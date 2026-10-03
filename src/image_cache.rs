use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

use axum::body::Bytes;

const MAX_ENTRIES: usize = 2_048;
const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_ENTRY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum ImageCacheKey {
    // The legacy key intentionally omits `height` from preview requests.
    Preview {
        tid: i64,
        png: bool,
    },
    Avatar {
        texture_hash: String,
        texture_type: String,
        three_d: bool,
        size: u32,
        png: bool,
    },
}

#[derive(Debug, Clone)]
pub struct CachedImage {
    pub body: Bytes,
    pub etag: String,
    pub modified: Option<SystemTime>,
}

struct Entry {
    image: CachedImage,
    expires_at: Instant,
    inserted_at: Instant,
}

#[derive(Default)]
pub struct ImageCache {
    entries: Mutex<HashMap<ImageCacheKey, Entry>>,
    bytes: Mutex<usize>,
}

impl ImageCache {
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn get(&self, key: &ImageCacheKey) -> Option<CachedImage> {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if entries
            .get(key)
            .is_some_and(|entry| entry.expires_at <= now)
        {
            if let Some(entry) = entries.remove(key) {
                self.subtract_bytes(entry.image.body.len());
            }
            return None;
        }
        entries.get(key).map(|entry| entry.image.clone())
    }

    pub fn insert(&self, key: ImageCacheKey, image: CachedImage, ttl: Duration) {
        let size = image.body.len();
        if size > MAX_ENTRY_BYTES || size > MAX_BYTES {
            return;
        }

        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut bytes = self.bytes.lock().unwrap_or_else(|error| error.into_inner());
        let expired: Vec<_> = entries
            .iter()
            .filter(|(_, entry)| entry.expires_at <= now)
            .map(|(key, _)| key.clone())
            .collect();
        for expired_key in expired {
            if let Some(entry) = entries.remove(&expired_key) {
                *bytes = bytes.saturating_sub(entry.image.body.len());
            }
        }
        if let Some(entry) = entries.remove(&key) {
            *bytes = bytes.saturating_sub(entry.image.body.len());
        }

        while entries.len() >= MAX_ENTRIES || bytes.saturating_add(size) > MAX_BYTES {
            let Some(oldest_key) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.inserted_at)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            if let Some(entry) = entries.remove(&oldest_key) {
                *bytes = bytes.saturating_sub(entry.image.body.len());
            }
        }

        *bytes = bytes.saturating_add(size);
        entries.insert(
            key,
            Entry {
                image,
                expires_at: now + ttl,
                inserted_at: now,
            },
        );
    }

    pub fn clear(&self) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut bytes = self.bytes.lock().unwrap_or_else(|error| error.into_inner());
        entries.clear();
        *bytes = 0;
    }

    fn subtract_bytes(&self, amount: usize) {
        let mut bytes = self.bytes.lock().unwrap_or_else(|error| error.into_inner());
        *bytes = bytes.saturating_sub(amount);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(tid: i64) -> ImageCacheKey {
        ImageCacheKey::Preview { tid, png: true }
    }

    fn image(body: &'static [u8]) -> CachedImage {
        CachedImage {
            body: Bytes::from_static(body),
            etag: "\"fixture\"".to_owned(),
            modified: None,
        }
    }

    #[test]
    fn caches_expires_and_clears_images() {
        let cache = ImageCache::default();
        cache.insert(key(1), image(b"png"), Duration::from_millis(1));
        assert!(cache.get(&key(1)).is_some());
        std::thread::sleep(Duration::from_millis(2));
        assert!(cache.get(&key(1)).is_none());

        cache.insert(key(2), image(b"webp"), Duration::from_secs(60));
        cache.clear();
        assert!(cache.get(&key(2)).is_none());
        assert_eq!(*cache.bytes.lock().unwrap(), 0);
    }

    #[test]
    fn bounds_entry_count_and_memory() {
        let cache = ImageCache::default();
        for tid in 0..=MAX_ENTRIES as i64 {
            cache.insert(key(tid), image(b"x"), Duration::from_secs(60));
        }
        let entries = cache.entries.lock().unwrap();
        assert_eq!(entries.len(), MAX_ENTRIES);
        assert!(!entries.contains_key(&key(0)));
        assert!(*cache.bytes.lock().unwrap() <= MAX_BYTES);
    }
}
