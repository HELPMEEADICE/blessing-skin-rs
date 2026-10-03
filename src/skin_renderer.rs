use image::{DynamicImage, Rgba, RgbaImage, imageops};

#[derive(Clone, Copy)]
struct V {
    x: f32,
    y: f32,
    z: f32,
}
impl V {
    const fn new(x: f32, y: f32, z: f32) -> Self {
        Self { x, y, z }
    }
    fn add(self, b: Self) -> Self {
        Self::new(self.x + b.x, self.y + b.y, self.z + b.z)
    }
    fn mul(self, n: f32) -> Self {
        Self::new(self.x * n, self.y * n, self.z * n)
    }
}
#[derive(Clone, Copy)]
struct Uv {
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    fu: bool,
    fv: bool,
}
const fn uv(x: u32, y: u32, w: u32, h: u32) -> Uv {
    Uv {
        x,
        y,
        w,
        h,
        fu: false,
        fv: false,
    }
}
const fn uvu(x: u32, y: u32, w: u32, h: u32) -> Uv {
    Uv {
        fu: true,
        ..uv(x, y, w, h)
    }
}
const fn uvv(x: u32, y: u32, w: u32, h: u32) -> Uv {
    Uv {
        fv: true,
        ..uv(x, y, w, h)
    }
}
const fn uvuv(x: u32, y: u32, w: u32, h: u32) -> Uv {
    Uv {
        fu: true,
        fv: true,
        ..uv(x, y, w, h)
    }
}
#[derive(Clone, Copy)]
struct Layout {
    front: Uv,
    back: Uv,
    right: Uv,
    left: Uv,
    top: Uv,
    bottom: Uv,
}
struct Cube {
    min: V,
    size: V,
    uv: Layout,
}
struct Face {
    origin: V,
    u: V,
    v: V,
    tex: Uv,
    depth: f32,
}
#[derive(Clone, Copy)]
struct Camera {
    ca: f32,
    sa: f32,
    co: f32,
    so: f32,
}
impl Camera {
    fn new(yaw: f32, pitch: f32) -> Self {
        let (a, o) = (pitch.to_radians(), yaw.to_radians());
        Self {
            ca: a.cos(),
            sa: a.sin(),
            co: o.cos(),
            so: o.sin(),
        }
    }
    fn project(self, p: V) -> V {
        V::new(
            p.x * self.co + p.z * self.so,
            p.x * self.sa * self.so + p.y * self.ca - p.z * self.sa * self.co,
            -p.x * self.ca * self.so + p.y * self.sa + p.z * self.ca * self.co,
        )
    }
}

/// Render the two full-body orthographic views emitted by the legacy renderer.
pub(crate) fn render_preview(skin: &RgbaImage, alex: bool) -> DynamicImage {
    let skin = flatten_layers(skin);
    let back = view(&skin, alex, 135.0, -25.0, 12.0, false);
    let front = view(&skin, alex, -45.0, -25.0, 12.0, false);
    let (hp, ip, vp, w, h) = (30_u32, 15_u32, 15_u32, front.width(), front.height());
    let mut out = RgbaImage::from_pixel((hp + w + ip) * 2, vp * 2 + h, Rgba([0, 0, 0, 0]));
    imageops::overlay(&mut out, &back, i64::from(hp), i64::from(vp));
    imageops::overlay(&mut out, &front, i64::from(hp + w + ip * 2), i64::from(vp));
    DynamicImage::ImageRgba8(out)
}

/// Render the legacy head-only avatar projection at ratio 25.
pub(crate) fn render_avatar(skin: &RgbaImage, three_d: bool) -> DynamicImage {
    let skin = flatten_layers(skin);
    let (yaw, pitch) = if three_d { (45.0, -25.0) } else { (0.0, 0.0) };
    DynamicImage::ImageRgba8(view(&skin, false, yaw, pitch, 25.0, true))
}

fn flatten_layers(skin: &RgbaImage) -> RgbaImage {
    let mut prepared = legacy_opaque_base(skin);
    if skin.dimensions() != (64, 64) {
        return prepared;
    }
    let source = prepared.clone();
    for y in 0..16 {
        for x in 0..56 {
            prepared.put_pixel(x, 16 + y, *source.get_pixel(x, 32 + y));
        }
        for x in 0..16 {
            prepared.put_pixel(16 + x, 48 + y, *source.get_pixel(x, 48 + y));
            prepared.put_pixel(32 + x, 48 + y, *source.get_pixel(48 + x, 48 + y));
        }
    }
    prepared
}

fn legacy_opaque_base(skin: &RgbaImage) -> RgbaImage {
    let key = *skin.get_pixel(0, 0);
    let mut remove_solid_background = key[3] >= 14;
    for y in 0..8 {
        for x in 0..8 {
            let pixel = *skin.get_pixel(x, y);
            if pixel != key || pixel[3] < 14 {
                remove_solid_background = false;
            }
        }
    }

    let fill = if remove_solid_background {
        Rgba([key[0], key[1], key[2], 255])
    } else {
        Rgba([0, 0, 0, 255])
    };
    let mut prepared = RgbaImage::from_pixel(skin.width(), skin.height(), Rgba([0, 0, 0, 0]));
    let base_rectangles = [
        (8, 0, 23, 7),
        (0, 8, 31, 15),
        (4, 16, 11, 19),
        (20, 16, 35, 19),
        (44, 16, 51, 19),
        (0, 20, 54, 31),
        (20, 48, 27, 51),
        (36, 48, 43, 51),
        (16, 52, 47, 63),
    ];
    for (left, top, right, bottom) in base_rectangles {
        for y in top..=bottom.min(skin.height().saturating_sub(1)) {
            for x in left..=right.min(skin.width().saturating_sub(1)) {
                prepared.put_pixel(x, y, fill);
            }
        }
    }

    for y in 0..skin.height() {
        for x in 0..skin.width() {
            let pixel = *skin.get_pixel(x, y);
            if remove_solid_background
                && pixel[0] == key[0]
                && pixel[1] == key[1]
                && pixel[2] == key[2]
            {
                continue;
            }
            blend(prepared.get_pixel_mut(x, y), pixel);
        }
    }
    prepared
}
fn view(
    skin: &RgbaImage,
    alex: bool,
    yaw: f32,
    pitch: f32,
    ratio: f32,
    head_only: bool,
) -> RgbaImage {
    let camera = Camera::new(yaw, pitch);
    let mut faces = Vec::new();
    cube(
        &mut faces,
        Cube {
            min: V::new(0.0, 0.0, -2.0),
            size: V::new(8.0, 8.0, 8.0),
            uv: Layout {
                front: uv(8, 8, 8, 8),
                back: uvu(24, 8, 8, 8),
                right: uv(0, 8, 8, 8),
                left: uvu(16, 8, 8, 8),
                top: uv(8, 0, 8, 8),
                bottom: uv(16, 0, 8, 8),
            },
        },
        camera,
    );
    cube(
        &mut faces,
        Cube {
            min: V::new(-0.5, -0.5, -2.5),
            size: V::new(9.0, 9.0, 9.0),
            uv: Layout {
                front: uv(40, 8, 8, 8),
                back: uvu(56, 8, 8, 8),
                right: uv(32, 8, 8, 8),
                left: uvu(48, 8, 8, 8),
                top: uv(40, 0, 8, 8),
                bottom: uv(48, 0, 8, 8),
            },
        },
        camera,
    );
    if !head_only {
        body(&mut faces, alex, skin.height() == 64, camera);
    }
    raster(skin, faces, camera, ratio)
}

fn body(f: &mut Vec<Face>, alex: bool, modern: bool, c: Camera) {
    cube(
        f,
        Cube {
            min: V::new(0.0, 8.0, 0.0),
            size: V::new(8.0, 12.0, 4.0),
            uv: Layout {
                front: uv(20, 20, 8, 12),
                back: uvu(32, 20, 8, 12),
                right: uv(16, 20, 4, 12),
                left: uvu(28, 20, 4, 12),
                top: uv(20, 16, 8, 4),
                bottom: uvv(28, 16, 8, 4),
            },
        },
        c,
    );
    let aw = if alex { 3.0 } else { 4.0 };
    let ap = aw as u32;
    let ruv = if alex {
        Layout {
            front: uv(44, 20, ap, 12),
            back: uvu(48, 20, ap, 12),
            right: uv(47, 20, 4, 12),
            left: uvu(36, 20, 4, 12),
            top: uv(44, 16, ap, 4),
            bottom: uv(47, 16, ap, 4),
        }
    } else {
        Layout {
            front: uv(44, 20, 4, 12),
            back: uvu(52, 20, 4, 12),
            right: uv(40, 20, 4, 12),
            left: uvu(48, 20, 4, 12),
            top: uv(44, 16, 4, 4),
            bottom: uv(48, 16, 4, 4),
        }
    };
    cube(
        f,
        Cube {
            min: V::new(-4.0, 8.0, 0.0),
            size: V::new(aw, 12.0, 4.0),
            uv: ruv,
        },
        c,
    );
    let luv = if alex {
        Layout {
            front: uv(36, 52, ap, 12),
            back: uv(43, 52, ap, 12),
            right: uv(32, 52, 4, 12),
            left: uvu(40, 52, 4, 12),
            top: uv(36, 48, ap, 4),
            bottom: uv(39, 48, ap, 4),
        }
    } else if modern {
        Layout {
            front: uv(36, 52, 4, 12),
            back: uvu(44, 52, 4, 12),
            right: uv(32, 52, 4, 12),
            left: uvu(40, 52, 4, 12),
            top: uv(36, 48, 4, 4),
            bottom: uv(40, 48, 4, 4),
        }
    } else {
        Layout {
            front: uvu(44, 20, 4, 12),
            back: uv(52, 20, 4, 12),
            right: uvu(40, 20, 4, 12),
            left: uv(48, 20, 4, 12),
            top: uvu(44, 16, 4, 4),
            bottom: uvuv(48, 16, 4, 4),
        }
    };
    cube(
        f,
        Cube {
            min: V::new(8.0, 8.0, 0.0),
            size: V::new(aw, 12.0, 4.0),
            uv: luv,
        },
        c,
    );
    cube(
        f,
        Cube {
            min: V::new(0.0, 20.0, 0.0),
            size: V::new(4.0, 12.0, 4.0),
            uv: Layout {
                front: uv(4, 20, 4, 12),
                back: uvu(12, 20, 4, 12),
                right: uv(0, 20, 4, 12),
                left: uvu(8, 20, 4, 12),
                top: uv(4, 16, 4, 4),
                bottom: uv(8, 16, 4, 4),
            },
        },
        c,
    );
    let ll = if modern {
        Layout {
            front: uv(20, 52, 4, 12),
            back: uvu(28, 52, 4, 12),
            right: uv(16, 52, 4, 12),
            left: uvu(24, 52, 4, 12),
            top: uv(20, 48, 4, 4),
            bottom: uv(24, 48, 4, 4),
        }
    } else {
        Layout {
            front: uvu(4, 20, 4, 12),
            back: uv(12, 20, 4, 12),
            right: uvu(0, 20, 4, 12),
            left: uv(8, 20, 4, 12),
            top: uvu(4, 16, 4, 4),
            bottom: uvuv(8, 16, 4, 4),
        }
    };
    cube(
        f,
        Cube {
            min: V::new(4.0, 20.0, 0.0),
            size: V::new(4.0, 12.0, 4.0),
            uv: ll,
        },
        c,
    );
}

fn cube(f: &mut Vec<Face>, b: Cube, c: Camera) {
    let m = b.min;
    let z = m.add(b.size);
    let s = [
        (
            V::new(m.x, m.y, z.z),
            V::new(b.size.x, 0.0, 0.0),
            V::new(0.0, b.size.y, 0.0),
            b.uv.front,
        ),
        (
            V::new(m.x, m.y, m.z),
            V::new(b.size.x, 0.0, 0.0),
            V::new(0.0, b.size.y, 0.0),
            b.uv.back,
        ),
        (
            V::new(m.x, m.y, m.z),
            V::new(0.0, 0.0, b.size.z),
            V::new(0.0, b.size.y, 0.0),
            b.uv.right,
        ),
        (
            V::new(z.x, m.y, m.z),
            V::new(0.0, 0.0, b.size.z),
            V::new(0.0, b.size.y, 0.0),
            b.uv.left,
        ),
        (
            V::new(m.x, m.y, m.z),
            V::new(b.size.x, 0.0, 0.0),
            V::new(0.0, 0.0, b.size.z),
            b.uv.top,
        ),
        (
            V::new(m.x, z.y, m.z),
            V::new(b.size.x, 0.0, 0.0),
            V::new(0.0, 0.0, b.size.z),
            b.uv.bottom,
        ),
    ];
    for (o, u, v, t) in s {
        if t.w == 0 || t.h == 0 {
            continue;
        }
        let depth = c.project(o.add(u.mul(0.5)).add(v.mul(0.5))).z;
        f.push(Face {
            origin: o,
            u,
            v,
            tex: t,
            depth,
        });
    }
}

fn raster(skin: &RgbaImage, mut faces: Vec<Face>, camera: Camera, ratio: f32) -> RgbaImage {
    let (mut minx, mut maxx, mut miny, mut maxy) = (
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::INFINITY,
        f32::NEG_INFINITY,
    );
    for f in &faces {
        for p in [
            f.origin,
            f.origin.add(f.u),
            f.origin.add(f.v),
            f.origin.add(f.u).add(f.v),
        ] {
            let p = camera.project(p);
            minx = minx.min(p.x);
            maxx = maxx.max(p.x);
            miny = miny.min(p.y);
            maxy = maxy.max(p.y);
        }
    }
    if !minx.is_finite() {
        return RgbaImage::new(1, 1);
    }
    let w = ((maxx - minx) * ratio + 0.5).floor().max(1.0) as u32;
    let h = ((maxy - miny) * ratio + 0.5).floor().max(1.0) as u32;
    let mut high = RgbaImage::from_pixel(
        w.saturating_mul(2).saturating_add(1),
        h.saturating_mul(2).saturating_add(1),
        Rgba([0, 0, 0, 0]),
    );
    // Match PHP Polygon::addPngPolygon painter ordering: maximum-depth faces are painted first.
    faces.sort_by(|a, b| b.depth.total_cmp(&a.depth));
    for face in &faces {
        draw(&mut high, skin, face, camera, minx, miny, ratio * 2.0);
    }
    imageops::resize(&high, w, h, imageops::FilterType::Triangle)
}

fn draw(
    dst: &mut RgbaImage,
    skin: &RgbaImage,
    f: &Face,
    c: Camera,
    minx: f32,
    miny: f32,
    ratio: f32,
) {
    let t = f.tex;
    if t.x.saturating_add(t.w) > skin.width() || t.y.saturating_add(t.h) > skin.height() {
        return;
    }
    let o = c.project(f.origin);
    let eu = c.project(f.origin.add(f.u));
    let ev = c.project(f.origin.add(f.v));
    let e = c.project(f.origin.add(f.u).add(f.v));
    let ox = (o.x - minx) * ratio;
    let oy = (o.y - miny) * ratio;
    let (ux, uy) = (
        (eu.x - o.x) * ratio / t.w as f32,
        (eu.y - o.y) * ratio / t.w as f32,
    );
    let (vx, vy) = (
        (ev.x - o.x) * ratio / t.h as f32,
        (ev.y - o.y) * ratio / t.h as f32,
    );
    let det = ux * vy - uy * vx;
    if det.abs() < f32::EPSILON {
        return;
    }
    let pts = [
        (ox, oy),
        ((eu.x - minx) * ratio, (eu.y - miny) * ratio),
        ((ev.x - minx) * ratio, (ev.y - miny) * ratio),
        ((e.x - minx) * ratio, (e.y - miny) * ratio),
    ];
    let x0 = pts
        .iter()
        .map(|p| p.0)
        .fold(f32::INFINITY, f32::min)
        .floor()
        .max(0.0) as u32;
    let x1 = pts
        .iter()
        .map(|p| p.0)
        .fold(f32::NEG_INFINITY, f32::max)
        .ceil()
        .min(dst.width() as f32) as u32;
    let y0 = pts
        .iter()
        .map(|p| p.1)
        .fold(f32::INFINITY, f32::min)
        .floor()
        .max(0.0) as u32;
    let y1 = pts
        .iter()
        .map(|p| p.1)
        .fold(f32::NEG_INFINITY, f32::max)
        .ceil()
        .min(dst.height() as f32) as u32;
    for y in y0..y1 {
        for x in x0..x1 {
            let (dx, dy) = (x as f32 + 0.5 - ox, y as f32 + 0.5 - oy);
            let (u, v) = ((dx * vy - dy * vx) / det, (ux * dy - uy * dx) / det);
            if u < 0.0 || v < 0.0 || u >= t.w as f32 || v >= t.h as f32 {
                continue;
            }
            let (u, v) = (u.floor() as u32, v.floor() as u32);
            let sx = t.x + if t.fu { t.w - 1 - u } else { u };
            let sy = t.y + if t.fv { t.h - 1 - v } else { v };
            paint_surface(dst.get_pixel_mut(x, y), *skin.get_pixel(sx, sy));
        }
    }
}

fn paint_surface(dst: &mut Rgba<u8>, src: Rgba<u8>) {
    if src[3] > 0 {
        *dst = Rgba([src[0], src[1], src[2], 255]);
    }
}

fn blend(dst: &mut Rgba<u8>, src: Rgba<u8>) {
    let a = u32::from(src[3]);
    if a == 255 {
        *dst = src;
        return;
    }
    if a == 0 {
        return;
    }
    let da = u32::from(dst[3]);
    let ia = 255 - a;
    let oa = a + (da * ia + 127) / 255;
    let mut out = [0_u8; 4];
    for c in 0..3 {
        let fg = u32::from(src[c]) * a;
        let bg = (u32::from(dst[c]) * da * ia + 127) / 255;
        out[c] = ((fg + bg) / oa.max(1)).min(255) as u8;
    }
    out[3] = oa.min(255) as u8;
    *dst = Rgba(out);
}

#[cfg(test)]
mod tests {
    use super::{render_avatar, render_preview};
    use image::{GenericImageView, Rgba, RgbaImage};
    #[test]
    fn renders_two_projected_views_for_skin_preview() {
        let skin = RgbaImage::from_pixel(64, 64, Rgba([80, 130, 190, 255]));
        let preview = render_preview(&skin, false);
        assert!(
            preview.width() > 400 && preview.height() > 400,
            "preview is {}x{}",
            preview.width(),
            preview.height()
        );
        assert!(preview.width() > 300);
        assert!(preview.pixels().any(|(_, _, p)| p[3] > 0));
    }
    #[test]
    fn legacy_2d_projection_orders_the_near_back_face_in_front() {
        let mut skin = RgbaImage::from_pixel(64, 32, Rgba([0, 0, 0, 0]));
        for y in 8..16 {
            for x in 8..16 {
                skin.put_pixel(x, y, Rgba([20, 40, 220, 255]));
            }
            for x in 24..32 {
                skin.put_pixel(x, y, Rgba([220, 40, 20, 255]));
            }
        }
        let avatar = render_avatar(&skin, false).to_rgba8();
        assert!(avatar.pixels().any(|p| p[0] > 150 && p[2] < 80 && p[3] > 0));
        assert!(!avatar.pixels().any(|p| p[2] > 150 && p[0] < 80 && p[3] > 0));
    }
    #[test]
    fn projects_head_only_avatar_in_both_modes() {
        let skin = RgbaImage::from_pixel(64, 64, Rgba([190, 90, 40, 255]));
        for three_d in [false, true] {
            let avatar = render_avatar(&skin, three_d);
            assert!(avatar.width() > 100 && avatar.height() > 100);
            assert!(avatar.pixels().any(|(_, _, p)| p[3] > 0));
        }
    }
}
