import http.server
import json
import importlib.util
import sys
import threading
import unittest
from unittest.mock import patch
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("compat_compare.py")
SPEC = importlib.util.spec_from_file_location("compat_compare", MODULE_PATH)
compat = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = compat
SPEC.loader.exec_module(compat)


class CompatCompareTests(unittest.TestCase):
    def test_read_only_allowlist_accepts_protocol_reads(self):
        for path in (
            "/api/",
            "/api/user",
            "/api/players?page=1",
            "/api/admin/closet/42",
            "/raw/42",
            "/avatar/player/Notch",
            "/avatar/user/42",
            "/avatar/hash/" + "a" * 64,
            "/avatar/0?png",
            "/preview/42?height=128",
            "/preview/hash/" + "b" * 64 + "?png",
            "/Alex.json",
            "/csl/Alex.json",
            "/textures/0123456789abcdef0123456789abcdef",
        ):
            with self.subTest(path=path):
                self.assertTrue(compat.is_safe_path(path))

    def test_allowlist_rejects_session_routes_and_all_mutations(self):
        for path in (
            "/auth/login",
            "/oauth/authorize",
            "/setup/database",
            "/user/profile",
            "/admin/options",
            "/api/players/3",
            "/avatar/user/-1",
            "/avatar/hash/not-a-hash",
            "/preview/3/extra",
            "/preview/hash/../api/user",
            "/api/user/notifications/3",
            "/skinlib/show/3",
            "/texture",
            "/texture/3",
            "/api/%2e%2e/auth/login",
            "//other.example/api/user",
        ):
            with self.subTest(path=path):
                self.assertFalse(compat.is_safe_path(path))

    def test_checked_in_example_fixture_is_valid(self):
        fixture_path = MODULE_PATH.parents[1] / "docs" / "compat-shadow.example.json"
        with patch.dict(
            compat.os.environ,
            {
                "BS_SHADOW_OAUTH_TOKEN": "read-only-test-token",
                "BS_SHADOW_PLAYER": "ExamplePlayer",
                "BS_SHADOW_USER_ID": "7",
                "BS_SHADOW_TEXTURE_HASH": "a" * 64,
                "BS_SHADOW_TEXTURE_ID": "42",
            },
        ):
            fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
            probes = compat.validate_fixture(fixture)
            for probe in probes:
                probe["path"] = compat.resolve_probe_path(probe["path"])
        self.assertEqual(len(probes), 11)
        self.assertTrue(all(compat.is_safe_path(probe["path"]) for probe in probes))

    def test_path_variables_expand_only_to_allowlisted_read_routes(self):
        with patch.dict(
            compat.os.environ,
            {
                "BS_SHADOW_TEXTURE_HASH": "a" * 64,
                "BS_SHADOW_TEXTURE_ID": "42",
            },
        ):
            self.assertEqual(
                compat.resolve_probe_path("/textures/${BS_SHADOW_TEXTURE_HASH}"),
                "/textures/" + "a" * 64,
            )
            self.assertEqual(
                compat.resolve_probe_path("/raw/${BS_SHADOW_TEXTURE_ID}"),
                "/raw/42",
            )

    def test_path_variables_cannot_escape_the_read_only_allowlist(self):
        with patch.dict(
            compat.os.environ,
            {"BS_SHADOW_TEXTURE_ID": "42/../api/user"},
        ):
            with self.assertRaisesRegex(ValueError, "read-only GET allowlist"):
                compat.resolve_probe_path("/raw/${BS_SHADOW_TEXTURE_ID}")

        with patch.dict(compat.os.environ, {"BS_SHADOW_TEXTURE_ID": "42\r\n"}):
            with self.assertRaisesRegex(ValueError, "control characters"):
                compat.resolve_probe_path("/raw/${BS_SHADOW_TEXTURE_ID}")

    def test_fixture_rejects_non_get_methods(self):
        with self.assertRaisesRegex(ValueError, "must be GET"):
            compat.validate_fixture(
                {
                    "format_version": 1,
                    "requests": [
                        {"name": "write", "path": "/api/", "method": "POST"}
                    ],
                }
            )

    def test_fixture_requires_a_safe_path(self):
        with self.assertRaisesRegex(ValueError, "read-only GET allowlist"):
            compat.validate_fixture(
                {
                    "format_version": 1,
                    "requests": [{"name": "login", "path": "/auth/login"}],
                }
            )

    def test_fixture_rejects_method_override_headers(self):
        with self.assertRaisesRegex(ValueError, "must not override the GET method"):
            compat.validate_fixture(
                {
                    "format_version": 1,
                    "requests": [
                        {
                            "name": "override",
                            "path": "/api/",
                            "headers": {"X-HTTP-Method-Override": "DELETE"},
                        }
                    ],
                }
            )

    def test_fixture_requires_environment_tokens_and_rejects_header_injection(self):
        fixture = {
            "format_version": 1,
            "requests": [
                {
                    "name": "auth read",
                    "path": "/api/user",
                    "headers": {"Authorization": "Bearer ${BS_COMPAT_TEST_TOKEN}"},
                }
            ],
        }
        with patch.dict(compat.os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "is not set"):
                compat.validate_fixture(fixture)
        with patch.dict(
            compat.os.environ,
            {"BS_COMPAT_TEST_TOKEN": "safe\r\nInjected: yes"},
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "control characters"):
                compat.validate_fixture(fixture)

    def test_fetch_does_not_follow_redirects(self):
        seen = []

        class RedirectHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.command, self.path))
                self.send_response(302)
                self.send_header("Location", "/api/user")
                self.end_headers()

            def log_message(self, format_string, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            response = compat.fetch(
                f"http://127.0.0.1:{server.server_port}",
                {"path": "/api/", "headers": {}},
                2,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertEqual(response.status, 302)
        self.assertEqual(seen, [("GET", "/api/")])

    def test_json_pointer_ignores_dynamic_values_without_hiding_other_fields(self):
        left = {"data": [{"name": "Alex", "created_at": "first"}], "total": 1}
        right = {"data": [{"name": "Alex", "created_at": "second"}], "total": 2}
        compat.remove_json_pointer(left, "/data/0/created_at")
        compat.remove_json_pointer(right, "/data/0/created_at")
        self.assertEqual(compat.first_json_differences(left, right), ["/total"])

    def test_compares_cache_headers_and_non_json_body(self):
        php = compat.HttpResponse(200, {"content-type": "image/png", "etag": '"one"'}, b"php")
        rust = compat.HttpResponse(200, {"content-type": "image/png", "etag": '"two"'}, b"rust")
        differences = compat.compare_responses(php, rust, [])
        self.assertEqual(len(differences), 2)
        self.assertEqual(differences[0], "header:etag")
        self.assertTrue(differences[1].startswith("body:sha256"))


    def test_compares_content_length_for_binary_protocol_responses(self):
        php = compat.HttpResponse(
            200,
            {"content-type": "image/png", "content-length": "3"},
            b"abc",
        )
        rust = compat.HttpResponse(
            200,
            {"content-type": "image/png", "content-length": "4"},
            b"abc",
        )
        self.assertEqual(
            compat.compare_responses(php, rust, []),
            ["header:content-length"],
        )


if __name__ == "__main__":
    unittest.main()
