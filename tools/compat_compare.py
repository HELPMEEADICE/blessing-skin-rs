#!/usr/bin/env python3
"""Compare safe, read-only PHP and Rust HTTP compatibility probes."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_RESPONSE_BYTES = 64 * 1024 * 1024
HEADER_NAMES = (
    "content-type",
    "content-language",
    "cache-control",
    "etag",
    "last-modified",
    "expires",
    "location",
    "vary",
    "www-authenticate",
    "allow",
)
HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
ENV_TOKEN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
SAFE_PATH_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        r"/api/?",
        r"/api/user",
        r"/api/user/notifications",
        r"/api/players",
        r"/api/closet",
        r"/api/admin/(?:users|players|reports)",
        r"/api/admin/closet/[1-9][0-9]*",
        r"/textures/[A-Za-z0-9_-]{1,128}",
        r"/csl/textures/[A-Za-z0-9_-]{1,128}",
        r"/raw/[1-9][0-9]*",
        r"/[^/]+\.json",
        r"/csl/[^/]+\.json",
    )
)


@dataclass(frozen=True)
class HttpResponse:
    status: int | None
    headers: dict[str, str]
    body: bytes
    error: str | None = None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def is_safe_path(value: str) -> bool:
    """Allow only known stateless GET routes; exclude session and write routes."""
    if not isinstance(value, str) or not value.startswith("/") or value.startswith("//"):
        return False
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        return False
    path = urllib.parse.unquote(parsed.path)
    if "\\" in path or ".." in path.split("/"):
        return False
    return any(pattern.fullmatch(path) for pattern in SAFE_PATH_PATTERNS)


def validate_fixture(document: Any) -> list[dict[str, Any]]:
    if not isinstance(document, dict) or type(document.get("format_version")) is not int or document["format_version"] != 1:
        raise ValueError("fixture format_version must be 1")
    requests = document.get("requests")
    if not isinstance(requests, list) or not requests:
        raise ValueError("fixture requests must be a non-empty array")
    names: set[str] = set()
    validated = []
    for index, item in enumerate(requests):
        where = f"requests[{index}]"
        if not isinstance(item, dict):
            raise ValueError(f"{where} must be an object")
        name = item.get("name")
        path = item.get("path")
        if (
            not isinstance(name, str)
            or not name.strip()
            or any(ord(character) < 32 for character in name)
            or name in names
        ):
            raise ValueError(f"{where}.name must be a unique printable non-empty string")
        if not isinstance(path, str) or not is_safe_path(ENV_TOKEN.sub("1", path)):
            raise ValueError(f"{where}.path is not on the read-only GET allowlist")
        names.add(name)
        headers = item.get("headers", {})
        if not isinstance(headers, dict) or any(
            not isinstance(key, str)
            or not HEADER_NAME.fullmatch(key)
            or not isinstance(value, str)
            for key, value in headers.items()
        ):
            raise ValueError(f"{where}.headers must map valid header names to strings")
        for value in headers.values():
            expanded = substitute_environment(value)
            if any(
                ord(character) < 32 or ord(character) == 127
                for character in expanded
            ):
                raise ValueError(f"{where}.headers values must not contain control characters")
        pointers = item.get("ignore_json_pointers", [])
        if not isinstance(pointers, list) or any(
            not isinstance(pointer, str) or not pointer.startswith("/")
            for pointer in pointers
        ):
            raise ValueError(f"{where}.ignore_json_pointers must contain JSON pointers")
        if "method" in item and item["method"] != "GET":
            raise ValueError(f"{where}.method must be GET; this tool never replays writes")
        if any(
            key.lower() in {"x-http-method", "x-http-method-override", "x-method-override"}
            for key in headers
        ):
            raise ValueError(f"{where}.headers must not override the GET method")
        validated.append(
            {
                "name": name,
                "path": path,
                "headers": headers,
                "ignore_json_pointers": pointers,
            }
        )
    return validated


def substitute_environment(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        variable = match.group(1)
        if variable not in os.environ:
            raise ValueError(f"environment variable {variable} required by fixture is not set")
        return os.environ[variable]

    return ENV_TOKEN.sub(replace, value)


def resolve_probe_path(value: str) -> str:
    """Expand fixture path variables, then enforce the GET allowlist again."""
    path = substitute_environment(value)
    if any(
        (ord(character) < 32 and character != "\t") or ord(character) == 127
        for character in path
    ):
        raise ValueError("path variables must not contain control characters")
    if not is_safe_path(path):
        raise ValueError("resolved path is not on the read-only GET allowlist")
    return path


def build_url(base: str, path: str) -> str:
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("base URLs must use http or https and include a host")
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError("base URLs must not contain credentials, a query, or a fragment")
    request = urllib.parse.urlsplit(path)
    prefix = parsed.path.rstrip("/")
    joined_path = prefix + request.path
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, joined_path, request.query, ""))


def read_limited(stream: Any) -> bytes:
    body = stream.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError("response exceeds the 64 MiB comparison limit")
    return body


def fetch(base: str, probe: dict[str, Any], timeout: float) -> HttpResponse:
    try:
        headers = {key: substitute_environment(value) for key, value in probe["headers"].items()}
        headers.setdefault("Accept", "*/*")
        headers.setdefault("User-Agent", "blessing-skin-readonly-compat/1")
        request = urllib.request.Request(
            build_url(base, probe["path"]), headers=headers, method="GET"
        )
        opener = urllib.request.build_opener(NoRedirect)
        with opener.open(request, timeout=timeout) as response:
            return HttpResponse(
                response.status,
                {key.lower(): value.strip() for key, value in response.headers.items()},
                read_limited(response),
            )
    except urllib.error.HTTPError as response:
        try:
            body = read_limited(response)
            return HttpResponse(
                response.code,
                {key.lower(): value.strip() for key, value in response.headers.items()},
                body,
            )
        finally:
            response.close()
    except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError, ValueError) as error:
        return HttpResponse(None, {}, b"", type(error).__name__)


def _pointer_tokens(pointer: str) -> list[str]:
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]


def remove_json_pointer(document: Any, pointer: str) -> None:
    parts = _pointer_tokens(pointer)
    current = document
    for token in parts[:-1]:
        if isinstance(current, dict):
            if token not in current:
                return
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            return
    final = parts[-1]
    if isinstance(current, dict):
        current.pop(final, None)
    elif isinstance(current, list) and final.isdigit() and int(final) < len(current):
        current[int(final)] = None


def first_json_differences(left: Any, right: Any, pointer: str = "") -> list[str]:
    if type(left) is not type(right):
        return [pointer or "/"]
    if isinstance(left, dict):
        differences = []
        for key in sorted(left.keys() | right.keys()):
            child = pointer + "/" + str(key).replace("~", "~0").replace("/", "~1")
            if key not in left or key not in right:
                differences.append(child)
            else:
                differences.extend(first_json_differences(left[key], right[key], child))
            if len(differences) >= 5:
                return differences[:5]
        return differences
    if isinstance(left, list):
        if len(left) != len(right):
            return [pointer + "/length"]
        differences = []
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            differences.extend(first_json_differences(left_item, right_item, f"{pointer}/{index}"))
            if len(differences) >= 5:
                return differences[:5]
        return differences
    return [] if left == right else [pointer or "/"]


def compare_responses(
    php: HttpResponse, rust: HttpResponse, ignore_pointers: list[str]
) -> list[str]:
    differences = []
    if php.status != rust.status:
        differences.append("status")
    for header in HEADER_NAMES:
        if php.headers.get(header) != rust.headers.get(header):
            differences.append(f"header:{header}")
    php_is_json = "json" in php.headers.get("content-type", "").lower()
    rust_is_json = "json" in rust.headers.get("content-type", "").lower()
    if php_is_json and rust_is_json:
        try:
            php_body = json.loads(php.body)
            rust_body = json.loads(rust.body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            differences.append("body:invalid-json")
        else:
            for pointer in ignore_pointers:
                remove_json_pointer(php_body, pointer)
                remove_json_pointer(rust_body, pointer)
            differences.extend(
                "json:" + pointer
                for pointer in first_json_differences(php_body, rust_body)
            )
    elif php.body != rust.body:
        differences.append(
            "body:sha256"
            f"(php={hashlib.sha256(php.body).hexdigest()},"
            f"rust={hashlib.sha256(rust.body).hexdigest()})"
        )
    if php.error or rust.error:
        differences.append(f"transport:php={php.error or 'ok'},rust={rust.error or 'ok'}")
    return differences


def run(php_url: str, rust_url: str, fixtures: Path, timeout: float) -> int:
    try:
        probes = validate_fixture(json.loads(fixtures.read_text(encoding="utf-8")))
        for probe in probes:
            probe["path"] = resolve_probe_path(probe["path"])
            for value in probe["headers"].values():
                substitute_environment(value)
        build_url(php_url, "/")
        build_url(rust_url, "/")
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"Invalid fixture or URL: {error}", file=sys.stderr)
        return 2

    failed = 0
    print(f"Comparing {len(probes)} read-only GET probes.")
    for probe in probes:
        php = fetch(php_url, probe, timeout)
        rust = fetch(rust_url, probe, timeout)
        differences = compare_responses(php, rust, probe["ignore_json_pointers"])
        if differences:
            failed += 1
            print(f"FAIL {probe['name']}: " + "; ".join(differences))
        else:
            print(f"PASS {probe['name']} (HTTP {php.status})")
    passed = len(probes) - failed
    print(f"Result: {passed}/{len(probes)} matched.")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--php-url", required=True, help="PHP base URL")
    parser.add_argument("--rust-url", required=True, help="Rust base URL")
    parser.add_argument("--fixtures", required=True, type=Path, help="version 1 JSON probe file")
    parser.add_argument("--timeout", type=float, default=10.0, help="per-request timeout in seconds")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    return run(args.php_url, args.rust_url, args.fixtures, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
