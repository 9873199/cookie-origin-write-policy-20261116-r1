"""
Unit tests for the building blocks of `httpx.SecureCookiePolicy`.
The policy is primarily exercised end-to-end in
`tests/client/test_cookie_policy.py`.
"""

from http.cookiejar import CookieJar

import httpx
from httpx._cookie_policy import (
    _default_path,
    _domain_match,
    _is_ip_address,
    _normalize_domain,
    _parse_set_cookie,
    _path_match,
)


def test_normalize_domain() -> None:
    # Domain names are case-insensitive, and a trailing "root dot"
    # is insignificant.
    assert _normalize_domain("EXAMPLE.org") == "example.org"
    assert _normalize_domain("example.org.") == "example.org"
    assert _normalize_domain("Example.ORG.") == "example.org"


def test_domain_matching_label_boundaries() -> None:
    assert _domain_match("example.org", "example.org")
    assert _domain_match("sub.example.org", "example.org")
    assert _domain_match("a.b.example.org", "example.org")
    # Suffixes that don't fall on a label boundary never match.
    assert not _domain_match("notexample.org", "example.org")
    assert not _domain_match("example.org", "ample.org")
    assert not _domain_match("example.org", "sub.example.org")


def test_domain_matching_ip_literals() -> None:
    # IP literals only ever match themselves.
    assert _domain_match("127.0.0.1", "127.0.0.1")
    assert not _domain_match("127.0.0.1", "0.0.1")
    assert not _domain_match("127.0.0.1", "1")
    assert _domain_match("::1", "::1")
    assert not _domain_match("::1", ":1")


def test_is_ip_address() -> None:
    assert _is_ip_address("127.0.0.1")
    assert _is_ip_address("::1")
    assert _is_ip_address("2001:db8::1")
    assert not _is_ip_address("example.org")
    assert not _is_ip_address("127.0.0.1.example.org")


def test_default_path() -> None:
    assert _default_path("") == "/"
    assert _default_path("/") == "/"
    assert _default_path("/account") == "/"
    assert _default_path("/account/login") == "/account"
    assert _default_path("/account/") == "/account"


def test_path_match() -> None:
    assert _path_match("/account", "/account")
    assert _path_match("/account/login", "/account")
    assert _path_match("/account", "/")
    assert not _path_match("/accountable", "/account")
    assert not _path_match("/", "/account")


def test_parse_set_cookie() -> None:
    parsed = _parse_set_cookie("name=value; Secure; Path=/; Domain=example.org")
    assert parsed is not None
    assert parsed.name == "name"
    assert parsed.value == "value"
    assert parsed.secure
    assert parsed.path == "/"
    assert parsed.domain == "example.org"
    assert parsed.has_domain_attribute

    # An empty `Domain` attribute still counts as present.
    parsed = _parse_set_cookie("name=value; Domain=")
    assert parsed is not None
    assert parsed.domain is None
    assert parsed.has_domain_attribute

    # Headers without a well-formed name/value pair don't parse.
    assert _parse_set_cookie("not-a-cookie") is None
    assert _parse_set_cookie("=value") is None


def test_policy_allows_with_root_dot_and_mixed_case() -> None:
    policy = httpx.SecureCookiePolicy()
    jar: CookieJar = CookieJar()

    # A trailing root dot and mixed case are canonicalised away,
    # on both the response URL and the `Domain` attribute.
    url = httpx.URL("http://EXAMPLE.org./")
    assert policy.allows("a=1; Domain=Example.ORG.", url, jar)
    assert policy.allows("a=1", url, jar)
    assert not policy.allows("a=1; Domain=other.org", url, jar)


def test_policy_public_suffix_function_receives_normalized_domain() -> None:
    seen = []
    policy = httpx.SecureCookiePolicy(
        is_public_suffix=lambda domain: seen.append(domain) or domain == "co.uk"
    )
    jar: CookieJar = CookieJar()

    url = httpx.URL("https://example.co.uk/")
    assert not policy.allows("a=1; Domain=CO.UK.", url, jar)
    assert seen == ["co.uk"]
