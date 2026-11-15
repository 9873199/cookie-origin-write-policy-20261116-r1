"""
Integration tests for `httpx.SecureCookiePolicy`, exercising the cookie
receiving chain end-to-end through `Client`/`AsyncClient` and
`MockTransport`. Behaviour is verified against the `Cookie` header that
is actually sent on the next request, not just the jar contents.
"""

from http.cookiejar import CookieJar

import pytest

import httpx


def echo_cookies(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"cookies": request.headers.get("cookie")})


def parse_cookie_header(header: str | None) -> dict[str, str]:
    if header is None:
        return {}
    return dict(
        pair.strip().split("=", 1) for pair in header.split(";") if pair.strip()
    )


def secure_app(request: httpx.Request) -> httpx.Response:
    """
    Sets a `Secure` cookie over HTTPS, then attempts to overwrite or
    delete it over HTTP.
    """
    if request.url.path == "/set_secure":
        return httpx.Response(200, headers={"set-cookie": "session=abc; Secure"})
    elif request.url.path == "/http_overwrite":
        return httpx.Response(200, headers={"set-cookie": "session=evil"})
    elif request.url.path == "/http_expire":
        return httpx.Response(
            200,
            headers={
                "set-cookie": "session=; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
            },
        )
    elif request.url.path == "/http_expire_max_age":
        return httpx.Response(200, headers={"set-cookie": "session=; Max-Age=0"})
    elif request.url.path == "/https_update":
        return httpx.Response(200, headers={"set-cookie": "session=def; Secure"})
    elif request.url.path == "/https_expire":
        return httpx.Response(200, headers={"set-cookie": "session=; Max-Age=0"})
    return echo_cookies(request)


def test_http_cannot_overwrite_secure_cookie() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(secure_app),
        cookie_policy=httpx.SecureCookiePolicy(),
    )

    client.get("https://example.org/set_secure")
    assert client.cookies["session"] == "abc"

    client.get("http://example.org/http_overwrite")

    # The rejected write must not have touched the existing cookie.
    assert client.cookies["session"] == "abc"
    response = client.get("https://example.org/echo")
    assert response.json() == {"cookies": "session=abc"}


def test_http_cannot_expire_secure_cookie() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(secure_app),
        cookie_policy=httpx.SecureCookiePolicy(),
    )

    client.get("https://example.org/set_secure")

    # Deletion attempts using an expiry date in the past...
    client.get("http://example.org/http_expire")
    assert client.cookies["session"] == "abc"

    # ...or using `Max-Age=0` cannot remove the cookie either.
    client.get("http://example.org/http_expire_max_age")
    assert client.cookies["session"] == "abc"

    response = client.get("https://example.org/echo")
    assert response.json() == {"cookies": "session=abc"}


def test_https_can_update_and_expire_own_secure_cookie() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(secure_app),
        cookie_policy=httpx.SecureCookiePolicy(),
    )

    client.get("https://example.org/set_secure")
    client.get("https://example.org/https_update")
    response = client.get("https://example.org/echo")
    assert response.json() == {"cookies": "session=def"}

    client.get("https://example.org/https_expire")
    assert "session" not in client.cookies
    response = client.get("https://example.org/echo")
    assert response.json() == {"cookies": None}


def test_default_client_behaviour_is_unchanged() -> None:
    # Without a policy the historical behaviour is retained:
    # an HTTP response may overwrite a `Secure` cookie.
    client = httpx.Client(transport=httpx.MockTransport(secure_app))

    client.get("https://example.org/set_secure")
    client.get("http://example.org/http_overwrite")

    assert client.cookies["session"] == "evil"
    response = client.get("https://example.org/echo")
    assert response.json() == {"cookies": "session=evil"}


def path_app(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/app/login":
        return httpx.Response(
            200, headers={"set-cookie": "token=secure-val; Secure; Path=/app"}
        )
    elif request.url.path == "/evil_same_path":
        return httpx.Response(
            200, headers={"set-cookie": "token=evil; Path=/app"}
        )
    elif request.url.path == "/evil_parent_path":
        return httpx.Response(200, headers={"set-cookie": "token=evil2; Path=/"})
    elif request.url.path == "/ok_other_path":
        return httpx.Response(
            200, headers={"set-cookie": "token=other; Path=/other"}
        )
    return echo_cookies(request)


def test_same_name_cookie_with_different_paths() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(path_app),
        cookie_policy=httpx.SecureCookiePolicy(),
    )

    client.get("https://example.org/app/login")

    # Same name and an overlapping path: blocked.
    client.get("http://example.org/evil_same_path")
    # Same name and a parent path, which also overlaps: blocked.
    client.get("http://example.org/evil_parent_path")
    # Same name but a disjoint path: allowed.
    client.get("http://example.org/ok_other_path")

    response = client.get("https://example.org/app/page")
    assert response.json() == {"cookies": "token=secure-val"}

    response = client.get("http://example.org/other")
    assert response.json() == {"cookies": "token=other"}


def domain_overlap_app(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/parent_set":
        return httpx.Response(
            200,
            headers={"set-cookie": "shared=parent; Secure; Domain=example.org"},
        )
    elif request.url.path == "/child_evil":
        return httpx.Response(
            200,
            headers={"set-cookie": "shared=evil; Domain=sub.example.org"},
        )
    elif request.url.path == "/child_set":
        return httpx.Response(
            200,
            headers={"set-cookie": "sub=child; Secure; Domain=sub.example.org"},
        )
    elif request.url.path == "/parent_evil":
        return httpx.Response(
            200, headers={"set-cookie": "sub=evil; Domain=example.org"}
        )
    return echo_cookies(request)


def test_parent_and_child_domain_overlap() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(domain_overlap_app),
        cookie_policy=httpx.SecureCookiePolicy(),
    )

    client.get("https://example.org/parent_set")
    # An insecure child may not shadow the parent's `Secure` cookie.
    client.get("http://sub.example.org/child_evil")

    client.get("https://sub.example.org/child_set")
    # An insecure parent may not shadow the child's `Secure` cookie either.
    client.get("http://example.org/parent_evil")

    response = client.get("https://sub.example.org/echo")
    cookies = parse_cookie_header(response.json()["cookies"])
    assert cookies == {"shared": "parent", "sub": "child"}


def host_prefix_app(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/set":
        return httpx.Response(
            200,
            headers=[
                ("set-cookie", "__Host-a=1; Secure; Path=/"),
                # A `Domain` attribute disqualifies the cookie...
                ("set-cookie", "__Host-b=1; Secure; Path=/; Domain=example.org"),
                # ...even an empty one.
                ("set-cookie", "__Host-c=1; Secure; Path=/; Domain="),
                # The `Secure` attribute is required.
                ("set-cookie", "__Host-d=1; Path=/"),
                # The path must be exactly `/`.
                ("set-cookie", "__Host-e=1; Secure; Path=/account"),
                # Prefixes are matched case-insensitively.
                ("set-cookie", "__host-f=1; Secure; Path=/"),
            ],
        )
    elif request.url.path == "/nopath":
        # No `Path` attribute, but the default path of `/nopath` is `/`.
        return httpx.Response(200, headers={"set-cookie": "__Host-g=1; Secure"})
    elif request.url.path == "/sub/page":
        # The default path here is `/sub`, so the cookie is rejected.
        return httpx.Response(200, headers={"set-cookie": "__Host-h=1; Secure"})
    return echo_cookies(request)


def test_host_prefix_rules() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(host_prefix_app),
        cookie_policy=httpx.SecureCookiePolicy(),
    )

    client.get("https://example.org/set")
    client.get("https://example.org/nopath")
    client.get("https://example.org/sub/page")
    # `__Host-` cookies are never accepted over HTTP.
    client.get("http://example.org/set")

    response = client.get("https://example.org/echo")
    cookies = parse_cookie_header(response.json()["cookies"])
    assert cookies == {"__Host-a": "1", "__host-f": "1", "__Host-g": "1"}


def secure_prefix_app(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/set":
        return httpx.Response(
            200,
            headers=[
                ("set-cookie", "__Secure-a=1; Secure"),
                # The `Secure` attribute is required.
                ("set-cookie", "__Secure-b=1"),
                # Prefixes are matched case-insensitively.
                ("set-cookie", "__secure-c=1; Secure"),
            ],
        )
    return echo_cookies(request)


def test_secure_prefix_rules() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(secure_prefix_app),
        cookie_policy=httpx.SecureCookiePolicy(),
    )

    client.get("https://example.org/set")
    # `__Secure-` cookies are never accepted over HTTP.
    client.get("http://example.org/set")

    response = client.get("https://example.org/echo")
    cookies = parse_cookie_header(response.json()["cookies"])
    assert cookies == {"__Secure-a": "1", "__secure-c": "1"}


def secure_attribute_app(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/set":
        return httpx.Response(200, headers={"set-cookie": "s=1; Secure"})
    return echo_cookies(request)


def test_secure_attribute_rejected_over_http() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(secure_attribute_app),
        cookie_policy=httpx.SecureCookiePolicy(),
    )

    client.get("http://example.org/set")
    assert "s" not in client.cookies

    client.get("https://example.org/set")
    assert client.cookies["s"] == "1"


def forged_host_app(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/set":
        return httpx.Response(
            200,
            headers=[
                ("set-cookie", "x=1; Domain=example.org"),
                ("set-cookie", "y=2; Domain=notexample.org"),
            ],
        )
    return echo_cookies(request)


def test_policy_uses_response_url_not_host_header() -> None:
    # The policy must judge the `Set-Cookie` against the URL of the actual
    # response, never against a user-supplied `Host` header.
    client = httpx.Client(
        transport=httpx.MockTransport(forged_host_app),
        cookie_policy=httpx.SecureCookiePolicy(),
        headers={"Host": "notexample.org"},
    )

    client.get("http://example.org/set")

    # `x` matches the actual response host, so it is stored. `y` only
    # matches the forged `Host` header, so it is rejected.
    response = client.get("http://example.org/echo")
    assert response.json() == {"cookies": "x=1"}


def redirect_app(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/start":
        # A secure hop, setting a `Secure` cookie mid-chain.
        return httpx.Response(
            302,
            headers={
                "location": "http://example.org/middle",
                "set-cookie": "hop=secure; Secure",
            },
        )
    elif request.url.path == "/middle":
        # An insecure hop, attempting to overwrite the cookie.
        return httpx.Response(
            302,
            headers=[
                ("location", "https://example.org/final"),
                ("set-cookie", "hop=evil"),
                ("set-cookie", "mid=1"),
            ],
        )
    elif request.url.path == "/insecure_start":
        # An insecure hop may not set a `Secure` cookie, even if the
        # chain continues over HTTPS.
        return httpx.Response(
            302,
            headers={
                "location": "https://example.org/final",
                "set-cookie": "z=1; Secure",
            },
        )
    return echo_cookies(request)


def test_policy_applied_to_each_redirect_hop() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(redirect_app),
        cookie_policy=httpx.SecureCookiePolicy(),
    )

    response = client.get("https://example.org/start", follow_redirects=True)
    cookies = parse_cookie_header(response.json()["cookies"])
    assert cookies == {"hop": "secure", "mid": "1"}

    response = client.get("http://example.org/insecure_start", follow_redirects=True)
    assert "z" not in client.cookies


def public_suffix_app(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/set":
        if request.url.host == "example.co.uk":
            return httpx.Response(
                200,
                headers=[
                    ("set-cookie", "a=1; Domain=co.uk"),
                    ("set-cookie", "b=2; Domain=example.co.uk"),
                ],
            )
        elif request.url.host == "myapp.appspot.com":
            return httpx.Response(
                200, headers={"set-cookie": "c=3; Domain=appspot.com"}
            )
        return httpx.Response(200, headers={"set-cookie": "d=4; Domain=example.org"})
    return echo_cookies(request)


def test_public_suffixes_rejected_via_caller_supplied_function() -> None:
    policy = httpx.SecureCookiePolicy(
        is_public_suffix=lambda domain: domain in {"co.uk", "appspot.com"}
    )
    client = httpx.Client(
        transport=httpx.MockTransport(public_suffix_app), cookie_policy=policy
    )

    client.get("https://example.co.uk/set")
    client.get("https://myapp.appspot.com/set")
    client.get("https://example.org/set")

    response = client.get("https://example.co.uk/echo")
    assert response.json() == {"cookies": "b=2"}
    response = client.get("https://myapp.appspot.com/echo")
    assert response.json() == {"cookies": None}
    response = client.get("https://example.org/echo")
    assert response.json() == {"cookies": "d=4"}


def domain_boundary_app(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/set":
        return httpx.Response(
            200,
            headers=[
                # Not a label-boundary match on the response host.
                ("set-cookie", "a=1; Domain=ample.org"),
                # Domain names are case-insensitive.
                ("set-cookie", "b=2; Domain=EXAMPLE.ORG"),
                # A server may not set cookies for a child domain.
                ("set-cookie", "c=3; Domain=sub.example.org"),
            ],
        )
    return echo_cookies(request)


def test_domain_matching_uses_label_boundaries() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(domain_boundary_app),
        cookie_policy=httpx.SecureCookiePolicy(),
    )

    client.get("https://example.org/set")

    response = client.get("https://example.org/echo")
    assert response.json() == {"cookies": "b=2"}
    # Domain cookies are sent to subdomains...
    response = client.get("https://sub.example.org/echo")
    assert response.json() == {"cookies": "b=2"}
    # ...but never to names that merely share a suffix.
    response = client.get("https://notexample.org/echo")
    assert response.json() == {"cookies": None}


def ip_app(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/set":
        return httpx.Response(
            200,
            headers=[
                ("set-cookie", "a=1"),
                # A `Domain` attribute on an IP literal is ignored,
                # leaving a host-only cookie.
                ("set-cookie", "b=2; Domain=127.0.0.1"),
                ("set-cookie", "c=3; Domain=0.0.1"),
            ],
        )
    return echo_cookies(request)


def test_ip_address_cookies_are_host_only() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(ip_app),
        cookie_policy=httpx.SecureCookiePolicy(),
    )

    client.get("http://127.0.0.1/set")

    response = client.get("http://127.0.0.1/echo")
    cookies = parse_cookie_header(response.json()["cookies"])
    assert cookies == {"a": "1", "b": "2"}
    for cookie in client.cookies.jar:
        assert not cookie.domain_specified


def test_two_clients_side_by_side() -> None:
    protected = httpx.Client(
        transport=httpx.MockTransport(secure_app),
        cookie_policy=httpx.SecureCookiePolicy(),
    )
    unprotected = httpx.Client(transport=httpx.MockTransport(secure_app))

    for client in (protected, unprotected):
        client.get("https://example.org/set_secure")
        client.get("http://example.org/http_overwrite")

    assert protected.cookies["session"] == "abc"
    assert unprotected.cookies["session"] == "evil"


def test_policy_does_not_leak_through_shared_cookie_jar() -> None:
    jar = CookieJar()
    policy = httpx.SecureCookiePolicy()
    protected = httpx.Client(
        cookies=jar,
        transport=httpx.MockTransport(secure_app),
        cookie_policy=policy,
    )
    unprotected = httpx.Client(cookies=jar, transport=httpx.MockTransport(secure_app))

    assert protected.cookies.policy is policy
    assert unprotected.cookies.policy is None

    protected.get("https://example.org/set_secure")
    protected.get("http://example.org/http_overwrite")
    assert jar and next(iter(jar)).value == "abc"

    # The other client shares the jar, but not the policy.
    unprotected.get("http://example.org/http_overwrite")
    assert next(iter(jar)).value == "evil"


def test_copying_cookies_does_not_copy_the_policy() -> None:
    cookies = httpx.Cookies(policy=httpx.SecureCookiePolicy())
    assert httpx.Cookies(cookies).policy is None


def test_manual_cookie_operations_bypass_the_policy() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(secure_app),
        cookie_policy=httpx.SecureCookiePolicy(),
    )

    client.get("https://example.org/set_secure")

    # Explicitly set or deleted cookies are not subject to the policy,
    # which only applies to cookies received in responses.
    client.cookies.set("session", "manual", domain="example.org")
    assert client.cookies["session"] == "manual"
    client.cookies.delete("session")
    assert "session" not in client.cookies

    client.cookies["__Host-manual"] = "1"
    assert client.cookies["__Host-manual"] == "1"


def test_replacing_client_cookies_keeps_the_policy() -> None:
    policy = httpx.SecureCookiePolicy()
    client = httpx.Client(
        transport=httpx.MockTransport(secure_app), cookie_policy=policy
    )

    client.cookies = {"other": "1"}
    assert client.cookies.policy is policy

    client.get("https://example.org/set_secure")
    client.get("http://example.org/http_overwrite")
    assert client.cookies["session"] == "abc"


@pytest.mark.anyio
async def test_async_client_cookie_policy() -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(secure_app),
        cookie_policy=httpx.SecureCookiePolicy(),
    ) as client:
        await client.get("https://example.org/set_secure")
        await client.get("http://example.org/http_overwrite")
        await client.get("http://example.org/http_expire_max_age")

        response = await client.get("https://example.org/echo")
        assert response.json() == {"cookies": "session=abc"}
