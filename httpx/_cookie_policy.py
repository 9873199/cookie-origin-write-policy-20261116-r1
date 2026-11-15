"""
An optional, browser-style security policy for the cookie receiving chain.

The policy implemented here follows the rules that browsers apply when
deciding whether an incoming `Set-Cookie` header should be honoured:

* The decision is always made against the URL of the actual response that
  carried the header. The final request URL of a redirect chain, or a
  user-supplied `Host` header, are never used as a substitute.
* Domain handling is canonicalised before any comparison: names are
  lowercased, and any trailing "root dot" is insignificant, so that
  `example.org` and `EXAMPLE.org.` are the same domain. IP literals
  (IPv4 or IPv6) only ever match themselves, and cannot carry domain
  cookies: a `Domain` attribute on an IP literal is dropped if it
  exactly matches the host, leaving a host-only cookie, and rejected
  outright otherwise. Domain matching works on label boundaries, so
  `example.org` matches `sub.example.org` but never `notexample.org`.
* Cookies whose name starts with `__Secure-` must be set over a secure
  scheme and must include the `Secure` attribute. Cookies whose name
  starts with `__Host-` additionally require `Path=/` and must not
  include a `Domain` attribute at all (an empty `Domain=` attribute
  still counts as being present). Prefixes are matched
  case-insensitively, as browsers do.
* A `Domain` attribute that is a public suffix is rejected. Whether a
  domain is a public suffix is determined by a pure function supplied
  by the caller. The library never downloads a public suffix list.
* An insecure (`http://`) response may not set a cookie carrying the
  `Secure` attribute, and may not write or delete any cookie that
  overlaps an existing `Secure` cookie in the jar. Overlap means the
  same name, with domains that domain-match each other in either
  direction, and paths that path-match each other in either direction.
  This also covers deletion attempts using an expired date or
  `Max-Age=0`, since those arrive as regular `Set-Cookie` writes.
  A rejected write is dropped before it reaches the cookie jar, so the
  pre-existing value is left untouched.

The policy only applies to cookies received in responses. Cookies that
are set explicitly through `Cookies.set()`, `Cookies.update()` or the
mapping interface are always applied as-is.
"""

from __future__ import annotations

import ipaddress
import typing
from http.cookiejar import CookieJar

from ._urls import URL

__all__ = ["SecureCookiePolicy"]


def _normalize_domain(domain: str) -> str:
    """
    Canonicalise a domain name for comparison purposes.

    Domain names are case-insensitive, and a trailing "root dot" is
    insignificant, so `EXAMPLE.org.` canonicalises to `example.org`.
    """
    return domain.lower().rstrip(".")


def _is_ip_address(host: str) -> bool:
    """
    Return `True` if the host is an IPv4 or IPv6 literal.
    """
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _domain_match(host: str, domain: str) -> bool:
    """
    Domain matching, as described in RFC 6265 section 5.1.3, applied to
    already-canonicalised domains.

    Matching is on label boundaries only: `sub.example.org` matches
    `example.org`, but `notexample.org` does not. IP literals only ever
    match themselves.
    """
    if _is_ip_address(host):
        return host == domain
    return host == domain or host.endswith("." + domain)


def _default_path(uri_path: str) -> str:
    """
    The default cookie path for a request path, as described in
    RFC 6265 section 5.1.4.
    """
    if not uri_path.startswith("/") or uri_path.count("/") == 1:
        return "/"
    return uri_path[: uri_path.rindex("/")]


def _path_match(request_path: str, cookie_path: str) -> bool:
    """
    Path matching, as described in RFC 6265 section 5.1.4.
    """
    if request_path == cookie_path:
        return True
    if request_path.startswith(cookie_path):
        if cookie_path.endswith("/"):
            return True
        return request_path[len(cookie_path)] == "/"
    return False


class _ParsedSetCookie(typing.NamedTuple):
    name: str
    value: str
    # The canonicalised `Domain` attribute, or `None` if the attribute
    # was absent or empty.
    domain: str | None
    # `True` if a `Domain` attribute was present at all, even an empty one.
    has_domain_attribute: bool
    # The `Path` attribute, if present and absolute.
    path: str | None
    secure: bool


def _parse_set_cookie(header: str) -> _ParsedSetCookie | None:
    """
    A minimal parse of a `Set-Cookie` header, sufficient to apply the
    security policy. Returns `None` for headers that don't include a
    well-formed name/value pair.
    """
    pair, _, attributes = header.partition(";")
    if "=" not in pair:
        return None
    name, _, value = pair.partition("=")
    name = name.strip()
    if not name:
        return None

    domain: str | None = None
    has_domain_attribute = False
    path: str | None = None
    secure = False

    for attribute in attributes.split(";"):
        attribute_name, _, attribute_value = attribute.partition("=")
        attribute_name = attribute_name.strip().lower()
        attribute_value = attribute_value.strip()
        if attribute_name == "domain":
            has_domain_attribute = True
            # Leading dots in the `Domain` attribute are insignificant,
            # as per RFC 6265 section 5.2.3.
            domain = _normalize_domain(attribute_value.lstrip(".")) or None
        elif attribute_name == "path":
            # A `Path` attribute that isn't absolute is ignored,
            # as per RFC 6265 section 5.2.4.
            path = attribute_value if attribute_value.startswith("/") else None
        elif attribute_name == "secure":
            secure = True

    return _ParsedSetCookie(
        name=name,
        value=value.strip(),
        domain=domain,
        has_domain_attribute=has_domain_attribute,
        path=path,
        secure=secure,
    )


def _remove_domain_attribute(header: str) -> str:
    """
    Return a `Set-Cookie` header with any `Domain` attribute removed,
    leaving a host-only cookie.
    """
    pair, _, attributes = header.partition(";")
    kept: list[str] = []
    for attribute in attributes.split(";"):
        attribute_name, _, _ = attribute.partition("=")
        if attribute_name.strip().lower() != "domain":
            kept.append(attribute)
    return ";".join([pair, *kept])


class SecureCookiePolicy:
    """
    A browser-style security policy for incoming `Set-Cookie` headers.

    Usage:

    ```python
    >>> client = httpx.Client(cookie_policy=httpx.SecureCookiePolicy())
    ```

    An optional `is_public_suffix` callable may be provided to reject
    cookies that are set on public suffixes. It is called with a
    canonicalised (lowercased, no leading or trailing dots) domain, and
    should return `True` if the domain is a public suffix. The callable
    is a pure function provided by the caller, typically closing over a
    snapshot of the public suffix list. HTTPX never downloads one.
    """

    def __init__(
        self, is_public_suffix: typing.Callable[[str], bool] | None = None
    ) -> None:
        self._is_public_suffix = is_public_suffix

    def filter_set_cookie_headers(
        self, set_cookie_headers: list[str], url: URL, jar: CookieJar
    ) -> list[str]:
        """
        Given the `Set-Cookie` headers of a response, the URL of the actual
        response, and the current cookie jar, return the headers that the
        policy allows to be written to the jar. Headers may be rewritten,
        such as dropping a `Domain` attribute from a cookie set by an IP
        literal host.
        """
        filtered: list[str] = []
        for header in set_cookie_headers:
            allowed, rewritten = self._evaluate(header, url, jar)
            if allowed:
                filtered.append(rewritten)
        return filtered

    def allows(self, set_cookie: str, url: URL, jar: CookieJar) -> bool:
        """
        Return `True` if a single `Set-Cookie` header, received from the
        given response URL, may be written to the given cookie jar.
        """
        allowed, _ = self._evaluate(set_cookie, url, jar)
        return allowed

    def _evaluate(
        self, set_cookie: str, url: URL, jar: CookieJar
    ) -> tuple[bool, str]:
        """
        Evaluate a single `Set-Cookie` header against the policy.

        Returns a two-tuple of whether the header is allowed, and the
        header to write to the jar, which may have been rewritten.
        """
        parsed = _parse_set_cookie(set_cookie)
        if parsed is None:
            # Not a well-formed cookie header. There's nothing here for
            # the policy to enforce, so leave it to the cookie jar,
            # which will also end up ignoring it.
            return True, set_cookie

        # The scheme and host of the actual response determine the
        # security context. Redirect targets and `Host` headers play
        # no part here.
        is_secure_scheme = url.scheme == "https"
        host = _normalize_domain(url.host)

        domain = parsed.domain
        if domain is not None and _is_ip_address(host):
            # IP literals cannot carry domain cookies. A `Domain`
            # attribute that exactly matches the host is dropped,
            # leaving a host-only cookie. Anything else is rejected
            # outright, since IP literals only ever match themselves.
            if domain != host:
                return False, set_cookie
            return self._evaluate(_remove_domain_attribute(set_cookie), url, jar)

        if domain is not None:
            if not _domain_match(host, domain):
                # Servers may only set cookies for their own domain
                # or a parent domain.
                return False, set_cookie
            if self._is_public_suffix is not None and self._is_public_suffix(
                domain
            ):
                # Cookies may not be set on public suffixes.
                return False, set_cookie

        effective_domain = host if domain is None else domain
        effective_path = (
            parsed.path if parsed.path is not None else _default_path(url.path)
        )

        # The `__Secure-` and `__Host-` prefixes are enforced, matched
        # case-insensitively as browsers do.
        name = parsed.name.lower()
        if name.startswith(("__secure-", "__host-")):
            if not is_secure_scheme or not parsed.secure:
                return False, set_cookie
        if name.startswith("__host-"):
            # A `Domain` attribute disqualifies the cookie, even an
            # empty one, and the effective path must be exactly `/`.
            if parsed.has_domain_attribute or effective_path != "/":
                return False, set_cookie

        if parsed.secure and not is_secure_scheme:
            # The `Secure` attribute may not be set over an insecure scheme.
            return False, set_cookie

        if not is_secure_scheme:
            # An insecure response may not write or delete any cookie
            # that overlaps an existing `Secure` cookie. This also
            # covers deletion attempts using an expired date or
            # `Max-Age=0`, which arrive as regular `Set-Cookie` writes.
            for cookie in jar:
                if not cookie.secure or cookie.name != parsed.name:
                    continue
                other_domain = _normalize_domain(cookie.domain.lstrip("."))
                if not (
                    _domain_match(effective_domain, other_domain)
                    or _domain_match(other_domain, effective_domain)
                ):
                    continue
                other_path = cookie.path or "/"
                if not (
                    _path_match(effective_path, other_path)
                    or _path_match(other_path, effective_path)
                ):
                    continue
                return False, set_cookie

        return True, set_cookie
