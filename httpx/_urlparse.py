"""
An implementation of `urlparse` that provides URL validation and normalization
as described by RFC3986.

We rely on this implementation rather than the one in Python's stdlib, because:

* It provides more complete URL validation.
* It properly differentiates between an empty querystring and an absent querystring,
  to distinguish URLs with a trailing '?'.
* It handles scheme, hostname, port, and path normalization.
* It supports IDNA hostnames, normalizing them to their encoded form.
* The API supports passing individual components, as well as the complete URL string.

Previously we relied on the excellent `rfc3986` package to handle URL parsing and
validation, but this module provides a simpler alternative, with less indirection
required.
"""

import ipaddress
import re
import typing

import idna

from ._exceptions import InvalidURL

MAX_URL_LENGTH = 65536

# https://datatracker.ietf.org/doc/html/rfc3986.html#section-2.3
UNRESERVED_CHARACTERS = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
SUB_DELIMS = "!$&'()*+,;="

# Percent-encoded sequences are validated *before* component-wise encoding,
# so a malformed sequence ("%zz", "%4") is rejected rather than having its
# leading "%" percent-encoded a second time.
PERCENT_ENCODED_REGEX = re.compile("%[A-Fa-f0-9]{2}")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

# Characters that are allowed to remain unencoded in each component, in
# addition to the unreserved character set. These sets deliberately differ
# per component so that delimiter characters are only treated as safe where
# they do not terminate the component:
#
# * userinfo: the sub-delimiters and ":". "@" must be encoded since it
#   marks the end of the userinfo.
# * path: the sub-delimiters plus the path-related gen-delimiters.
# * query: the sub-delimiters plus ":", "?", "[", "]" and "@". "/" is *not*
#   included here (it is encoded as "%2F"), so the query does not share the
#   path's safe set.
# * fragment: the sub-delimiters plus "/", "?", ":", "[", "]" and "@".
#   "#" may remain as-is, as the fragment is the final component.
USERINFO_SAFE_CHARACTERS = SUB_DELIMS + ":"
PATH_SAFE_CHARACTERS = SUB_DELIMS + ":/[]@"
QUERY_SAFE_CHARACTERS = SUB_DELIMS + ":?[]@"
FRAGMENT_SAFE_CHARACTERS = SUB_DELIMS + ":/?#[]@"
HOST_SAFE_CHARACTERS = SUB_DELIMS

# When a username or password is supplied as a *decoded* value it is
# pre-encoded before the ":" separator is inserted. The separator itself is
# therefore excluded from the safe set, along with "@", so a ":" inside a
# username (eg. "a:b") cannot later be mistaken for the user/password split.
USERINFO_SUBCOMPONENT_SAFE_CHARACTERS = SUB_DELIMS


# {scheme}:      (optional)
# //{authority}  (optional)
# {path}
# ?{query}       (optional)
# #{fragment}    (optional)
URL_REGEX = re.compile(
    (
        r"(?:(?P<scheme>{scheme}):)?"
        r"(?://(?P<authority>{authority}))?"
        r"(?P<path>{path})"
        r"(?:\?(?P<query>{query}))?"
        r"(?:#(?P<fragment>{fragment}))?"
    ).format(
        scheme="([a-zA-Z][a-zA-Z0-9+.-]*)?",
        authority="[^/?#]*",
        path="[^?#]*",
        query="[^#]*",
        fragment=".*",
    )
)

# {userinfo}@    (optional)
# {host}
# :{port}        (optional)
AUTHORITY_REGEX = re.compile(
    (
        r"(?:(?P<userinfo>{userinfo})@)?" r"(?P<host>{host})" r":?(?P<port>{port})?"
    ).format(
        userinfo=".*",  # Any character sequence.
        host="(\\[.*\\]|[^:@]*)",  # Either any character sequence excluding ':' or '@',
        # or an IPv6 address enclosed within square brackets.
        port=".*",  # Any character sequence.
    )
)


# If we call urlparse with an individual component, then we need to regex
# validate that component individually.
# Note that we're duplicating the same strings as above. Shock! Horror!!
COMPONENT_REGEX = {
    "scheme": re.compile("([a-zA-Z][a-zA-Z0-9+.-]*)?"),
    "authority": re.compile("[^/?#]*"),
    "path": re.compile("[^?#]*"),
    "query": re.compile("[^#]*"),
    "fragment": re.compile(".*"),
    "userinfo": re.compile("[^@]*"),
    "host": re.compile("(\\[.*\\]|[^:]*)"),
    "port": re.compile(".*"),
}


# We use these simple regexs as a first pass before handing off to
# the stdlib 'ipaddress' module for IP address validation.
IPv4_STYLE_HOSTNAME = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")
IPv6_STYLE_HOSTNAME = re.compile(r"^\[.*\]$")


class ParseResult(typing.NamedTuple):
    scheme: str
    userinfo: str
    host: str
    port: typing.Optional[int]
    path: str
    query: typing.Optional[str]
    fragment: typing.Optional[str]

    @property
    def authority(self) -> str:
        return "".join(
            [
                f"{self.userinfo}@" if self.userinfo else "",
                f"[{self.host}]" if ":" in self.host else self.host,
                f":{self.port}" if self.port is not None else "",
            ]
        )

    @property
    def netloc(self) -> str:
        return "".join(
            [
                f"[{self.host}]" if ":" in self.host else self.host,
                f":{self.port}" if self.port is not None else "",
            ]
        )

    def copy_with(self, **kwargs: typing.Optional[str]) -> "ParseResult":
        if not kwargs:
            return self

        defaults = {
            "scheme": self.scheme,
            "authority": self.authority,
            "path": self.path,
            "query": self.query,
            "fragment": self.fragment,
        }
        defaults.update(kwargs)
        return urlparse("", **defaults)

    def __str__(self) -> str:
        authority = self.authority
        return "".join(
            [
                f"{self.scheme}:" if self.scheme else "",
                f"//{authority}" if authority else "",
                self.path,
                f"?{self.query}" if self.query is not None else "",
                f"#{self.fragment}" if self.fragment is not None else "",
            ]
        )


def urlparse(url: str = "", **kwargs: typing.Optional[str]) -> ParseResult:
    # Initial basic checks on allowable URLs.
    # ---------------------------------------

    # Hard limit the maximum allowable URL length.
    if len(url) > MAX_URL_LENGTH:
        raise InvalidURL("URL too long")

    # If a URL includes any ASCII control characters including \t, \r, \n,
    # then treat it as invalid.
    if any(char.isascii() and not char.isprintable() for char in url):
        raise InvalidURL("Invalid non-printable ASCII character in URL")

    # Some keyword arguments require special handling.
    # ------------------------------------------------

    # Coerce "port" to a string, if it is provided as an integer.
    if "port" in kwargs:
        port = kwargs["port"]
        kwargs["port"] = str(port) if isinstance(port, int) else port

    # Replace "netloc" with "host and "port".
    if "netloc" in kwargs:
        netloc = kwargs.pop("netloc") or ""
        kwargs["host"], _, kwargs["port"] = netloc.partition(":")

    # Replace "username" and/or "password" with "userinfo".
    #
    # These values are *decoded* input (eg. the "@" in "user@example.com"
    # represents an actual "@" character), so a literal "%" is encoded as
    # "%25". The ":" and "@" delimiters are encoded too, so the assembled
    # userinfo cannot be mis-split when it is reparsed. When a fully-formed
    # userinfo is supplied instead, it is treated as already-serialized input
    # below, with existing escapes validated.
    if "username" in kwargs or "password" in kwargs:
        username = quote(
            kwargs.pop("username", "") or "",
            safe=USERINFO_SUBCOMPONENT_SAFE_CHARACTERS,
        )
        password = quote(
            kwargs.pop("password", "") or "",
            safe=USERINFO_SUBCOMPONENT_SAFE_CHARACTERS,
        )
        kwargs["userinfo"] = f"{username}:{password}" if password else username

    # Replace "raw_path" with "path" and "query".
    if "raw_path" in kwargs:
        raw_path = kwargs.pop("raw_path") or ""
        kwargs["path"], seperator, kwargs["query"] = raw_path.partition("?")
        if not seperator:
            kwargs["query"] = None

    # Ensure that IPv6 "host" addresses are always escaped with "[...]".
    if "host" in kwargs:
        host = kwargs.get("host") or ""
        if ":" in host and not (host.startswith("[") and host.endswith("]")):
            kwargs["host"] = f"[{host}]"

    # If any keyword arguments are provided, ensure they are valid.
    # -------------------------------------------------------------

    for key, value in kwargs.items():
        if value is not None:
            if len(value) > MAX_URL_LENGTH:
                raise InvalidURL(f"URL component '{key}' too long")

            # If a component includes any ASCII control characters including \t, \r, \n,
            # then treat it as invalid.
            if any(char.isascii() and not char.isprintable() for char in value):
                raise InvalidURL(
                    f"Invalid non-printable ASCII character in URL component '{key}'"
                )

            # Ensure that keyword arguments match as a valid regex.
            if not COMPONENT_REGEX[key].fullmatch(value):
                raise InvalidURL(f"Invalid URL component '{key}'")

    # The URL_REGEX will always match, but may have empty components.
    url_match = URL_REGEX.match(url)
    assert url_match is not None
    url_dict = url_match.groupdict()

    # * 'scheme', 'authority', and 'path' may be empty strings.
    # * 'query' may be 'None', indicating no trailing "?" portion.
    #   Any string including the empty string, indicates a trailing "?".
    # * 'fragment' may be 'None', indicating no trailing "#" portion.
    #   Any string including the empty string, indicates a trailing "#".
    scheme = kwargs.get("scheme", url_dict["scheme"]) or ""
    authority = kwargs.get("authority", url_dict["authority"]) or ""
    path = kwargs.get("path", url_dict["path"]) or ""
    query = kwargs.get("query", url_dict["query"])
    fragment = kwargs.get("fragment", url_dict["fragment"])

    # The AUTHORITY_REGEX will always match, but may have empty components.
    authority_match = AUTHORITY_REGEX.match(authority)
    assert authority_match is not None
    authority_dict = authority_match.groupdict()

    # * 'userinfo' and 'host' may be empty strings.
    # * 'port' may be 'None'.
    userinfo = kwargs.get("userinfo", authority_dict["userinfo"]) or ""
    host = kwargs.get("host", authority_dict["host"]) or ""
    port = kwargs.get("port", authority_dict["port"])

    # Normalize and validate each component.
    # We end up with a parsed representation of the URL,
    # with components that are plain ASCII bytestrings.
    parsed_scheme: str = scheme.lower()
    # Existing percent-encoded sequences are validated and preserved, while
    # other characters are encoded against the safe set for this component.
    parsed_userinfo: str = requote(userinfo, safe=USERINFO_SAFE_CHARACTERS)
    parsed_host: str = encode_host(host)
    parsed_port: typing.Optional[int] = normalize_port(port, scheme)

    has_scheme = parsed_scheme != ""
    has_authority = (
        parsed_userinfo != "" or parsed_host != "" or parsed_port is not None
    )
    validate_path(path, has_scheme=has_scheme, has_authority=has_authority)
    if has_authority:
        path = normalize_path(path)

    # The GEN_DELIMS set is... : / ? # [ ] @
    # These do not need to be percent-quoted unless they serve as delimiters for the
    # specific component.

    # Each component is encoded against its own safe character set, so that an
    # already-escaped sequence is never re-encoded and a raw reserved character
    # cannot leak past a component boundary.

    # For 'path' we need to drop ? and # from the GEN_DELIMS set.
    parsed_path: str = requote(path, safe=PATH_SAFE_CHARACTERS)
    # For 'query' we need to drop '#' from the GEN_DELIMS set.
    # We also exclude '/' because it is more robust to replace it with a percent
    # encoding despite it not being a requirement of the spec.
    parsed_query: typing.Optional[str] = (
        None if query is None else requote(query, safe=QUERY_SAFE_CHARACTERS)
    )
    # For 'fragment' we can include all of the GEN_DELIMS set.
    parsed_fragment: typing.Optional[str] = (
        None if fragment is None else requote(fragment, safe=FRAGMENT_SAFE_CHARACTERS)
    )

    # The parsed ASCII bytestrings are our canonical form.
    # All properties of the URL are derived from these.
    return ParseResult(
        parsed_scheme,
        parsed_userinfo,
        parsed_host,
        parsed_port,
        parsed_path,
        parsed_query,
        parsed_fragment,
    )


def encode_host(host: str) -> str:
    if not host:
        return ""

    elif IPv4_STYLE_HOSTNAME.match(host):
        # Validate IPv4 hostnames like #.#.#.#
        #
        # From https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
        #
        # IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet
        try:
            ipaddress.IPv4Address(host)
        except ipaddress.AddressValueError:
            raise InvalidURL(f"Invalid IPv4 address: {host!r}")
        return host

    elif IPv6_STYLE_HOSTNAME.match(host):
        # Validate IPv6 hostnames like [...]
        #
        # From https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
        #
        # "A host identified by an Internet Protocol literal address, version 6
        # [RFC3513] or later, is distinguished by enclosing the IP literal
        # within square brackets ("[" and "]").  This is the only place where
        # square bracket characters are allowed in the URI syntax."
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ipaddress.AddressValueError:
            raise InvalidURL(f"Invalid IPv6 address: {host!r}")
        return host[1:-1]

    elif host.isascii():
        # Regular ASCII hostnames
        #
        # From https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
        #
        # reg-name    = *( unreserved / pct-encoded / sub-delims )
        return requote(host.lower(), safe=HOST_SAFE_CHARACTERS)

    # IDNA hostnames
    try:
        return idna.encode(host.lower()).decode("ascii")
    except idna.IDNAError:
        raise InvalidURL(f"Invalid IDNA hostname: {host!r}")


def normalize_port(
    port: typing.Optional[typing.Union[str, int]], scheme: str
) -> typing.Optional[int]:
    # From https://tools.ietf.org/html/rfc3986#section-3.2.3
    #
    # "A scheme may define a default port.  For example, the "http" scheme
    # defines a default port of "80", corresponding to its reserved TCP
    # port number.  The type of port designated by the port number (e.g.,
    # TCP, UDP, SCTP) is defined by the URI scheme.  URI producers and
    # normalizers should omit the port component and its ":" delimiter if
    # port is empty or if its value would be the same as that of the
    # scheme's default."
    if port is None or port == "":
        return None

    try:
        port_as_int = int(port)
    except ValueError:
        raise InvalidURL(f"Invalid port: {port!r}")

    # See https://url.spec.whatwg.org/#url-miscellaneous
    default_port = {"ftp": 21, "http": 80, "https": 443, "ws": 80, "wss": 443}.get(
        scheme
    )
    if port_as_int == default_port:
        return None
    return port_as_int


def validate_path(path: str, has_scheme: bool, has_authority: bool) -> None:
    """
    Path validation rules that depend on if the URL contains
    a scheme or authority component.

    See https://datatracker.ietf.org/doc/html/rfc3986.html#section-3.3
    """
    if has_authority:
        # If a URI contains an authority component, then the path component
        # must either be empty or begin with a slash ("/") character."
        if path and not path.startswith("/"):
            raise InvalidURL("For absolute URLs, path must be empty or begin with '/'")
    else:
        # If a URI does not contain an authority component, then the path cannot begin
        # with two slash characters ("//").
        if path.startswith("//"):
            raise InvalidURL(
                "URLs with no authority component cannot have a path starting with '//'"
            )
        # In addition, a URI reference (Section 4.1) may be a relative-path reference,
        # in which case the first path segment cannot contain a colon (":") character.
        if path.startswith(":") and not has_scheme:
            raise InvalidURL(
                "URLs with no scheme component cannot have a path starting with ':'"
            )


def normalize_path(path: str) -> str:
    """
    Drop "." and ".." segments from a URL path.

    For example:

        normalize_path("/path/./to/somewhere/..") == "/path/to"
    """
    # https://datatracker.ietf.org/doc/html/rfc3986#section-5.2.4
    components = path.split("/")
    output: typing.List[str] = []
    for component in components:
        if component == ".":
            pass
        elif component == "..":
            if output and output != [""]:
                output.pop()
        else:
            output.append(component)
    return "/".join(output)


def percent_encode(char: str) -> str:
    """
    Replace a single character with the percent-encoded representation.

    Characters outside the ASCII range are represented with their a percent-encoded
    representation of their UTF-8 byte sequence.

    For example:

        percent_encode(" ") == "%20"
    """
    return "".join([f"%{byte:02x}" for byte in char.encode("utf-8")]).upper()


def is_safe(string: str, safe: str = "/") -> bool:
    """
    Determine if a given string is already quote-safe.
    """
    NON_ESCAPED_CHARS = UNRESERVED_CHARACTERS + safe + "%"

    # All characters must already be non-escaping or '%'
    for char in string:
        if char not in NON_ESCAPED_CHARS:
            return False

    # Any '%' characters must be valid '%xx' escape sequences.
    return string.count("%") == len(PERCENT_ENCODED_REGEX.findall(string))


def quote(string: str, safe: str = "/") -> str:
    """
    Use percent-encoding to quote a *decoded* value, such as a query
    parameter name/value or a username/password supplied to ``copy_with``.

    If the value already consists solely of safe characters and valid
    percent-encoded sequences it is returned untouched, so values like
    "with%20spaces" are not encoded a second time. Otherwise the *whole*
    value is encoded, including any "%" characters (as "%25"), since the
    value is treated as plain text rather than a serialized component.
    """
    if is_safe(string, safe=safe):
        return string

    NON_ESCAPED_CHARS = UNRESERVED_CHARACTERS + safe
    return "".join(
        [char if char in NON_ESCAPED_CHARS else percent_encode(char) for char in string]
    )


def requote(string: str, safe: str = "/") -> str:
    """
    Normalize a component that is already serialized (possibly containing
    percent-encoded sequences) into its canonical ASCII form.

    Processing follows the WHATWG "percent-encode after parsing" model:

    1.  Existing percent-encoded sequences are validated first. A "%" that
        is not followed by two ASCII hex digits is invalid and raises
        ``InvalidURL`` for every component, so malformed input can never be
        silently re-encoded (eg. "%zz" -> "%25zz").
    2.  Valid "%xx" sequences are passed through untouched. The parse step
        guarantees every component contains only ASCII, so this is also
        idempotent: requoting a parsed component leaves it unchanged.
    3.  Unreserved characters and the component-specific `safe` characters
        are left alone; every other character is UTF-8 percent-encoded.
    """
    NON_ESCAPED_CHARS = UNRESERVED_CHARACTERS + safe
    output: typing.List[str] = []
    length = len(string)
    index = 0
    while index < length:
        char = string[index]
        if char == "%":
            # A percent must be followed by two ASCII hex digits, otherwise
            # it cannot be an escape sequence and a raw "%" is not allowed
            # in any component.
            if (
                index + 2 >= length
                or string[index + 1] not in _HEX_DIGITS
                or string[index + 2] not in _HEX_DIGITS
            ):
                raise InvalidURL("Invalid percent-escape sequence in URL")
            output.append(string[index : index + 3])
            index += 3
        elif char in NON_ESCAPED_CHARS:
            output.append(char)
            index += 1
        else:
            output.append(percent_encode(char))
            index += 1
    return "".join(output)


def urlencode(items: typing.List[typing.Tuple[str, str]]) -> str:
    """
    We can use a much simpler version of the stdlib urlencode here because
    we don't need to handle a bunch of different typing cases, such as bytes vs str.

    https://github.com/python/cpython/blob/b2f7b2ef0b5421e01efb8c7bee2ef95d3bab77eb/Lib/urllib/parse.py#L926

    Note that we use '%20' encoding for spaces. and '%2F  for '/'.
    This is slightly different than `requests`, but is the behaviour that browsers use.

    See
    - https://github.com/encode/httpx/issues/2536
    - https://github.com/encode/httpx/issues/2721
    - https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlencode
    """
    return "&".join([quote(k, safe="") + "=" + quote(v, safe="") for k, v in items])
