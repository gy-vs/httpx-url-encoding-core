import pytest

import httpx

# Tests for `httpx.URL` instantiation and property accessors.


def test_basic_url():
    url = httpx.URL("https://www.example.com/")

    assert url.scheme == "https"
    assert url.userinfo == b""
    assert url.netloc == b"www.example.com"
    assert url.host == "www.example.com"
    assert url.port is None
    assert url.path == "/"
    assert url.query == b""
    assert url.fragment == ""

    assert str(url) == "https://www.example.com/"
    assert repr(url) == "URL('https://www.example.com/')"


def test_complete_url():
    url = httpx.URL("https://example.org:123/path/to/somewhere?abc=123#anchor")
    assert url.scheme == "https"
    assert url.host == "example.org"
    assert url.port == 123
    assert url.path == "/path/to/somewhere"
    assert url.query == b"abc=123"
    assert url.raw_path == b"/path/to/somewhere?abc=123"
    assert url.fragment == "anchor"

    assert str(url) == "https://example.org:123/path/to/somewhere?abc=123#anchor"
    assert (
        repr(url) == "URL('https://example.org:123/path/to/somewhere?abc=123#anchor')"
    )


def test_url_with_empty_query():
    """
    URLs with and without a trailing `?` but an empty query component
    should preserve the information on the raw path.
    """
    url = httpx.URL("https://www.example.com/path")
    assert url.path == "/path"
    assert url.query == b""
    assert url.raw_path == b"/path"

    url = httpx.URL("https://www.example.com/path?")
    assert url.path == "/path"
    assert url.query == b""
    assert url.raw_path == b"/path?"


def test_url_no_scheme():
    url = httpx.URL("://example.com")
    assert url.scheme == ""
    assert url.host == "example.com"
    assert url.path == "/"


def test_url_no_authority():
    url = httpx.URL("http://")
    assert url.scheme == "http"
    assert url.host == ""
    assert url.path == "/"


# Tests for percent encoding across path, query, and fragment...


def test_path_percent_encoding():
    # Test percent encoding for SUB_DELIMS ALPHA NUM and allowable GEN_DELIMS
    url = httpx.URL("https://example.com/!$&'()*+,;= abc ABC 123 :/[]@")
    assert url.raw_path == b"/!$&'()*+,;=%20abc%20ABC%20123%20:/[]@"
    assert url.path == "/!$&'()*+,;= abc ABC 123 :/[]@"
    assert url.query == b""
    assert url.fragment == ""


def test_query_percent_encoding():
    # Test percent encoding for SUB_DELIMS ALPHA NUM and allowable GEN_DELIMS
    url = httpx.URL("https://example.com/?!$&'()*+,;= abc ABC 123 :/[]@" + "?")
    assert url.raw_path == b"/?!$&'()*+,;=%20abc%20ABC%20123%20:%2F[]@?"
    assert url.path == "/"
    assert url.query == b"!$&'()*+,;=%20abc%20ABC%20123%20:%2F[]@?"
    assert url.fragment == ""


def test_fragment_percent_encoding():
    # Test percent encoding for SUB_DELIMS ALPHA NUM and allowable GEN_DELIMS
    url = httpx.URL("https://example.com/#!$&'()*+,;= abc ABC 123 :/[]@" + "?#")
    assert url.raw_path == b"/"
    assert url.path == "/"
    assert url.query == b""
    assert url.fragment == "!$&'()*+,;= abc ABC 123 :/[]@?#"


def test_url_query_encoding():
    """
    URL query parameters should use '%20' to encoding spaces,
    and should treat '/' as a safe character. This behaviour differs
    across clients, but we're matching browser behaviour here.

    See https://github.com/encode/httpx/issues/2536
    and https://github.com/encode/httpx/discussions/2460
    """
    url = httpx.URL("https://www.example.com/?a=b c&d=e/f")
    assert url.raw_path == b"/?a=b%20c&d=e%2Ff"

    url = httpx.URL("https://www.example.com/", params={"a": "b c", "d": "e/f"})
    assert url.raw_path == b"/?a=b%20c&d=e%2Ff"


def test_url_with_url_encoded_path():
    url = httpx.URL("https://www.example.com/path%20to%20somewhere")
    assert url.path == "/path to somewhere"
    assert url.query == b""
    assert url.raw_path == b"/path%20to%20somewhere"


def test_url_params():
    url = httpx.URL("https://example.org:123/path/to/somewhere", params={"a": "123"})
    assert str(url) == "https://example.org:123/path/to/somewhere?a=123"
    assert url.params == httpx.QueryParams({"a": "123"})

    url = httpx.URL(
        "https://example.org:123/path/to/somewhere?b=456", params={"a": "123"}
    )
    assert str(url) == "https://example.org:123/path/to/somewhere?a=123"
    assert url.params == httpx.QueryParams({"a": "123"})


# Tests for username and password


@pytest.mark.parametrize(
    "url,userinfo,username,password",
    [
        # username and password in URL.
        (
            "https://username:password@example.com",
            b"username:password",
            "username",
            "password",
        ),
        # username and password in URL with percent escape sequences.
        (
            "https://username%40gmail.com:pa%20ssword@example.com",
            b"username%40gmail.com:pa%20ssword",
            "username@gmail.com",
            "pa ssword",
        ),
        (
            "https://user%20name:p%40ssword@example.com",
            b"user%20name:p%40ssword",
            "user name",
            "p@ssword",
        ),
        # username and password in URL without percent escape sequences.
        (
            "https://username@gmail.com:pa ssword@example.com",
            b"username%40gmail.com:pa%20ssword",
            "username@gmail.com",
            "pa ssword",
        ),
        (
            "https://user name:p@ssword@example.com",
            b"user%20name:p%40ssword",
            "user name",
            "p@ssword",
        ),
    ],
)
def test_url_username_and_password(url, userinfo, username, password):
    url = httpx.URL(url)
    assert url.userinfo == userinfo
    assert url.username == username
    assert url.password == password


# Tests for different host types


def test_url_valid_host():
    url = httpx.URL("https://example.com/")
    assert url.host == "example.com"


def test_url_normalized_host():
    url = httpx.URL("https://EXAMPLE.com/")
    assert url.host == "example.com"


def test_url_ipv4_like_host():
    """rare host names used to quality as IPv4"""
    url = httpx.URL("https://023b76x43144/")
    assert url.host == "023b76x43144"


# Tests for different port types


def test_url_valid_port():
    url = httpx.URL("https://example.com:123/")
    assert url.port == 123


def test_url_normalized_port():
    # If the port matches the scheme default it is normalized to None.
    url = httpx.URL("https://example.com:443/")
    assert url.port is None


def test_url_invalid_port():
    with pytest.raises(httpx.InvalidURL) as exc:
        httpx.URL("https://example.com:abc/")
    assert str(exc.value) == "Invalid port: 'abc'"


# Tests for path handling


def test_url_normalized_path():
    url = httpx.URL("https://example.com/abc/def/../ghi/./jkl")
    assert url.path == "/abc/ghi/jkl"


def test_url_escaped_path():
    url = httpx.URL("https://example.com/ /🌟/")
    assert url.raw_path == b"/%20/%F0%9F%8C%9F/"


def test_url_leading_dot_prefix_on_absolute_url():
    url = httpx.URL("https://example.com/../abc")
    assert url.path == "/abc"


def test_url_leading_dot_prefix_on_relative_url():
    url = httpx.URL("../abc")
    assert url.path == "../abc"


# Tests for optional percent encoding


def test_param_requires_encoding():
    url = httpx.URL("http://webservice", params={"u": "with spaces"})
    assert str(url) == "http://webservice?u=with%20spaces"


def test_param_does_not_require_encoding():
    url = httpx.URL("http://webservice", params={"u": "with%20spaces"})
    assert str(url) == "http://webservice?u=with%20spaces"


def test_param_with_existing_escape_requires_encoding():
    url = httpx.URL("http://webservice", params={"u": "http://example.com?q=foo%2Fa"})
    assert str(url) == "http://webservice?u=http%3A%2F%2Fexample.com%3Fq%3Dfoo%252Fa"


# Tests for invalid URLs


def test_url_invalid_hostname():
    """
    Ensure that invalid URLs raise an `httpx.InvalidURL` exception.
    """
    with pytest.raises(httpx.InvalidURL):
        httpx.URL("https://😇/")


def test_url_excessively_long_url():
    with pytest.raises(httpx.InvalidURL) as exc:
        httpx.URL("https://www.example.com/" + "x" * 100_000)
    assert str(exc.value) == "URL too long"


def test_url_excessively_long_component():
    with pytest.raises(httpx.InvalidURL) as exc:
        httpx.URL("https://www.example.com", path="/" + "x" * 100_000)
    assert str(exc.value) == "URL component 'path' too long"


def test_url_non_printing_character_in_url():
    with pytest.raises(httpx.InvalidURL) as exc:
        httpx.URL("https://www.example.com/\n")
    assert str(exc.value) == "Invalid non-printable ASCII character in URL"


def test_url_non_printing_character_in_component():
    with pytest.raises(httpx.InvalidURL) as exc:
        httpx.URL("https://www.example.com", path="/\n")
    assert (
        str(exc.value)
        == "Invalid non-printable ASCII character in URL component 'path'"
    )


# Test for url components


def test_url_with_components():
    url = httpx.URL(scheme="https", host="www.example.com", path="/")

    assert url.scheme == "https"
    assert url.userinfo == b""
    assert url.host == "www.example.com"
    assert url.port is None
    assert url.path == "/"
    assert url.query == b""
    assert url.fragment == ""

    assert str(url) == "https://www.example.com/"


def test_urlparse_with_invalid_component():
    with pytest.raises(TypeError) as exc:
        httpx.URL(scheme="https", host="www.example.com", incorrect="/")
    assert str(exc.value) == "'incorrect' is an invalid keyword argument for URL()"


def test_urlparse_with_invalid_scheme():
    with pytest.raises(httpx.InvalidURL) as exc:
        httpx.URL(scheme="~", host="www.example.com", path="/")
    assert str(exc.value) == "Invalid URL component 'scheme'"


def test_urlparse_with_invalid_path():
    with pytest.raises(httpx.InvalidURL) as exc:
        httpx.URL(scheme="https", host="www.example.com", path="abc")
    assert str(exc.value) == "For absolute URLs, path must be empty or begin with '/'"

    with pytest.raises(httpx.InvalidURL) as exc:
        httpx.URL(path="//abc")
    assert (
        str(exc.value)
        == "URLs with no authority component cannot have a path starting with '//'"
    )

    with pytest.raises(httpx.InvalidURL) as exc:
        httpx.URL(path=":abc")
    assert (
        str(exc.value)
        == "URLs with no scheme component cannot have a path starting with ':'"
    )


def test_url_with_relative_path():
    # This path would be invalid for an absolute URL, but is valid as a relative URL.
    url = httpx.URL(path="abc")
    assert url.path == "abc"


# Tests for `httpx.URL` python built-in operators.


def test_url_eq_str():
    """
    Ensure that `httpx.URL` supports the equality operator.
    """
    url = httpx.URL("https://example.org:123/path/to/somewhere?abc=123#anchor")
    assert url == "https://example.org:123/path/to/somewhere?abc=123#anchor"
    assert str(url) == url


def test_url_set():
    """
    Ensure that `httpx.URL` instances can be used in sets.
    """
    urls = (
        httpx.URL("http://example.org:123/path/to/somewhere"),
        httpx.URL("http://example.org:123/path/to/somewhere/else"),
    )

    url_set = set(urls)

    assert all(url in urls for url in url_set)


# Tests for TypeErrors when instantiating `httpx.URL`.


def test_url_invalid_type():
    """
    Ensure that invalid types on `httpx.URL()` raise a `TypeError`.
    """

    class ExternalURLClass:  # representing external URL class
        pass

    with pytest.raises(TypeError):
        httpx.URL(ExternalURLClass())  # type: ignore


def test_url_with_invalid_component():
    with pytest.raises(TypeError) as exc:
        httpx.URL(scheme="https", host="www.example.com", incorrect="/")
    assert str(exc.value) == "'incorrect' is an invalid keyword argument for URL()"


# Tests for `URL.join()`.


def test_url_join():
    """
    Some basic URL joining tests.
    """
    url = httpx.URL("https://example.org:123/path/to/somewhere")
    assert url.join("/somewhere-else") == "https://example.org:123/somewhere-else"
    assert (
        url.join("somewhere-else") == "https://example.org:123/path/to/somewhere-else"
    )
    assert (
        url.join("../somewhere-else") == "https://example.org:123/path/somewhere-else"
    )
    assert url.join("../../somewhere-else") == "https://example.org:123/somewhere-else"


def test_relative_url_join():
    url = httpx.URL("/path/to/somewhere")
    assert url.join("/somewhere-else") == "/somewhere-else"
    assert url.join("somewhere-else") == "/path/to/somewhere-else"
    assert url.join("../somewhere-else") == "/path/somewhere-else"
    assert url.join("../../somewhere-else") == "/somewhere-else"


def test_url_join_rfc3986():
    """
    URL joining tests, as-per reference examples in RFC 3986.

    https://tools.ietf.org/html/rfc3986#section-5.4
    """

    url = httpx.URL("http://example.com/b/c/d;p?q")

    assert url.join("g") == "http://example.com/b/c/g"
    assert url.join("./g") == "http://example.com/b/c/g"
    assert url.join("g/") == "http://example.com/b/c/g/"
    assert url.join("/g") == "http://example.com/g"
    assert url.join("//g") == "http://g"
    assert url.join("?y") == "http://example.com/b/c/d;p?y"
    assert url.join("g?y") == "http://example.com/b/c/g?y"
    assert url.join("#s") == "http://example.com/b/c/d;p?q#s"
    assert url.join("g#s") == "http://example.com/b/c/g#s"
    assert url.join("g?y#s") == "http://example.com/b/c/g?y#s"
    assert url.join(";x") == "http://example.com/b/c/;x"
    assert url.join("g;x") == "http://example.com/b/c/g;x"
    assert url.join("g;x?y#s") == "http://example.com/b/c/g;x?y#s"
    assert url.join("") == "http://example.com/b/c/d;p?q"
    assert url.join(".") == "http://example.com/b/c/"
    assert url.join("./") == "http://example.com/b/c/"
    assert url.join("..") == "http://example.com/b/"
    assert url.join("../") == "http://example.com/b/"
    assert url.join("../g") == "http://example.com/b/g"
    assert url.join("../..") == "http://example.com/"
    assert url.join("../../") == "http://example.com/"
    assert url.join("../../g") == "http://example.com/g"

    assert url.join("../../../g") == "http://example.com/g"
    assert url.join("../../../../g") == "http://example.com/g"

    assert url.join("/./g") == "http://example.com/g"
    assert url.join("/../g") == "http://example.com/g"
    assert url.join("g.") == "http://example.com/b/c/g."
    assert url.join(".g") == "http://example.com/b/c/.g"
    assert url.join("g..") == "http://example.com/b/c/g.."
    assert url.join("..g") == "http://example.com/b/c/..g"

    assert url.join("./../g") == "http://example.com/b/g"
    assert url.join("./g/.") == "http://example.com/b/c/g/"
    assert url.join("g/./h") == "http://example.com/b/c/g/h"
    assert url.join("g/../h") == "http://example.com/b/c/h"
    assert url.join("g;x=1/./y") == "http://example.com/b/c/g;x=1/y"
    assert url.join("g;x=1/../y") == "http://example.com/b/c/y"

    assert url.join("g?y/./x") == "http://example.com/b/c/g?y/./x"
    assert url.join("g?y/../x") == "http://example.com/b/c/g?y/../x"
    assert url.join("g#s/./x") == "http://example.com/b/c/g#s/./x"
    assert url.join("g#s/../x") == "http://example.com/b/c/g#s/../x"


def test_resolution_error_1833():
    """
    See https://github.com/encode/httpx/issues/1833
    """
    url = httpx.URL("https://example.com/?[]")
    assert url.join("/") == "https://example.com/"


# Tests for `URL.copy_with()`.


def test_copy_with():
    url = httpx.URL("https://www.example.com/")
    assert str(url) == "https://www.example.com/"

    url = url.copy_with()
    assert str(url) == "https://www.example.com/"

    url = url.copy_with(scheme="http")
    assert str(url) == "http://www.example.com/"

    url = url.copy_with(netloc=b"example.com")
    assert str(url) == "http://example.com/"

    url = url.copy_with(path="/abc")
    assert str(url) == "http://example.com/abc"


def test_url_copywith_authority_subcomponents():
    copy_with_kwargs = {
        "username": "username",
        "password": "password",
        "port": 444,
        "host": "example.net",
    }
    url = httpx.URL("https://example.org")
    new = url.copy_with(**copy_with_kwargs)
    assert str(new) == "https://username:password@example.net:444"


def test_url_copywith_netloc():
    copy_with_kwargs = {
        "netloc": b"example.net:444",
    }
    url = httpx.URL("https://example.org")
    new = url.copy_with(**copy_with_kwargs)
    assert str(new) == "https://example.net:444"


def test_url_copywith_userinfo_subcomponents():
    copy_with_kwargs = {
        "username": "tom@example.org",
        "password": "abc123@ %",
    }
    url = httpx.URL("https://example.org")
    new = url.copy_with(**copy_with_kwargs)
    assert str(new) == "https://tom%40example.org:abc123%40%20%25@example.org"
    assert new.username == "tom@example.org"
    assert new.password == "abc123@ %"
    assert new.userinfo == b"tom%40example.org:abc123%40%20%25"


def test_url_copywith_invalid_component():
    url = httpx.URL("https://example.org")
    with pytest.raises(TypeError):
        url.copy_with(pathh="/incorrect-spelling")
    with pytest.raises(TypeError):
        url.copy_with(userinfo="should be bytes")


def test_url_copywith_urlencoded_path():
    url = httpx.URL("https://example.org")
    url = url.copy_with(path="/path to somewhere")
    assert url.path == "/path to somewhere"
    assert url.query == b""
    assert url.raw_path == b"/path%20to%20somewhere"


def test_url_copywith_query():
    url = httpx.URL("https://example.org")
    url = url.copy_with(query=b"a=123")
    assert url.path == "/"
    assert url.query == b"a=123"
    assert url.raw_path == b"/?a=123"


def test_url_copywith_raw_path():
    url = httpx.URL("https://example.org")
    url = url.copy_with(raw_path=b"/some/path")
    assert url.path == "/some/path"
    assert url.query == b""
    assert url.raw_path == b"/some/path"

    url = httpx.URL("https://example.org")
    url = url.copy_with(raw_path=b"/some/path?")
    assert url.path == "/some/path"
    assert url.query == b""
    assert url.raw_path == b"/some/path?"

    url = httpx.URL("https://example.org")
    url = url.copy_with(raw_path=b"/some/path?a=123")
    assert url.path == "/some/path"
    assert url.query == b"a=123"
    assert url.raw_path == b"/some/path?a=123"


def test_url_copywith_security():
    """
    Prevent unexpected changes on URL after calling copy_with (CVE-2021-41945)
    """
    with pytest.raises(httpx.InvalidURL):
        httpx.URL("https://u:p@[invalid!]//evilHost/path?t=w#tw")

    url = httpx.URL("https://example.com/path?t=w#tw")
    bad = "https://xxxx:xxxx@xxxxxxx/xxxxx/xxx?x=x#xxxxx"
    with pytest.raises(httpx.InvalidURL):
        url.copy_with(scheme=bad)


# Tests for copy-modifying-parameters methods.
#
# `URL.copy_set_param()`
# `URL.copy_add_param()`
# `URL.copy_remove_param()`
# `URL.copy_merge_params()`


def test_url_set_param_manipulation():
    """
    Some basic URL query parameter manipulation.
    """
    url = httpx.URL("https://example.org:123/?a=123")
    assert url.copy_set_param("a", "456") == "https://example.org:123/?a=456"


def test_url_add_param_manipulation():
    """
    Some basic URL query parameter manipulation.
    """
    url = httpx.URL("https://example.org:123/?a=123")
    assert url.copy_add_param("a", "456") == "https://example.org:123/?a=123&a=456"


def test_url_remove_param_manipulation():
    """
    Some basic URL query parameter manipulation.
    """
    url = httpx.URL("https://example.org:123/?a=123")
    assert url.copy_remove_param("a") == "https://example.org:123/"


def test_url_merge_params_manipulation():
    """
    Some basic URL query parameter manipulation.
    """
    url = httpx.URL("https://example.org:123/?a=123")
    assert url.copy_merge_params({"b": "456"}) == "https://example.org:123/?a=123&b=456"


# Tests for IDNA hostname support.


@pytest.mark.parametrize(
    "given,idna,host,raw_host,scheme,port",
    [
        (
            "http://中国.icom.museum:80/",
            "http://xn--fiqs8s.icom.museum:80/",
            "中国.icom.museum",
            b"xn--fiqs8s.icom.museum",
            "http",
            None,
        ),
        (
            "http://Königsgäßchen.de",
            "http://xn--knigsgchen-b4a3dun.de",
            "königsgäßchen.de",
            b"xn--knigsgchen-b4a3dun.de",
            "http",
            None,
        ),
        (
            "https://faß.de",
            "https://xn--fa-hia.de",
            "faß.de",
            b"xn--fa-hia.de",
            "https",
            None,
        ),
        (
            "https://βόλος.com:443",
            "https://xn--nxasmm1c.com:443",
            "βόλος.com",
            b"xn--nxasmm1c.com",
            "https",
            None,
        ),
        (
            "http://ශ්‍රී.com:444",
            "http://xn--10cl1a0b660p.com:444",
            "ශ්‍රී.com",
            b"xn--10cl1a0b660p.com",
            "http",
            444,
        ),
        (
            "https://نامه‌ای.com:4433",
            "https://xn--mgba3gch31f060k.com:4433",
            "نامه‌ای.com",
            b"xn--mgba3gch31f060k.com",
            "https",
            4433,
        ),
    ],
    ids=[
        "http_with_port",
        "unicode_tr46_compat",
        "https_without_port",
        "https_with_port",
        "http_with_custom_port",
        "https_with_custom_port",
    ],
)
def test_idna_url(given, idna, host, raw_host, scheme, port):
    url = httpx.URL(given)
    assert url == httpx.URL(idna)
    assert url.host == host
    assert url.raw_host == raw_host
    assert url.scheme == scheme
    assert url.port == port


def test_url_unescaped_idna_host():
    url = httpx.URL("https://中国.icom.museum/")
    assert url.raw_host == b"xn--fiqs8s.icom.museum"


def test_url_escaped_idna_host():
    url = httpx.URL("https://xn--fiqs8s.icom.museum/")
    assert url.raw_host == b"xn--fiqs8s.icom.museum"


def test_url_invalid_idna_host():
    with pytest.raises(httpx.InvalidURL) as exc:
        httpx.URL("https://☃.com/")
    assert str(exc.value) == "Invalid IDNA hostname: '☃.com'"


# Tests for IPv4 hostname support.


def test_url_valid_ipv4():
    url = httpx.URL("https://1.2.3.4/")
    assert url.host == "1.2.3.4"


def test_url_invalid_ipv4():
    with pytest.raises(httpx.InvalidURL) as exc:
        httpx.URL("https://999.999.999.999/")
    assert str(exc.value) == "Invalid IPv4 address: '999.999.999.999'"


# Tests for IPv6 hostname support.


def test_ipv6_url():
    url = httpx.URL("http://[::ffff:192.168.0.1]:5678/")

    assert url.host == "::ffff:192.168.0.1"
    assert url.netloc == b"[::ffff:192.168.0.1]:5678"


def test_url_valid_ipv6():
    url = httpx.URL("https://[2001:db8::ff00:42:8329]/")
    assert url.host == "2001:db8::ff00:42:8329"


def test_url_invalid_ipv6():
    with pytest.raises(httpx.InvalidURL) as exc:
        httpx.URL("https://[2001]/")
    assert str(exc.value) == "Invalid IPv6 address: '[2001]'"


@pytest.mark.parametrize("host", ["[::ffff:192.168.0.1]", "::ffff:192.168.0.1"])
def test_ipv6_url_from_raw_url(host):
    url = httpx.URL(scheme="https", host=host, port=443, path="/")

    assert url.host == "::ffff:192.168.0.1"
    assert url.netloc == b"[::ffff:192.168.0.1]"
    assert str(url) == "https://[::ffff:192.168.0.1]/"


@pytest.mark.parametrize(
    "url_str",
    [
        "http://127.0.0.1:1234",
        "http://example.com:1234",
        "http://[::ffff:127.0.0.1]:1234",
    ],
)
@pytest.mark.parametrize("new_host", ["[::ffff:192.168.0.1]", "::ffff:192.168.0.1"])
def test_ipv6_url_copy_with_host(url_str, new_host):
    url = httpx.URL(url_str).copy_with(host=new_host)

    assert url.host == "::ffff:192.168.0.1"
    assert url.netloc == b"[::ffff:192.168.0.1]:1234"
    assert str(url) == "http://[::ffff:192.168.0.1]:1234"


# Test for deprecated API


def test_url_raw_compatibility():
    """
    Test case for the (to-be-deprecated) `url.raw` accessor.
    """
    url = httpx.URL("https://www.example.com/path")
    scheme, host, port, raw_path = url.raw

    assert scheme == b"https"
    assert host == b"www.example.com"
    assert port is None
    assert raw_path == b"/path"


# WHATWG-style table-driven tests for the component encoding pipeline.
#
# Each component is encoded against its own safe-character set *after* any
# existing percent-encoded sequences have been validated. Existing escapes
# must be preserved as-is, raw reserved characters must not leak across
# component boundaries, and malformed escapes raise `InvalidURL`.


@pytest.mark.parametrize(
    "given,expected",
    [
        # Already-escaped components round-trip unchanged.
        ("https://example.com/a%20b", "https://example.com/a%20b"),
        ("https://example.com/?a=b%20c", "https://example.com/?a=b%20c"),
        ("https://example.com/#frag%20ment", "https://example.com/#frag%20ment"),
        # Hex digits are accepted in either case, and stay bytewise identical.
        ("https://example.com/%2f%2F", "https://example.com/%2f%2F"),
        # An existing escape alongside a raw character that needs encoding:
        # the escape is preserved and only the raw character is encoded.
        ("https://example.com/a%20b c", "https://example.com/a%20b%20c"),
        ("https://example.com/?a=%2Fb/c", "https://example.com/?a=%2Fb%2Fc"),
        ("https://example.com/#a%20b c", "https://example.com/#a%20b%20c"),
        # Multiple raw characters and escapes mixed together.
        (
            "https://example.com/a%20b c?x=1%262&y=3 4",
            "https://example.com/a%20b%20c?x=1%262&y=3%204",
        ),
        # Unicode characters are UTF-8 percent-encoded, existing escapes kept.
        (
            "https://example.com/%E2%9C%93/ü",
            "https://example.com/%E2%9C%93/%C3%BC",
        ),
        (
            "https://example.com/?q=%E2%9C%93&r=ü",
            "https://example.com/?q=%E2%9C%93&r=%C3%BC",
        ),
        (
            "https://example.com/#%E2%9C%93 ü",
            "https://example.com/#%E2%9C%93%20%C3%BC",
        ),
        # Unicode host combined with escaped and raw characters elsewhere.
        (
            "https://müller.de/a%20b/?q=c d#e%20f",
            "https://xn--mller-kva.de/a%20b/?q=c%20d#e%20f",
        ),
        # A literal reserved character stays raw where the component allows it.
        ("https://example.com/a/b;c=1", "https://example.com/a/b;c=1"),
        ("https://example.com/?a=1&b=2;3", "https://example.com/?a=1&b=2;3"),
        ("https://example.com/#a/b?c#d", "https://example.com/#a/b?c#d"),
        # The query deliberately does not share the path safe set: "/" is
        # encoded as "%2F" in the query, but kept raw in the path.
        (
            "https://example.com/a/b?c=d/e",
            "https://example.com/a/b?c=d%2Fe",
        ),
        # userinfo: existing escapes preserved, "@" raw is encoded because it
        # terminates the userinfo component.
        (
            "https://user%40name:p%40ss@example.com/",
            "https://user%40name:p%40ss@example.com/",
        ),
        (
            "https://user@name:p@ss@example.com/",
            "https://user%40name:p%40ss@example.com/",
        ),
        (
            "https://u%20ser:p%20ss@example.com/",
            "https://u%20ser:p%20ss@example.com/",
        ),
    ],
    ids=[
        "escaped_path",
        "escaped_query",
        "escaped_fragment",
        "mixed_case_hex",
        "mixed_path",
        "mixed_query",
        "mixed_fragment",
        "mixed_several",
        "unicode_path",
        "unicode_query",
        "unicode_fragment",
        "unicode_host_mixed",
        "raw_reserved_path",
        "raw_reserved_query",
        "raw_reserved_fragment",
        "query_slash_encoded",
        "escaped_userinfo",
        "raw_at_in_userinfo",
        "spaces_in_userinfo",
    ],
)
def test_component_encoding_table(given, expected):
    url = httpx.URL(given)
    assert str(url) == expected
    # Encoding is idempotent: parsing the serialized form changes nothing.
    assert str(httpx.URL(str(url))) == expected
    assert url.copy_with() == expected


def test_raw_path_query_and_fragment_conventions():
    """
    `raw_path` exposes path + query as raw bytes, `query` excludes the
    leading "?", and `fragment` is URL-decoded. These public conventions
    hold for inputs mixing escapes with raw characters.
    """
    url = httpx.URL("https://müller.de/a%20b/?c=d%20e&f=/g#h%20i?j")
    assert url.raw_host == b"xn--mller-kva.de"
    assert url.raw_path == b"/a%20b/?c=d%20e&f=%2Fg"
    assert url.query == b"c=d%20e&f=%2Fg"
    assert url.path == "/a b/"
    assert url.fragment == "h i?j"
    assert str(url) == "https://xn--mller-kva.de/a%20b/?c=d%20e&f=%2Fg#h%20i?j"


@pytest.mark.parametrize(
    "given",
    [
        # Malformed percent-escape in every component must be rejected.
        "https://example.com/a%zz",
        "https://example.com/a%",
        "https://example.com/a%2",
        "https://example.com/a%2g",
        "https://example.com/?q=100%ok",
        "https://example.com/?q=%",
        "https://example.com/#frag%zz",
        "https://user%zz:pass@example.com/",
        "https://user:pass%2@example.com/",
        "https://ex%zzample.com/",
        # Trailing "%" at the end of a component.
        "https://example.com/path%",
        "https://example.com/?q=%",
        "https://example.com/#%",
    ],
    ids=[
        "bad_hex_path",
        "lone_percent_path",
        "truncated_escape_path",
        "non_hex_escape_path",
        "bad_hex_query",
        "lone_percent_query",
        "bad_hex_fragment",
        "bad_hex_username",
        "truncated_escape_password",
        "bad_hex_host",
        "trailing_percent_path",
        "trailing_percent_query",
        "trailing_percent_fragment",
    ],
)
def test_invalid_percent_escapes_table(given):
    with pytest.raises(httpx.InvalidURL) as exc:
        httpx.URL(given)
    assert str(exc.value) == "Invalid percent-escape sequence in URL"


@pytest.mark.parametrize(
    "component,value",
    [
        ("userinfo", b"user%zz"),
        ("path", "/a%zz"),
        ("query", b"a=%zz"),
        ("raw_path", b"/a%zz?b=%2"),
        ("fragment", "frag%zz"),
        ("host", "ex%zzample.com"),
    ],
)
def test_invalid_percent_escapes_in_components(component, value):
    with pytest.raises(httpx.InvalidURL, match="Invalid percent-escape sequence"):
        httpx.URL("https://example.org/", **{component: value})


@pytest.mark.parametrize(
    "given,control",
    [
        ("https://example.com/a\tb", "\t"),
        ("https://example.com/?q=a\rb", "\r"),
        ("https://example.com/#a\nb", "\n"),
        ("https://example.com/a\x7fb", "\x7f"),
        ("https://user\x00name@example.com/", "\x00"),
    ],
)
def test_control_characters_rejected_table(given, control):
    # A bare ASCII control character is never percent-encoded for the caller.
    with pytest.raises(httpx.InvalidURL):
        httpx.URL(given)


def test_control_characters_in_components_rejected():
    with pytest.raises(httpx.InvalidURL):
        httpx.URL("https://example.org", path="/a\tb")
    with pytest.raises(httpx.InvalidURL):
        httpx.URL("https://example.org", query=b"a=\x00")
    with pytest.raises(httpx.InvalidURL):
        httpx.URL("https://example.org", fragment="a\nb")


@pytest.mark.parametrize(
    "given,expected,raw_path",
    [
        # Empty / absent components remain distinguishable.
        ("https://example.com", "https://example.com", b"/"),
        ("https://example.com/", "https://example.com/", b"/"),
        ("https://example.com/path", "https://example.com/path", b"/path"),
        ("https://example.com/path?", "https://example.com/path?", b"/path?"),
        ("https://example.com/path#", "https://example.com/path#", b"/path"),
        (
            "https://example.com/path?#",
            "https://example.com/path?#",
            b"/path?",
        ),
        (
            "https://example.com/a%20b?#frag",
            "https://example.com/a%20b?#frag",
            b"/a%20b?",
        ),
        # Relative references with empty or absent components.
        ("", "", b"/"),
        ("/", "/", b"/"),
        ("?query", "?query", b"/?query"),
        ("#fragment", "#fragment", b"/"),
    ],
    ids=[
        "no_path_query_fragment",
        "root_path",
        "path_only",
        "empty_query",
        "empty_fragment",
        "empty_query_and_fragment",
        "escaped_path_empty_query",
        "empty_string",
        "root_relative",
        "query_relative",
        "fragment_relative",
    ],
)
def test_empty_components_table(given, expected, raw_path):
    url = httpx.URL(given)
    assert str(url) == expected
    assert url.raw_path == raw_path
    assert str(url.copy_with()) == expected


@pytest.mark.parametrize(
    "base,ref,expected",
    [
        # Escapes and raw characters survive join + re-parse unchanged.
        (
            "https://example.com/base/path",
            "a%20b c",
            "https://example.com/base/a%20b%20c",
        ),
        (
            "https://example.com/base/?q=1%202",
            "/new?x=a%2Fb/c",
            "https://example.com/new?x=a%2Fb%2Fc",
        ),
        (
            "https://müller.de/base/%C3%A4?x=1",
            "../%E2%9C%93?y=2 3",
            "https://xn--mller-kva.de/%E2%9C%93?y=2%203",
        ),
        (
            "https://example.com/a/b/c",
            "g?y#s%20t",
            "https://example.com/a/b/g?y#s%20t",
        ),
        # An empty reference resolves to the base, byte for byte.
        (
            "https://example.com/a%20b?c=d%2Fe#f%20g",
            "",
            "https://example.com/a%20b?c=d%2Fe#f%20g",
        ),
        # Relative URL bases keep their relative resolution.
        ("/path/to/somewhere", "../new%20place", "/path/new%20place"),
        # Joining then reparsing must be equivalent to the joined result.
        (
            "https://example.com/pa%20th?q=a%20b",
            "/new%20path?x=%2Fy",
            "https://example.com/new%20path?x=%2Fy",
        ),
    ],
    ids=[
        "relative_mixed_path",
        "absolute_mixed_query",
        "unicode_base_dot_segments",
        "query_and_fragment_ref",
        "empty_reference",
        "relative_base",
        "encoded_target",
    ],
)
def test_join_encoding_table(base, ref, expected):
    url = httpx.URL(base).join(ref)
    assert str(url) == expected
    assert url == expected
    # The joined URL is itself stable under re-parse and join with "".
    assert str(httpx.URL(str(url))) == expected
    assert url.join("") == expected


@pytest.mark.parametrize(
    "given,changes",
    [
        ("https://example.com/a%20b?c=d%2Fe#f%20g", {}),
        ("https://user%40name:p%40ss@example.com/", {}),
        ("https://xn--mller-kva.de/%C3%A4/?q=%C3%BC#%E2%9C%93", {}),
        (
            "https://example.com/a%20b?c=d%20e#f%20g",
            {"path": "/x%20y"},
        ),
        (
            "https://example.com/a?b=c#d",
            {"query": b"e=%2Ff%20g"},
        ),
        (
            "https://example.com/a#b",
            {"fragment": "h%20i/j?k#l"},
        ),
        (
            "https://example.com/",
            {"username": "user@name", "password": "p ss%word"},
        ),
        (
            "https://example.com/",
            {"raw_path": b"/x%20y?z=%2F1 2"},
        ),
    ],
    ids=[
        "no_changes",
        "no_changes_userinfo",
        "no_changes_unicode",
        "replace_path",
        "replace_query",
        "replace_fragment",
        "replace_userinfo",
        "replace_raw_path",
    ],
)
def test_copy_with_idempotency_table(given, changes):
    url = httpx.URL(given, **changes)

    # `copy_with` with no arguments must return an equivalent URL.
    copied = url.copy_with()
    assert str(copied) == str(url)
    assert copied == url
    assert copied.raw_path == url.raw_path
    assert copied.query == url.query
    assert copied.fragment == url.fragment
    assert copied.userinfo == url.userinfo

    # And the serialized form must survive a fresh parse.
    assert str(httpx.URL(str(url))) == str(url)


def test_copy_with_preserves_mixed_escapes():
    """
    Regression: a component containing both an existing escape and a raw
    reserved character used to be fully re-encoded ("%20" -> "%2520"),
    making `copy_with`/`join` produce a non-equivalent URL.
    """
    url = httpx.URL("https://example.com/a%20b c?x=1%2F2/y#z%20z z")
    assert str(url) == "https://example.com/a%20b%20c?x=1%2F2%2Fy#z%20z%20z"
    assert url.copy_with() == url
    assert url.copy_with(scheme="https") == url
    assert httpx.URL(str(url)) == url
    assert url.copy_with(path=url.raw_path.split(b"?")[0].decode()) == (
        "https://example.com/a%20b%20c?x=1%2F2%2Fy#z%20z%20z"
    )


def test_decoded_inputs_encode_literal_percent():
    """
    Values supplied through the decoded-value kwargs (username/password and
    params) are plain text: a literal "%" becomes "%25", and a fully valid
    value without other characters needing encoding is left as given.
    """
    url = httpx.URL("https://example.org").copy_with(
        username="tom@example.org", password="abc123@ %"
    )
    assert str(url) == "https://tom%40example.org:abc123%40%20%25@example.org"
    assert url.password == "abc123@ %"

    assert str(httpx.URL("http://webservice", params={"u": "with%20spaces"})) == (
        "http://webservice?u=with%20spaces"
    )
    assert (
        str(
            httpx.URL("http://webservice", params={"u": "http://example.com?q=foo%2Fa"})
        )
        == "http://webservice?u=http%3A%2F%2Fexample.com%3Fq%3Dfoo%252Fa"
    )


def test_userinfo_delimiters_are_encoded():
    """
    A ":" or "@" inside a decoded username/password must be percent-encoded,
    so the assembled userinfo keeps a single unambiguous user/password split
    and round-trips through `copy_with`/re-parse.
    """
    url = httpx.URL("https://example.org").copy_with(username="a:b", password="c:d@e")
    assert str(url) == "https://a%3Ab:c%3Ad%40e@example.org"
    assert url.username == "a:b"
    assert url.password == "c:d@e"
    assert url.userinfo == b"a%3Ab:c%3Ad%40e"
    assert httpx.URL(str(url)).username == "a:b"
    assert httpx.URL(str(url)).password == "c:d@e"
