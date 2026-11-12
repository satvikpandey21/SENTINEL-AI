import pytest

from sentinel_security.middleware import client_ip


def scope(peer="198.51.100.20", headers=()):
    return {"client": (peer, 1234) if peer else None, "headers": list(headers)}


def test_direct_client_cannot_spoof_forwarding_headers():
    assert client_ip(scope(headers=[(b"x-forwarded-for", b"1.2.3.4")]), ()) == "198.51.100.20"


def test_walks_trusted_proxies_from_right_and_ignores_spoofed_leftmost():
    request = scope("10.0.0.2", [(b"x-forwarded-for", b"1.2.3.4, 198.51.100.9, 10.0.0.3")])
    assert client_ip(request, ("10.0.0.0/8",)) == "198.51.100.9"


@pytest.mark.parametrize(
    "headers",
    [
        [(b"x-forwarded-for", b"invalid")],
        [(b"x-forwarded-for", b"1.1.1.1"), (b"x-forwarded-for", b"2.2.2.2")],
        [(b"x-forwarded-for", b"a" * 2049)],
        [(b"x-forwarded-for", b"\xff")],
        [],
    ],
)
def test_ambiguous_or_invalid_forwarding_falls_back_to_peer(headers):
    assert client_ip(scope("10.0.0.2", headers), ("10.0.0.0/8",)) == "10.0.0.2"


def test_ipv6_and_unknown_peer():
    assert (
        client_ip(scope("::1", [(b"x-forwarded-for", b"2001:db8::42")]), ("::1/128",))
        == "2001:db8::42"
    )
    assert client_ip(scope(None), ()) == "unknown"
    assert client_ip(scope("invalid"), ()) == "unknown"
