from simpledns.util import is_ipv4_address, is_ipv6_address, is_address_validate

def test_is_ipv4_address_with_correct_address():
    addr = "1.1.1.1"
    r = is_ipv4_address(addr)
    assert r == True

def test_is_ipv4_address_with_incorrect_address():
    addr = "1.1.1."
    r = is_ipv4_address(addr)
    assert r == False

def test_is_ipv6_address_with_correct_address():
    addr = "fe80::1"
    r = is_ipv6_address(addr)
    assert r == True

def test_is_ipv6_address_with_incorrect_address():
    addr = "fdss??"
    r = is_ipv6_address(addr)
    assert r == False

def test_is_address_validate_with_correct_ipv4_address():
    addr = "1.1.1.1"
    r = is_address_validate(addr)
    assert r == True

def test_is_address_validate_with_incorrect_ipv4_address():
    addr = "1.1.1."
    r = is_address_validate(addr)
    assert r == False

def test_is_address_validate_with_correct_ipv6_address():
    addr = "fe80::1"
    r = is_address_validate(addr)
    assert r == True

def test_is_address_validate_with_incorrect_ipv6_address():
    addr = "sdff>?>"
    r = is_address_validate(addr)
    assert r == False
