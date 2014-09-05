import os
import sys

from twisted.names import client, dns, server, cache

from simpledns.dnsproxy import DispatchResolver

def test_config_with_correct_server_config_of_only_root_domain_and_only_address(tmpdir):
    p = tmpdir.mkdir('conf').join('dispatch.conf')
    p.write('server=/com/127.0.0.1')

    d = DispatchResolver(str(p.realpath()), servers=[("127.0.0.2", 53)])
    queries = [dns.Query(b'com', dns.A, dns.IN)]
    addr = d.pickServer(queries)
    assert addr == ("127.0.0.1", 53)


def test_config_with_correct_server_config_of_normal_domain_and_only_address(tmpdir):
    p = tmpdir.mkdir('conf').join('dispatch.conf')
    p.write('server=/example.com/127.0.0.1')

    d = DispatchResolver(str(p.realpath()), servers=[("127.0.0.2", 53)])
    queries = [dns.Query(b'example.com', dns.A, dns.IN)]
    addr = d.pickServer(queries)
    assert addr == ("127.0.0.1", 53)


def test_config_with_correct_server_config_of_only_root_domain_and_address_with_port(tmpdir):
    p = tmpdir.mkdir('conf').join('dispatch.conf')
    p.write('server=/com/127.0.0.1#5353')

    d = DispatchResolver(str(p.realpath()), servers=[("127.0.0.2", 53)])
    queries = [dns.Query(b'com', dns.A, dns.IN)]
    addr = d.pickServer(queries)
    assert addr == ("127.0.0.1", 5353)


def test_config_with_correct_server_config_of_normal_domain_and_address_with_port(tmpdir):
    p = tmpdir.mkdir('conf').join('dispatch.conf')
    p.write('server=/example.com/127.0.0.1#5353')

    d = DispatchResolver(str(p.realpath()), servers=[("127.0.0.2", 53)])
    queries = [dns.Query(b'example.com', dns.A, dns.IN)]
    addr = d.pickServer(queries)
    assert addr == ("127.0.0.1", 5353)


def test_config_with_correct_server_config_pick_server_1(tmpdir):
    p = tmpdir.mkdir('conf').join('dispatch.conf')
    p.write('server=/com/127.0.0.1')

    d = DispatchResolver(str(p.realpath()), servers=[("127.0.0.2", 53)])
    queries = [dns.Query(b'example.com', dns.A, dns.IN)]
    addr = d.pickServer(queries)
    assert addr == ("127.0.0.1", 53)


def test_config_with_correct_server_config_pick_server_2(tmpdir):
    p = tmpdir.mkdir('conf').join('dispatch.conf')
    p.write('server=/com/127.0.0.1')

    d = DispatchResolver(str(p.realpath()), servers=[("127.0.0.2", 53)])
    queries = [dns.Query(b'www.example.com', dns.A, dns.IN)]
    addr = d.pickServer(queries)
    assert addr == ("127.0.0.1", 53)


def test_config_with_correct_server_config_pick_server_3(tmpdir):
    p = tmpdir.mkdir('conf').join('dispatch.conf')
    p.write('server=/com/127.0.0.1')

    d = DispatchResolver(str(p.realpath()), servers=[("127.0.0.2", 53)])
    queries = [dns.Query(b'www.example.example.com', dns.A, dns.IN)]
    addr = d.pickServer(queries)
    assert addr == ("127.0.0.1", 53)


def test_config_with_incorrect_server_domain_config(tmpdir):
    p = tmpdir.mkdir('conf').join('dispatch.conf')
    p.write('server=//127.0.0.1')

    d = DispatchResolver(str(p.realpath()), servers=[("127.0.0.2", 53)])
    queries = [dns.Query(b'example.com', dns.A, dns.IN)]
    addr = d.pickServer(queries)
    # fallback to the default upstream server
    assert addr == ("127.0.0.2", 53)


def test_config_with_incorrect_server_address_config(tmpdir):
    p = tmpdir.mkdir('conf').join('dispatch.conf')
    p.write('server=/example.com/127.0.0.')

    d = DispatchResolver(str(p.realpath()), servers=[("127.0.0.2", 53)])
    queries = [dns.Query(b'example.com', dns.A, dns.IN)]
    addr = d.pickServer(queries)
    # fallback to the default upstream server
    assert addr == ("127.0.0.2", 53)


def test_config_with_correct_address_config_ipv4_query_1(tmpdir):
    p = tmpdir.mkdir('conf').join('dispatch.conf')
    p.write('address=/example.com/1.1.1.1')

    d = DispatchResolver(str(p.realpath()), servers=[("127.0.0.2", 53)])
    r = d._matchAddress(b'example.com', d._aRecords)
    assert r[0].payload.dottedQuad() == '1.1.1.1'


def test_config_with_correct_address_config_ipv4_query_2(tmpdir):
    p = tmpdir.mkdir('conf').join('dispatch.conf')
    p.write('address=/example.com/1.1.1.1')

    d = DispatchResolver(str(p.realpath()), servers=[("127.0.0.2", 53)])
    r = d._matchAddress(b'www.example.com', d._aRecords)
    assert r[0].payload.dottedQuad() == '1.1.1.1'


def test_config_with_correct_address_config_ipv4_query_3(tmpdir):
    p = tmpdir.mkdir('conf').join('dispatch.conf')
    p.write('address=/example.com/1.1.1.1')

    d = DispatchResolver(str(p.realpath()), servers=[("127.0.0.2", 53)])
    r = d._matchAddress(b'something.something.example.com', d._aRecords)
    assert r[0].payload.dottedQuad() == '1.1.1.1'


def test_config_with_incorrect_address_config_ipv4(tmpdir):
    p = tmpdir.mkdir('conf').join('dispatch.conf')
    p.write('address=/example.com/1.1.1.')

    d = DispatchResolver(str(p.realpath()), servers=[("127.0.0.2", 53)])
    r = d._matchAddress(b'something.something.example.com', d._aRecords)
    assert r is None


def test_config_with_correct_address_config_ipv6_query_1(tmpdir):
    p = tmpdir.mkdir('conf').join('dispatch.conf')
    p.write('address=/example.com/::1')

    d = DispatchResolver(str(p.realpath()), servers=[("127.0.0.2", 53)])
    r = d._matchAddress(b'example.com', d._aaaaRecords)
    assert r[0].payload._address == '::1'


def test_config_with_correct_address_config_ipv6_query_2(tmpdir):
    p = tmpdir.mkdir('conf').join('dispatch.conf')
    p.write('address=/example.com/::1')

    d = DispatchResolver(str(p.realpath()), servers=[("127.0.0.2", 53)])
    r = d._matchAddress(b'www.example.com', d._aaaaRecords)
    assert r[0].payload._address == '::1'


def test_config_with_correct_address_config_ipv6_query_3(tmpdir):
    p = tmpdir.mkdir('conf').join('dispatch.conf')
    p.write('address=/example.com/::1')

    d = DispatchResolver(str(p.realpath()), servers=[("127.0.0.2", 53)])
    r = d._matchAddress(b'something.something.example.com', d._aaaaRecords)
    assert r[0].payload._address == '::1'


def test_config_with_incorrect_address_config_ipv6(tmpdir):
    p = tmpdir.mkdir('conf').join('dispatch.conf')
    p.write('address=/example.com/::1???')

    d = DispatchResolver(str(p.realpath()), servers=[("127.0.0.2", 53)])
    r = d._matchAddress(b'example.com', d._aaaaRecords)
    assert r is None
