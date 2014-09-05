from twisted.names import dns
from twisted.internet import task

from simpledns.dnsproxy import ExtendCacheResolver

def test_min_ttl():
    r = ([dns.RRHeader(b"example.com", dns.A, dns.IN, 60,
                       dns.Record_A("127.0.0.1", 60))],
         [dns.RRHeader(b"example.com", dns.A, dns.IN, 50,
                       dns.Record_A("127.0.0.1", 50))],
         [dns.RRHeader(b"example.com", dns.A, dns.IN, 40,
                       dns.Record_A("127.0.0.1", 40))])
    
    clock = task.Clock()
    query = dns.Query(name=b"example.com", type=dns.A, cls=dns.IN)
    
    e = ExtendCacheResolver(reactor=clock, minTTL=100)
    e.cacheResult(query, r)
    
    clock.advance(70)
    # minTTL is 100 seconds so it won't expire
    assert query in e.cache
    
    # Now it is expired
    clock.advance(30.1)
    assert query not in e.cache
    
def test_max_ttl():
    r = ([dns.RRHeader(b"example.com", dns.A, dns.IN, 60,
                       dns.Record_A("127.0.0.1", 60))],
         [dns.RRHeader(b"example.com", dns.A, dns.IN, 50,
                       dns.Record_A("127.0.0.1", 50))],
         [dns.RRHeader(b"example.com", dns.A, dns.IN, 40,
                       dns.Record_A("127.0.0.1", 40))])
    
    clock = task.Clock()
    query = dns.Query(name=b"example.com", type=dns.A, cls=dns.IN)
    
    e = ExtendCacheResolver(reactor=clock, maxTTL=20)
    e.cacheResult(query, r)
    
    clock.advance(19)
    assert query in e.cache
    
    clock.advance(1.1)
    # Already expired
    assert query not in e.cache
    
def test_cache_size():
    r1 = ([dns.RRHeader(b"example1.com", dns.A, dns.IN, 60,
                       dns.Record_A("127.0.0.1", 60))],
         [dns.RRHeader(b"example1.com", dns.A, dns.IN, 50,
                       dns.Record_A("127.0.0.1", 50))],
         [dns.RRHeader(b"example1.com", dns.A, dns.IN, 40,
                       dns.Record_A("127.0.0.1", 40))])
    
    r2 = ([dns.RRHeader(b"example2.com", dns.A, dns.IN, 60,
                       dns.Record_A("127.0.0.2", 60))],
         [dns.RRHeader(b"example2.com", dns.A, dns.IN, 50,
                       dns.Record_A("127.0.0.2", 50))],
         [dns.RRHeader(b"example2.com", dns.A, dns.IN, 40,
                       dns.Record_A("127.0.0.2", 40))])
                       
    r3 = ([dns.RRHeader(b"example3.com", dns.A, dns.IN, 60,
                       dns.Record_A("127.0.0.3", 60))],
         [dns.RRHeader(b"example3.com", dns.A, dns.IN, 50,
                       dns.Record_A("127.0.0.3", 50))],
         [dns.RRHeader(b"example3.com", dns.A, dns.IN, 40,
                       dns.Record_A("127.0.0.3", 40))])
                       
    query1 = dns.Query(name=b"example1.com", type=dns.A, cls=dns.IN)
    query2 = dns.Query(name=b"example2.com", type=dns.A, cls=dns.IN)
    query3 = dns.Query(name=b"example3.com", type=dns.A, cls=dns.IN)
    
    clock = task.Clock()
    e = ExtendCacheResolver(reactor=clock, cacheSize=2)
    
    e.cacheResult(query1, r1)
    assert query1 in e.cache
    
    e.cacheResult(query2, r2)
    assert query2 in e.cache
    
    e.cacheResult(query3, r3)
    assert query3 in e.cache
    
    # query1 is out due to cache size limit
    assert query1 not in e.cache

    