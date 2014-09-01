#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2014 skyline75489
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import sys
import socket
import argparse
import time

from collections import OrderedDict

from twisted.internet import reactor, defer, error
from twisted.names import client, dns, server, cache, hosts
from twisted.internet.abstract import isIPAddress
from twisted.python import log, failure

info = sys.version_info
if not (info[0] == 2 and info[1] >= 7):
    print 'Python 2.7 required'
    sys.exit(1)


GFW_LIST = set(["74.125.127.102", "74.125.155.102", "74.125.39.102",
                "74.125.39.113", "209.85.229.138", "128.121.126.139",
                "159.106.121.75", "169.132.13.103", "192.67.198.6",
                "202.106.1.2", "202.181.7.85", "203.161.230.171",
                "203.98.7.65", "207.12.88.98", "208.56.31.43",
                "209.145.54.50", "209.220.30.174", "209.36.73.33",
                "211.94.66.147", "213.169.251.35", "216.221.188.182",
                "216.234.179.13", "243.185.187.39", "37.61.54.158",
                "4.36.66.178", "46.82.174.68", "59.24.3.173", "64.33.88.161",
                "64.33.99.47", "64.66.163.251", "65.104.202.252",
                "65.160.219.113", "66.45.252.237", "72.14.205.104",
                "72.14.205.99", "78.16.49.15", "8.7.198.45", "93.46.8.89"])


class DispatchResolver(client.Resolver):

    def __init__(self, dispatch_conf, servers=None, timeout=None, minTTL=60 * 60, query_timeout=1, verbose=0):
        self.serverMap = {}
        self.addressMap = {}
        self.minTTL = minTTL
        self.query_timeout = query_timeout
        self.verbose = verbose
        self.parseDispatchConfig(dispatch_conf)
        client.Resolver.__init__(self, servers=servers, timeout=timeout)
        # Retry three times for each query
        self.timeout = (self.query_timeout, self.query_timeout +
                        5, self.query_timeout + 15, self.query_timeout + 25)

    def is_address_validate(self, addr):
        try:
            socket.inet_aton(addr)
            return True
        except (socket.error, ValueError):
            try:
                socket.inet_pton(socket.AF_INET6, addr)
                return True
            except (socket.error, ValueError):
                return False

    def _connectedProtocol(self):
        """
        Return a new L{DNSDatagramProtocol} bound to a randomly selected port
        number.
        """
        proto = ExtendDNSDatagramProtocol(self, reactor=self._reactor)
        while True:
            try:
                self._reactor.listenUDP(dns.randomSource(), proto)
            except error.CannotListenError:
                pass
            else:
                return proto

    def parseDispatchConfig(self, config):
        if not os.path.exists(config):
            return
        f = open(config, 'r')
        for l in f.readlines():
            l = l.strip()
            if l == "" or l.startswith('#'):
                continue
            t = l.split('=')
            _type = t[0]
            _map = t[1]
            if _type == 'server':
                _entry = _map.split('/')
                _path = _entry[1].strip()
                _addr_and_port = _entry[2].strip().split('#')
                _addr = _addr_and_port[0]
                if not self.is_address_validate(_addr):
                    continue
                _port = "53"
                if len(_addr_and_port) == 2:
                    _port = _addr_and_port[1]

                _port = int(_port)
                self.serverMap[_path] = (_addr, _port)

            if _type == 'address':
                _entry = _map.split('/')
                _path = _entry[1].strip()
                _addr = _entry[2].strip()
                if not self.is_address_validate(_addr):
                    continue
                self.addressMap[_path] = _addr

    def pickServer(self, queries=None):
        _path = None
        name = str(queries[0].name)
        end = len(name.split('.'))
        begin = end - 1
        address = None
        while begin >= 0:
            try:
                _path = '.'.join(name.split('.')[begin:end])
                address = self.serverMap[_path]
                if self.verbose > 0:
                    log.msg('Dispatch server match for ' + name)
                break
            except KeyError:
                pass
            finally:
                begin = begin - 1
        else:
            if self.verbose > 0:
                log.msg('Dispatch server mismatch for ' + name)
            address = self.servers[0]
        return address

    def queryUDP(self, queries, timeout=None):
        if timeout is None:
            timeout = self.timeout

        upstream_address = self.pickServer(queries)
        d = self._query(upstream_address, queries, timeout[0])
        d.addErrback(self._reissue, upstream_address, queries, timeout)
        return d

    def _reissue(self, reason, address, query, timeout):
        reason.trap(dns.DNSQueryTimeoutError)

        timeout = timeout[1:]
        if not timeout:
            return failure.Failure(defer.TimeoutError(query))

        d = self._query(address, query, timeout[0], reason.value.id)
        d.addErrback(self._reissue, address, query, timeout)
        return d

    def queryTCP(self, queries, timeout=10):

        if not len(self.connections):
            address = self.pickServer(queries)
            if address is None:
                return defer.fail(IOError("No domain name servers available"))
            host, port = address
            self._reactor.connectTCP(host, port, self.factory)
            self.pending.append((defer.Deferred(), queries, timeout))
            return self.pending[-1][0]
        else:
            return self.connections[0].query(queries, timeout)

    def _lookup(self, name, cls, type, timeout):
        key = (name, type, cls)
        waiting = self._waiting.get(key)
        if waiting is None:
            self._waiting[key] = []
            d = self.queryUDP([dns.Query(name, type, cls)], timeout)

            def cbResult(result):
                for d in self._waiting.pop(key):
                    d.callback(result)
                return result
            d.addCallback(self.filterAnswers)
            d.addBoth(cbResult)
        else:
            d = defer.Deferred()
            waiting.append(d)
        return d

    def filterAnswers(self, message):
        if message.trunc:
            return self.queryTCP(message.queries).addCallback(self.filterAnswers)
        if message.rCode != dns.OK:
            return failure.Failure(self.exceptionForCode(message.rCode)(message))
        return (message.answers, message.authority, message.additional)

    def _aRecords(self, name, address):
        return tuple([dns.RRHeader(name, dns.A, dns.IN, self.minTTL,
                                   dns.Record_A(address, self.minTTL))])

    def _aaaaRecords(self, name, address):
        return tuple([dns.RRHeader(name, dns.AAAA, dns.IN, self.minTTL,
                                   dns.Record_AAAA(address, self.minTTL))])

    def _respond(self, name, records):
        if records:
            return defer.succeed((records, (), ()))
        return defer.fail(failure.Failure(dns.DomainError(name)))

    def _matchAddress(self, name, packRecords):
        """ 
        Check if query address matches any
        address rule in dispatch.conf
        """
        end = len(name.split('.'))
        begin = end - 1
        address = None
        while begin >= 0:
            try:
                _path = '.'.join(name.split('.')[begin:end])
                address = self.addressMap[_path]
                if self.verbose > 0:
                    log.msg('Dispatch address match for ' + name)
                records = packRecords(name, address)
                return records
            except KeyError:
                pass
            finally:
                begin = begin - 1
        else:
            if self.verbose > 0:
                log.msg('Dispatch address mismatch for ' + name)
            return None

    def lookupAddress(self, name, timeout=None):
        r = self._matchAddress(name, self._aRecords)
        if r:
            return self._respond(name, r)
        else:
            return self._lookup(name, dns.IN, dns.A, timeout)

    def lookupIPV6Address(self, name, timeout=None):
        r = self._matchAddress(name, self._aaaaRecords)
        if r:
            return self._respond(name, r)
        else:
            return self._lookup(name, dns.IN, dns.AAAA, timeout)


class LimitedSizeDict(OrderedDict):

    def __init__(self, size_limit=None, *args, **kwargs):
        self.size_limit = size_limit
        self.used = 0
        OrderedDict.__init__(self, *args, **kwargs)
        self._check_size_limit()

    def __setitem__(self, key, value):
        OrderedDict.__setitem__(self, key, value)
        self._check_size_limit()

    def _check_size_limit(self):
        if self.size_limit is not None:
            while len(self) > self.size_limit:
                self.popitem(last=False)
        self.used = len(self)


class ExtendCacheResolver(cache.CacheResolver):

    def __init__(self, _cache=None, verbose=0, reactor=None, cacheSize=500, minTTL=0, maxTTL=604800):
        assert maxTTL >= minTTL >= 0
        self.minTTL = minTTL
        self.maxTTL = maxTTL
        cache.CacheResolver.__init__(self, _cache, verbose, reactor)
        self.cache = LimitedSizeDict(size_limit=cacheSize)

    def cacheResult(self, query, payload, cacheTime=None):
        try:
            # Already cached
            r = self.cache[query]
            return
        except KeyError:
            pass

        self.cache[query] = (cacheTime or self._reactor.seconds(), payload)
        if self.verbose > 0:
            log.msg('Adding %r to cache' % query)
        if self.verbose > 1:
            log.msg('Cache used (%d / %d)' %
                    (self.cache.used, self.cache.size_limit))

        if query in self.cancel:
            self.cancel[query].cancel()

        s = list(payload[0]) + list(payload[1]) + list(payload[2])

        for r in s:
            if r.ttl < self.minTTL:
                r.ttl = self.minTTL
            if r.ttl > self.maxTTL:
                r.ttl = self.maxTTL
        if s:
            m = s[0].ttl
            for r in s:
                m = min(m, r.ttl)
        else:
            m = 0

        self.cancel[query] = self._reactor.callLater(m, self.clearEntry, query)


class ExtendDNSDatagramProtocol(dns.DNSDatagramProtocol):

    def datagramReceived(self, data, addr):
        """
        Read a datagram, extract the message in it and trigger the associated
        Deferred.
        """
        m = dns.Message()
        try:
            m.fromStr(data)
        except EOFError:
            log.msg("Truncated packet (%d bytes) from %s" % (len(data), addr))
            return
        except:
            # Nothing should trigger this, but since we're potentially
            # invoking a lot of different decoding methods, we might as well
            # be extra cautious.  Anything that triggers this is itself
            # buggy.
            log.err(failure.Failure(), "Unexpected decoding error")
            return
        # Filter spurious ips
        ans = m.answers
        if ans and isinstance(ans[0], dns.RRHeader) and ans[0].type == 1 and ans[0].payload.dottedQuad() in GFW_LIST:
            log.msg("Spurious IP detected")
            return

        if m.id in self.liveMessages:
            d, canceller = self.liveMessages[m.id]
            del self.liveMessages[m.id]
            canceller.cancel()
            # XXX we shouldn't need this hack of catching exception on
            # callback()
            try:
                d.callback(m)
            except:
                log.err()

        else:
            if m.id not in self.resends:
                self.controller.messageReceived(m, self, addr)


def main():
    parser = argparse.ArgumentParser(
        description="A lightweight yet useful proxy DNS server")
    parser.add_argument('-b', '--bind-addr', type=str,
                        help='local address to listen',
                        default='127.0.0.1',
                        )
    parser.add_argument('-p', '--bind-port', type=int,
                        help="local port to listen",
                        default=53,
                        )
    parser.add_argument('--upstream-ip', type=str,
                        help="upstream DNS server ip address",
                        default='208.67.222.222')
    parser.add_argument('--upstream-port', type=int,
                        help="upstream DNS server port",
                        default=53)
    parser.add_argument('--query-timeout', type=int,
                        help="time before close port used for querying",
                        default=1)
    parser.add_argument('--min-ttl', type=int,
                        help="the minimum time a record is held in cache",
                        default=0)
    parser.add_argument('--max-ttl', type=int,
                        help="the maximum time a record is held in cache",
                        default=604800)
    parser.add_argument('--cache-size', type=int,
                        help="record cache size",
                        default=500)
    parser.add_argument('-t', '--tcp-server',
                        help="enables TCP serving",
                        action="store_true")
    parser.add_argument('--hosts-file',
                        help="hosts file",
                        default="")
    parser.add_argument('--dispatch-conf',
                        help="URL dispatch conf file",
                        default="../dispatch.conf")
    parser.add_argument('-v', '--verbosity', type=int,
                        choices=[0, 1, 2],
                        help="output verbosity",
                        default=0)
    parser.add_argument('-q', '--quiet',
                        help="disable output",
                        action='store_true')
    parser.add_argument('-V', '--version',
                        help="print version number and exit",
                        action='store_true')

    args = parser.parse_args()
    if args.version:
        print("SimpleDNS 0.1")
        return
    if not args.quiet:
        log.startLogging(sys.stdout)
        
    addr = args.bind_addr
    port = args.bind_port
    log.msg("Listening on " + addr + ':' + str(port))
    log.msg("Using " + args.upstream_ip + ':' +
            str(args.upstream_port) + ' as upstream server')
           
    hosts_file = None 
    if not args.hosts_file:
        hosts_file = '/etc/hosts'
        if os.environ.__contains__('WINDIR'):
            hosts_file = os.environ['WINDIR'] + '/system32/drivers/etc/hosts'
    else:
        hosts_file = args.hosts_file
        
    factory = server.DNSServerFactory(
        caches=[ExtendCacheResolver(
            verbose=args.verbosity, cacheSize=args.cache_size, minTTL=args.min_ttl, maxTTL=args.max_ttl)],
        clients=[
            hosts.Resolver(hosts_file),
            DispatchResolver(args.dispatch_conf, servers=[(args.upstream_ip, args.upstream_port)], minTTL=args.min_ttl, query_timeout=args.query_timeout, verbose=args.verbosity
                             )],
        verbose=args.verbosity
    )

    protocol = dns.DNSDatagramProtocol(controller=factory)
    if args.verbosity < 2:
        dns.DNSDatagramProtocol.noisy = False
        server.DNSServerFactory.noisy = False
    try:
        reactor.listenUDP(port, protocol, addr)
        if args.tcp_server:
            reactor.listenTCP(
                port, factory, interface=addr)
        reactor.run()
    except error.CannotListenError:
        log.msg(
            "Couldn't listen on " + addr + ':' + str(port))
        log.msg('Check if BIND_PORT is already in use')
        log.msg('Try using sudo to run this program')

if __name__ == "__main__":
    raise SystemExit(main())
