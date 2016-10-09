# -*- coding: utf-8 -*-
# Copyright (c) 2016 skyline75489
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

import socket
from collections import OrderedDict


class LRUCache(object):
    """
    Simple LRU Cache, using OrderedDict.
    """

    def __init__(self, capacity=1000):
        self.capacity = capacity
        self.used = 0
        self.cache = OrderedDict()

    def get(self, key):
        # Don't catch KeyError here, for the sake of twisted CachedResolver
        # implementation.
        value = self.cache.pop(key)
        self.cache[key] = value
        return value

    def set(self, key, value):
        try:
            self.cache.pop(key)
        except KeyError:
            if len(self.cache) >= self.capacity:
                self.cache.popitem(last=False)
        self.cache[key] = value
        self.used = len(self.cache)

    def __getitem__(self, key):
        return self.get(key)

    def __setitem__(self, key, value):
        self.set(key, value)

    def __delitem__(self, key):
        del self.cache[key]

    def __len__(self):
        return len(self.cache)
        
    def items(self):
        return self.cache.items()


def is_address_validate(addr):
    if is_ipv4_address(addr):
        return True
    elif is_ipv6_address(addr):
        return True
    else:
        return False


def is_ipv4_address(addr):
    """ 
    Check if an address is a valid IPv4 address
    Note that something like '1.1.1' is considered to be valid. 
    Because '1.1.1' can be abbreviation of '1.1.1.0'
    """
    try:
        socket.inet_aton(addr)
        return True
    except (socket.error, ValueError):
        return False


def is_ipv6_address(addr):
    try:
        socket.inet_pton(socket.AF_INET6, addr)
        return True
    except (socket.error, ValueError):
        return False
