import socket

from collections import OrderedDict

class LimitedSizeDict(OrderedDict):
    """
    Dictionary that has limited capacity, behaves like a FIFO queue
    """
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
        
