import socket

def is_address_validate(addr):
    if is_ipv4_address(addr):
        return True
    elif is_ipv6_address(addr):
        return True
    else:
        return False

def is_ipv4_address(addr):
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