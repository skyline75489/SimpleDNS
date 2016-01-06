SimpleDNS
=========

.. image:: https://badge.fury.io/py/simpledns.png
    :target: http://badge.fury.io/py/simpledns
	
A lightweight yet useful proxy DNS server designed to cope with `complicated Internet environment <http://en.wikipedia.org/wiki/Great_Firewall_of_China#Blocking_methods>`__ in China, inspired by `ChinaDNS <https://github.com/clowwindy/ChinaDNS>`__ , `dnsmasq-chinadns <https://github.com/styx-hy/dnsmasq-chinadns>`__ and `fqdns <https://github.com/fqrouter/fqdns>`__, powered by Python `Twisted <https://twistedmatrix.com/trac/>`__.

Requirement
-----------

* Python 2.7
* Twisted
* Tornado for using Tornado IOLoop(optional)

Install
-------

* Linux/Mac OS X::
	
	# Clone this project
    $ sudo python setup.py install

* Windows
    
  `Download <http://pan.baidu.com/s/1i3A9KhB>`__
    
Usage
-----

Run ``sudo simpledns`` on your local machine. Then set your DNS server to 127.0.0.1.

::

	$ dig www.twitter.com +short
	twitter.com.
	199.59.149.230
	199.59.148.10
	199.59.150.7
	199.59.150.39

Note that the default cache lifetime depends on the ttl of DNS answer. You may want to set a larger ttl using --min-ttl to extend the cache lifetime.

Advanced
--------

::

	$ simpledns -h
	usage: simpledns [-h] [-b BIND_ADDR] [-p BIND_PORT]
	                 [--upstream-ip UPSTREAM_IP] [--upstream-port UPSTREAM_PORT]
	                 [--query-timeout QUERY_TIMEOUT] [--min-ttl MIN_TTL]
	                 [--max-ttl MAX_TTL] [--cache-size CACHE_SIZE] [-t]
	                 [--hosts-file HOSTS_FILE] [--dispatch-conf DISPATCH_CONF]
	                 [-v {0,1,2}] [-q] [-V]

	A lightweight yet useful proxy DNS server

	optional arguments:
	  -h, --help            show this help message and exit
	  -b BIND_ADDR, --bind-addr BIND_ADDR
	                        local address to listen
	  -p BIND_PORT, --bind-port BIND_PORT
	                        local port to listen
	  --upstream-ip UPSTREAM_IP
	                        upstream DNS server ip address
	  --upstream-port UPSTREAM_PORT
	                        upstream DNS server port
	  --query-timeout QUERY_TIMEOUT
	                        time before close port used for querying
	  --min-ttl MIN_TTL     the minimum time a record is held in cache
	  --max-ttl MAX_TTL     the maximum time a record is held in cache
	  --cache-size CACHE_SIZE
	                        record cache size
	  -t, --tcp-server      enables TCP serving
	  --hosts-file HOSTS_FILE
	                        hosts file
	  --dispatch-conf DISPATCH_CONF
	                        URL dispatch conf file
	  -v {0,1,2}, --verbosity {0,1,2}
	                        output verbosity
	  -q, --quiet           disable output
	  -V, --version         print version number and exit
	  
Configuration
-------------

Configuration file is at /usr/local/etc/simpledns/dispatch.conf.

Dispatch conf file uses the same rule as in `Dnsmasq <http://www.thekelleys.org.uk/dnsmasq/doc.html>`__. 'Address' and 'Server' rules are supported.

::

	address=/example1.com/1.1.1.1
	server=/example2.com/1.1.1.2
	  
	  
Default dispatch conf file is from `dnsmasq-china-list <https://github.com/felixonmars/dnsmasq-china-list/blob/master/accelerated-domains.china.conf>`__.

Fake ip list file is at /usr/local/ect/simpledns/iplist/txt. The source is `ChinaDNS <https://github.com/shadowsocks/ChinaDNS/blob/master/iplist.txt>`__.

TODO
----

* Config file support
* EDNS support
* Negative caching

License
-------

The MIT License
