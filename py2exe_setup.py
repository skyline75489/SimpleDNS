from distutils.core import setup
import sys
import os
# require import
import py2exe

# require shadowsocks
twpath = os.path.abspath(os.path.join(sys.path[-1], "twisted"))

if not os.path.isdir(twpath):
	raise IOError("require twisted")

with open('README.rst') as f:
	long_description = f.read()
		
includes = ["twisted", "zope.interface"]
console = [os.path.join("simpledns", "dnsproxy.py")]

setup(
	name="simpledns",
	version="0.1.2",
	license="MIT",
	description="A lightweight yet useful proxy DNS server",
	author='skyline75489',
	author_email='skyline75489@outlook.com',
	url='https://github.com/skyline75489/SimpleDNS',
	packages=['simpledns'],
	data_files=["README.rst", "LICENSE", "dispatch.conf"],
	options={'py2exe': {
		'includes': includes,
		'bundle_files': 1,
		'compressed': True}},
	console=console,
	classifiers=[
		'License :: OSI Approved :: MIT License',
		'Operating System :: OS Independent',
		'Programming Language :: Python :: 3',
		'Programming Language :: Python :: 3.4',
		'Topic :: Internet :: Proxy Servers',
	],
	long_description=long_description,
)
