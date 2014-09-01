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
	license="MIT",
	description="A lightweight yet useful proxy DNS server",
	author='skyline75489',
	author_email='skyline75489@outlook.com',
	url='https://github.com/skyline75489/SimpleDNS',
	packages=['simpledns'],
	data_files=["README.md", "LICENSE", "dispatch.conf"],
	options={'py2exe': {
		'includes': includes,
		'bundle_files': 1,
		'compressed': True}},
	console=console,
	classifiers=[
		'License :: OSI Approved :: MIT License',
		'Programming Language :: Python :: 2',
		'Programming Language :: Python :: 2.7',
		'Topic :: Internet :: Proxy Servers',
	],
	long_description=long_description,
	)
