from setuptools import setup

with open('README.rst') as f:
    long_description = f.read()

setup(
    name="simpledns",
    version="0.1.2",
    license="MIT",
    description="A lightweight yet useful proxy DNS server",
    author='skyline75489',
    author_email='skyline75489@outlook.com',
    url='https://github.com/skyline75489/SimpleDNS',
    packages=['simpledns'],
    data_files=[('/usr/local/etc/simpledns',['dispatch.conf'])],
    install_requires=[
        'twisted>=14.0.0'
    ],
    entry_points={
        'console_scripts': ['simpledns = simpledns.dnsproxy:main'],
    },
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: Proxy Servers',
    ],
    long_description=long_description,
)
