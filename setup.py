#!/usr/bin/env python3
from io import open

from os.path import abspath, dirname, join

from setuptools import setup

PROJECT_ROOT = abspath(dirname(__file__))
with open(join(PROJECT_ROOT, 'README.rst'), encoding='utf-8') as f:
    readme = f.read()

version = (
    [l for l in open(join(PROJECT_ROOT, 'zeroconf.py')) if '__version__' in l][0]
    .split('=')[-1]
    .strip().strip('\'"')
)

setup(
    name='zeroconf',
    version=version,
    description='Pure Python Multicast DNS Service Discovery Library '
    '(Bonjour/Avahi compatible)',
    long_description=readme,
    author='Paul Scott-Murphy, William McBrine, Jakub Stasiak',
    url='https://github.com/jstasiak/python-zeroconf',
    py_modules=['zeroconf'],
    platforms=['unix', 'linux', 'osx'],
    license='LGPL',
    zip_safe=False,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)',
        'Operating System :: POSIX',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS :: MacOS X',
        'Topic :: Software Development :: Libraries',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
    ],
    keywords=[
        'Bonjour', 'Avahi', 'Zeroconf', 'Multicast DNS', 'Service Discovery',
        'mDNS',
    ],
    install_requires=[
        'ifaddr',
        'ipaddress'
    ],
)
