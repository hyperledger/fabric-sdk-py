#!/usr/bin/env python
import io
import os
from setuptools import setup, find_packages
from hfs import VERSION

ROOT_DIR = os.path.dirname(__file__)
SOURCE_DIR = os.path.join(ROOT_DIR)

requirements = [
    'requests >= 2.5.0',
    'six >= 1.4.0',
    # 'websocket-client >= 0.32.0',
]

exec(open('hfs/version.py').read())

with open('./requirements-test.txt') as test_reqs_txt:
    test_requirements = [line for line in test_reqs_txt]

setup(
    name='hfs',
    version=VERSION,
    keywords=('Hyperledger Fabric', 'SDK'),
    license='Apache License v2.0',
    description="Python SDK for Hyperledger Fabric.",
    long_description=io.open('README.md', encoding='utf-8').read(),
    author='Hyperledger Community',
    url='https://github.com/hyperledger/fabric-sdk-py/',
    download_url='https://github.com/hyperledger/fabric-sdk-py/',
    packages=find_packages(),
    platforms='any',
    install_requires=requirements,
    tests_require=test_requirements,
    zip_safe=False,
    test_suite='tests',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Other Environment',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.0',
        'Programming Language :: Python :: 3.5',
        'Topic :: Utilities',
        'License :: OSI Approved :: Apache Software License',
    ],
    include_package_data=True,
)
