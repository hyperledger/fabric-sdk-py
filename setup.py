# SPDX-License-Identifier: Apache-2.0
#
#!/usr/bin/env python
import io
import os
from setuptools import setup, find_packages
from hfc import VERSION

ROOT_DIR = os.path.dirname(__file__)
SOURCE_DIR = os.path.join(ROOT_DIR)

exec(open('hfc/version.py').read())

with open('./requirements.txt') as reqs_txt:
    requirements = [line for line in reqs_txt]

with open('./requirements-test.txt') as test_reqs_txt:
    test_requirements = [line for line in test_reqs_txt]

setup(
    name='fabric-sdk-py',
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
    test_suite='test',
    classifiers=[
            'Development Status :: 3 - Alpha',
            'Environment :: Other Environment',
            'Intended Audience :: Developers',
            'Operating System :: OS Independent',
            'Programming Language :: Python',
            'Programming Language :: Python :: 3.6',
            'Topic :: Utilities',
            'License :: OSI Approved :: Apache Software License',
    ],
    include_package_data=True,
)
