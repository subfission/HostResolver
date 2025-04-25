#  setup.py
#
# Copyright (c) 2017-2018, Zach Jetson All rights reserved.
#
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: Zach Jetson
# Date:   May 2017-2025
# Name:   resolv.py
#
# This file will setup the Host Resolver script.

from setuptools import find_packages, setup

"""This file will setup the Host Resolver script."""

setup(
    name='resolv',
    description='Host resolver script.',
    long_description="Resolve hosts to IP addresses, scan for SPF records, and enumerate ASNs as quickly as possible.",
    author='Zach Jetson',
    maintainer='Zach Jetson',
    packages=find_packages(),
    keywords='host resolver enumeration',

    entry_points={
        'console_scripts': ['resolv = resolv:main']
    },

    python_requires='>=3.7,<3.13',
    setup_requires=[],
    install_requires=[
        "setuptools==79.0.1",
        "dnspython==2.7.0",
        "rich==14.0.0"
    ]
)
