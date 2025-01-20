#
# Copyright (c) 2024 Cisco and/or its affiliates
#
import os
import sys
import versioneer
from setuptools import setup

#
# hack to provent incorrect shebang substitution
#
import re
from distutils.command import build_scripts
build_scripts.first_line_re = re.compile(b'^should not match$')

__author__ = "Taylor Cook"
__author_email__ = "aacook@cisco.com"
__copyright__ = "Copyright (c) 2024 Cisco and/or its affiliates."
__license__ = "Apache 2.0"

if (sys.version_info.major == 2) or (sys.version_info.major == 3 and sys.version_info.minor < 8):
    print ("Sorry, Python < 3.8 is not supported")
    exit()

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup (
    name='ise_pyshark',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    description='Custom DPI tool used to passively analyze endpoint data and transmit results via Cisco ISE API messaging for improved endpoint profiling',
    long_description='Custom DPI tool used to passively analyze endpoint data and transmit results via Cisco ISE API messaging for improved endpoint profiling',
    packages=['ise_pyshark'],
    scripts=[
        'bin/ise-pyshark',
        'bin/ise-pyshark-file',
    ],
    author=__author__,
    author_email=__author_email__,
    license=__license__ + "; " + __copyright__,
    url='https://github.com/taylor-cook/ise-pyshark',
    download_url='https://github.com/taylor-cook/ise-pyshark',
    install_requires=[
        'psutil>=5.9.8',
        'pyshark>=0.6',
        'redis>=5.2.0',
        'requests>=2.31.0',
        'urllib3>=2.2.2',
        'user-agents>=2.2.0',
        'versioneer>=0.29'
    ],
    include_package_data=True,
    platforms=['OS X','Linux','Windows'],
    keywords=['ISE', 'API', 'IOT', 'profiling'],
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
)

