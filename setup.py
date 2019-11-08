from os import path
from setuptools import setup

here = path.abspath(path.dirname(__file__))


with open(path.join(here, 'README.md')) as fd:
    readme = fd.read()

setup(
    name='pyopenssl-psk',
    version='1.0.0',
    description='Add PSK support to pyOpenSSL',
    long_description=readme,
    long_description_content_type='text/markdown',
    url='https://github.com/gesslerpd/pyopenssl-psk',
    author='gesslerpd',
    author_email='gesslerpd@users.noreply.github.com',
    license='Apache-2.0',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    keywords='pyopenssl openssl psk',
    packages=['openssl_psk'],
    install_requires=[
        'pyOpenSSL',
        'cryptography>2.2.2'
    ],
)
