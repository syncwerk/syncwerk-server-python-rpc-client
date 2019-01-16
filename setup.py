from setuptools import setup, find_packages
setup(
    name='syncwerk-server-python-rpc-client',
    version='20181227',
    author='Syncwerk GmbH',
    author_email='support@syncwerk.com',
    packages=find_packages(exclude=["Makefile.am", "*.tests", "*.tests.*", "tests.*", "tests"]),
    url='https://www.syncwerk.com',
    license='Apache 2.0',
    description='Syncwerk RPC client',
    long_description='RPC client module to communicate with the Syncwerk server server',
    platforms=['any'],
    include_package_data=True,
)
