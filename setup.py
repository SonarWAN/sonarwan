from setuptools import setup

setup(name='sonarwan',
      version='0.1',
      description='Recognize devices of a private network by sniffing NAT\'d traffic',
      url='http://github.com/sonarwan/sonarwan',
      author='Ivan Itzcovich - Federico Bond',
      install_requires=[
          'pyshark',
          'tabulate',
          'yapf',
      ]
      packages=['sonarwan'],
      )
