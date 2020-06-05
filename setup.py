from setuptools import setup, find_packages


with open('README.md') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='Azure_Seconf',
    version='0.1.0',
    description='Azure CIS Benchmark',
    long_description=readme,
    author='Kumaran Gopi',
    author_email='',
    url='',
    license=license,
    packages=find_packages(exclude=('tests', 'docs'))
)

