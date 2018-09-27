
from setuptools import setup, find_packages

DEPENDENCIES = [
    "anthill-common>=0.1.0"
]

setup(
    name='anthill-admin',
    version='0.1.0',
    description='Administration service for Anthill platform',
    author='desertkun',
    license='MIT',
    author_email='desertkun@gmail.com',
    url='https://github.com/anthill-platform/anthill-admin',
    namespace_packages=["anthill"],
    packages=find_packages(),
    zip_safe=False,
    install_requires=DEPENDENCIES
)
