
from setuptools import setup, find_packages

DEPENDENCIES = [
    "anthill-common"
]

setup(
    name='anthill-admin',
    package_data={
      "anthill.admin": ["anthill/admin/sql", "anthill/admin/static"]
    },
    setup_requires=["pypigit-version"],
    git_version="0.1.0",
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
