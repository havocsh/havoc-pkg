from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="havoc",
    version="0.2.5",
    packages=find_packages(),

    # Project requires Python 3.7 or higher but less than Python 4
    python_requires='>=3.7, <4',

    # Project requires requests
    install_requires=[
        "requests>=2.25.0"
    ],


    # metadata to display on PyPI
    author="Tom D'Aquino",
    author_email="tom@havoc.sh",
    description="This is the havoc.sh REST API library Package",
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords="havoc.sh REST API library",
    url="https://havoc.sh/",
    project_urls={
        "Bug Tracker": "https://github.com/havocsh/havoc-pkg/issues",
        "Documentation": "https://github.com/havocsh/havoc-pkg/blob/main/README.md",
        "Source Code": "https://github.com/havocsh/havoc-pkg",
    },
    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent"
    ]
)
