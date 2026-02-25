"""
setup.py — Legacy build entry point.

Used for:
  uv run setup.py sdist bdist_wheel
  uv run setup.py --command-packages=stdeb.command bdist_deb
"""

from setuptools import setup, find_packages

setup(
    name="wisee",
    version="0.1.0",
    description="Local network discovery tool — ARP, mDNS, NetBIOS, UPnP, nmap",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="WiSee",
    url="https://github.com/r-seize/wisee",
    license="MIT",
    python_requires=">=3.10",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "scapy>=2.7.0",
        "rich>=14.3.3",
        "click>=8.3.1",
    ],
    entry_points={
        "console_scripts": [
            "wisee=wisee.cli:cli",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: System :: Networking :: Monitoring",
    ],
    include_package_data=True,
)