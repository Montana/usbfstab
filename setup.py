#!/usr/bin/env python3

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="usbfstab",
    version="1.0.0",
    author="Montana",
    author_email="montana@linux.com",
    description="Anti-forensic kill-switch that monitors USB ports and shuts down on changes",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Montana/usbfstab",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.7",
    install_requires=[
        "typing-extensions>=4.0.0",
        "asyncio>=3.4.3",
    ],
    entry_points={
        "console_scripts": [
            "usbfstab=usbfstab.usbfstab:main",
        ],
    },
    data_files=[
        ("/etc", ["install/usbfstab.ini"]),
        ("/usr/local/bin", ["install/usbfstab"]),
    ],
    include_package_data=True,
    zip_safe=False,
)
