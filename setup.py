from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ossec-config-manager",
    version="0.1.0",
    author="Cybersilo",
    description="A Python package for managing Wazuh OSSEC configurations",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Hisham-Tariq/ossec-config-manager",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
        "lxml",
    ],
) 