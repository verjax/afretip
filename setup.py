from setuptools import find_packages, setup

with open("README.md", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="afretip",
    version="1.0.0",
    author="C Nyandoro",
    author_email="csnyadoro03@gmail.com",
    description="Automated threat intelligence pipeline for first response for Wazuh (EDR)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://git.mif.vu.lt/micac/2025/afretip.git",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "threat-intel=threat_intel.cli:main",
            "afretip=threat_intel.cli:main",
        ],
    },
    include_package_data=True,
)
