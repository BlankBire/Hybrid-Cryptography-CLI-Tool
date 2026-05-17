from setuptools import find_packages, setup

setup(
    name="hybrid-crypto",
    version="1.0.0",
    description="Hybrid RSA-4096-OAEP + AES-GCM-256 file encryption CLI tool.",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "cryptography>=42.0.0",
    ],
    entry_points={
        "console_scripts": [
            "hybrid-crypto=hybrid_crypto.cli:main",
        ],
    },
)
