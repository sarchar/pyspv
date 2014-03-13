from distutils.core import setup, Extension

setup(
    name = "pyspv",
    author = "Chuck \"Sarchar\"",
    author_email = "chuck@borboggle.com",
    url = "https://github.com/sarchar/pyspv",
    license = "MIT",
    classifiers = [
        "License :: OSI Approved :: MIT License",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Topic :: Internet",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Networking",
        "Topic :: System :: Distributed Computing",
    ],
    description = "Bitcoin SPV implementation in Python",
    packages = ["pyspv", "pyspv.monitors", "pyspv.payments"],
    requires = ['bitarray (>=0.8.1)'],
    version = '0.0.1',
    long_description = open('README.md').read(),
)
