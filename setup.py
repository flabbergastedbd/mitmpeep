from setuptools import setup

setup(
    name="mitmpeep",
    version="0.1",
    description="Library to simplify mitmproxy scripts for web app pentesting.",
    url="https://github.com/tunnelshade/mitmpeep",
    author="Bharadwaj Machiraju",
    author_email="name.surname@gmail.com",
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Natural Language :: English",
        "Programming Language :: Python :: 3 :: Only"
    ],
    install_requires=[
        "mitmproxy>=2.0.2"
    ],
    tests_require=[
        "coverage",
        "flake8"
    ])
