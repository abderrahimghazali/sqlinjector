from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="sqlinjector",
    version="1.0.0",
    author="AbderrahimGHAZALI",
    author_email="ghazali.abderrahim1@gmail.com",
    description="A professional SQL injection testing framework for security professionals",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/abderrahimghazali/sqlinjector",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "Environment :: Console",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
        "aiohttp>=3.8.0",
        "click>=8.0.0",
        "colorama>=0.4.6",
        "beautifulsoup4>=4.11.0",
        "urllib3>=1.26.0",
        "pydantic>=2.0.0",
        "jinja2>=3.0.0",
        "tabulate>=0.9.0",
        "pyyaml>=6.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "isort>=5.0.0",
            "flake8>=5.0.0",
            "mypy>=1.0.0",
        ],
        "advanced": [
            "selenium>=4.0.0",
            "playwright>=1.30.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "sqlinjector=sqlinjector.cli:main",
        ],
    },
    keywords=["security", "sql-injection", "penetration-testing", "vulnerability-scanner"],
)