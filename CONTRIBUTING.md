Contributing to CERBERUS NETWORK DEFENDER
Thank you for your interest in contributing to CERBERUS! This document provides guidelines and instructions for contributing to the project.

Code of Conduct
By participating in this project, you agree to abide by our Code of Conduct. Please read it before contributing.

How to Contribute
Reporting Bugs
Check if the bug has already been reported in the Issues
If not, create a new issue with a descriptive title and clear description
Include steps to reproduce, expected behavior, and actual behavior
Add relevant logs, network captures, or screenshots if applicable
Use the "bug" label
Include information about your environment (OS, Python version, network setup)
Suggesting Enhancements
Check if the enhancement has already been suggested in the Issues
If not, create a new issue with a descriptive title and clear description
Explain why this enhancement would be useful for network defense
If possible, outline how the enhancement could be implemented
Use the "enhancement" label
Pull Requests
Fork the repository
Create a new branch from main
Make your changes
Run tests to ensure your changes don't break existing functionality
Submit a pull request to the main branch
Reference any related issues in your pull request description
Development Setup
Clone your fork of the repository

bash

Hide
git clone https://github.com/yourusername/cerberus-defender.git
cd cerberus-defender
Create and activate a virtual environment

bash

Hide
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
Install dependencies

bash

Hide
pip install -r requirements.txt
pip install -r requirements-dev.txt
Set up pre-commit hooks

bash

Hide
pre-commit install
Configure the system for development

bash

Hide
cp config.example.json config.dev.json
# Edit config.dev.json with development settings
Create a test network environment

bash

Hide
./scripts/create_test_network.sh
Development Guidelines
Network Interaction Safety
Always use the --simulation-mode flag during development to prevent unintended network changes
Test new decoy types in isolated environments before submitting PRs
Document any new network interactions clearly in code comments
Never test Moving Target Defense features on production networks
Coding Standards
Follow PEP 8 style guide
Use type hints for all function parameters and return values
Write docstrings for all classes and functions
Maintain test coverage above 80%
Use meaningful variable and function names
Keep methods focused and under 50 lines where possible
Testing
Write unit tests for all new functionality

Write integration tests for network interaction components

Include simulation tests for decoys and MTD strategies

Run the test suite before submitting a pull request

bash

Hide
pytest
Run linting checks

bash

Hide
flake8 cerberus
mypy cerberus
Specialized Contributions
Decoy Templates
If you want to contribute new decoy templates:

Add your template to the templates/decoys/ directory
Follow the existing template format
Include realistic service banners and responses
Document the behavior of the decoy
Add tests for the new decoy type
Update the decoy documentation
Moving Target Defense Strategies
For new MTD strategies:

Add your strategy to the strategies/mtd/ directory
Implement the required strategy interface
Document the strategy's effectiveness and limitations
Include performance impact analysis
Add tests for the new strategy
Update the MTD documentation
Evasion Techniques
For contributions related to evasion detection:

Document the evasion technique you're addressing
Implement detection mechanisms in the appropriate module
Add test cases with examples of the evasion technique
Update the threat detection documentation
Commit Guidelines
Use clear, descriptive commit messages
Follow the conventional commits format:
feat: for new features
fix: for bug fixes
docs: for documentation changes
test: for adding or updating tests
refactor: for code changes that neither fix bugs nor add features
perf: for performance improvements
chore: for changes to the build process or auxiliary tools
Branch Naming Convention
Use descriptive branch names that reflect the changes being made
Prefix branches with the type of change:
feature/ for new features
bugfix/ for bug fixes
hotfix/ for critical bug fixes
docs/ for documentation changes
refactor/ for code refactoring
Pull Request Process
Ensure your code follows the coding standards
Update documentation if necessary
Include tests for new functionality
Make sure all tests pass
Update the CHANGELOG.md with details of changes
The pull request will be reviewed by at least one maintainer
Address any feedback from code reviews
Once approved, a maintainer will merge your changes
Security Vulnerability Reporting
If you discover a security vulnerability, please do NOT open an issue. Email security@cerberus-defender.io instead.

Questions?
If you have any questions about contributing, feel free to:

Open an issue with the "question" label
Email contributors@cerberus-defender.io
Join our Discord community
Thank you for contributing to CERBERUS NETWORK DEFENDER!
