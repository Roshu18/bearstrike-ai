# Contributing to BearStrike AI

We welcome contributions to BearStrike AI! Your help is invaluable in making this project better for everyone. This document outlines the guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Submitting Pull Requests](#submitting-pull-requests)
- [Development Setup](#development-setup)
- [Coding Guidelines](#coding-guidelines)
- [Commit Message Guidelines](#commit-message-guidelines)
- [License](#license)

## Code of Conduct

BearStrike AI adheres to the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/0/code_of_conduct.html). By participating, you are expected to uphold this code. Please report unacceptable behavior to [your-email@example.com].

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue on GitHub. Before submitting, please do the following:

1.  **Check existing issues**: See if the bug has already been reported.
2.  **Provide detailed information**: Include steps to reproduce the bug, expected behavior, actual behavior, and your environment (OS, Python version, BearStrike AI version).
3.  **Use a clear title**: A concise and descriptive title helps in quickly understanding the issue.

### Suggesting Enhancements

We love new ideas! If you have a suggestion for an enhancement or a new feature, please open an issue on GitHub. When suggesting an enhancement:

1.  **Check existing suggestions**: Ensure your idea hasn't been proposed before.
2.  **Describe the feature**: Explain what the feature does, why it's useful, and how it might be implemented.
3.  **Provide use cases**: Illustrate how the feature would be used in practice.

### Submitting Pull Requests

Pull requests are the best way to contribute code. Here's a general workflow:

1.  **Fork the repository** and clone it to your local machine.
2.  **Create a new branch** for your feature or bug fix: `git checkout -b feature/your-feature-name` or `git checkout -b bugfix/your-bug-fix-name`.
3.  **Make your changes** and ensure they adhere to the [Coding Guidelines](#coding-guidelines).
4.  **Write tests** for your changes. Ensure existing tests pass.
5.  **Update documentation** if your changes affect any user-facing functionality or API.
6.  **Commit your changes** using a descriptive [Commit Message Guidelines](#commit-message-guidelines).
7.  **Push your branch** to your forked repository.
8.  **Open a Pull Request** to the `main` branch of the `bearstrike-ai` repository. Provide a clear description of your changes and reference any related issues.

## Development Setup

To set up your development environment, follow the [Installation](#installation) instructions in the `README.md`.

## Coding Guidelines

-   **Python Style**: Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) for Python code.
-   **Type Hinting**: Use type hints for all function arguments and return values.
-   **Docstrings**: All functions and classes should have clear docstrings explaining their purpose, arguments, and return values.
-   **Logging**: Use the `logging` module for output, not `print()`.

## Commit Message Guidelines

We follow the [Conventional Commits specification](https://www.conventionalcommits.org/en/v1.0.0/) for our commit messages. This helps with generating changelogs and understanding the history of the project. Examples:

-   `feat: add new feature X`
-   `fix: resolve bug Y`
-   `docs: update installation guide`
-   `chore: update dependencies`

## License

By contributing to BearStrike AI, you agree that your contributions will be licensed under the MIT License, as specified in the project's `LICENSE` file.
