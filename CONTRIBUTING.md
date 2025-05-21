# Contributing to Vaultic Crypto Engine

First off, thank you for considering contributing to the Vaultic Crypto Engine! Your help is essential for keeping it great.

## How can I Contribute?

There are many ways you can contribute to the project:

- **Reporting Bugs**: If you find a bug, please open an issue on GitHub. Include as much detail as possible, such as steps to reproduce, expected behavior, and actual behavior.
- **Suggesting Enhancements**: If you have an idea for a new feature or an improvement to an existing one, please open an issue to discuss it.
- **Writing Code**: If you're looking to contribute code, please look for issues tagged with "help wanted" or "good first issue." You can also propose your own changes.
- **Improving Documentation**: Clear and concise documentation is crucial. If you find areas that can be improved or new content that should be added, please let us know or submit a pull request.
- **Writing Tests**: More tests are always welcome! They help ensure stability and prevent regressions.

## Development Setup

1.  **Fork the repository** on GitHub.
2.  **Clone your fork locally**:
    ```bash
    git clone https://github.com/<YOUR_USERNAME>/vaultic-crypto-engine.git
    cd vaultic-crypto-engine
    ```
3.  **Create a new branch** for your changes:
    ```bash
    git checkout -b my-feature-branch
    ```
4.  **Install Rust**: If you don't have it already, install Rust from [rust-lang.org](https://www.rust-lang.org/).
5.  **Install `wasm-pack`**: For WebAssembly related contributions, you'll need `wasm-pack`.
    ```bash
    cargo install wasm-pack
    ```
6.  **Build the project**:
    ```bash
    cargo build
    # For WASM builds (if your changes affect WASM)
    wasm-pack build --scope vaultic -- --features wasm
    ```
7.  **Run tests**:
    ```bash
    cargo test
    # For WASM tests (if applicable)
    # You might need to set up a test runner like wasm-bindgen-test
    ```

## Coding Guidelines

- **Follow existing code style**: Try to maintain consistency with the existing codebase.
- **Write clear and concise comments**: Explain non-obvious parts of your code.
- **Ensure your code is well-tested**: Add unit tests for new features and bug fixes.
- **Keep commits focused**: Each commit should represent a logical unit of work.
- **Write meaningful commit messages**: Follow conventional commit message formats if possible (e.g., `feat(ecc): Add new ECC curve support`).
- **Ensure all tests pass** before submitting a pull request.
- **Format your code**: Run `cargo fmt` before committing.
- **Check for linter warnings**: Run `cargo clippy` and address any warnings.

## Pull Request Process

1.  **Ensure your branch is up-to-date** with the main repository's `main` (or `master`) branch.
    ```bash
    git remote add upstream https://github.com/vaultic-org/vaultic-crypto-engine.git
    git fetch upstream
    git rebase upstream/main
    ```
2.  **Push your changes** to your fork on GitHub:
    ```bash
    git push origin my-feature-branch
    ```
3.  **Open a Pull Request (PR)** from your fork to the `vaultic-org/vaultic-crypto-engine` repository.
4.  **Provide a clear description** of your changes in the PR. Link to any relevant issues.
5.  **Be prepared to discuss and iterate** on your PR based on feedback from maintainers.

## Code of Conduct

Please note that this project is released with a Contributor Code of Conduct. By participating in this project you agree to abide by its terms. (We would typically add a `CODE_OF_CONDUCT.md` file for this).

## Questions?

If you have any questions, feel free to open an issue or reach out to the maintainers.

Thank you for your contribution! 