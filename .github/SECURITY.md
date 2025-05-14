# Security Policy

## Supported Versions

We currently support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability within this library, please send an email to [security@vaultic.org](mailto:security@vaultic.org). All security vulnerabilities will be promptly addressed.

Please include the following information in your report:

- Type of vulnerability
- Steps to reproduce
- Affected versions
- Potential impact

## Security Considerations

This library addresses the Marvin Attack (RUSTSEC-2023-0071) with the following mitigations:

1. Random delays in private key operations
2. Enhanced blinding factors
3. Usage recommendations to avoid network-exposed environments

We actively monitor security advisories related to our dependencies and provide updates as quickly as possible when vulnerabilities are discovered.