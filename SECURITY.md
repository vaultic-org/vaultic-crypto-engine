# Marvin Attack Mitigations

This document describes the mitigation measures implemented in this library to counter the Marvin Attack (RUSTSEC-2023-0071).

## Background

The Marvin Attack is a timing side-channel vulnerability that affects many RSA implementations, including the Rust `rsa` library. This attack potentially allows an attacker to extract the private key by observing timing variations during decryption operations.

## Implemented Mitigations

While a definitive fix is not yet available for the `rsa` library, we have implemented several measures to significantly reduce the risk:

1. **Random Delays**: We have introduced random delays during decryption operations to mask timing variations based on key values.

2. **Usage Recommendations**: The documentation emphasizes the importance of using this library only in environments where side-channel attacks are impractical (such as local applications not exposed to the network).

3. **Timing Noise**: Critical operations are made more difficult to time precisely through the introduction of noise in the timing.

## Usage Recommendations

To minimize risks, we recommend:

1. **Avoid Network Environments**: Do not use this library in scenarios where an attacker could observe response times over a network.

2. **Avoid High-Frequency Operations**: Limit the number of decryption operations to reduce the statistical attack surface.

3. **Consider Constant-Time Alternatives**: For critical applications, consider using cryptographic libraries that guarantee constant-time operations such as `aws-lc-rs`.

## Future Plan

We are actively following the development of a complete fix for the `rsa` library. As soon as a fixed version becomes available, we will update this dependency.

For more information about the Marvin Attack, see:
- [Marvin Attack Official Site](https://people.redhat.com/~hkario/marvin/)
- [RUSTSEC-2023-0071 Security Advisory](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)