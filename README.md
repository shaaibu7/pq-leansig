# pq-leansig

A Rust library providing post-quantum XMSS (eXtended Merkle Signature Scheme) key generation, message signing, and signature verification for Lean Ethereum, the redesigned Ethereum consensus layer.

## Overview

`pq-leansig` is a cryptographic library that implements post-quantum secure key and signatures using XMSS with Poseidon hash functions. It provides both a Rust API and C FFI bindings for interoperability with other languages (particularly Go), along with SSZ (Simple Serialize) support for Ethereum compatibility.

This library is designed for use in Lean Ethereum's consensus layer, where quantum-resistant keys and signatures are essential for long-term security.

## Features

- **Post-Quantum Security**: XMSS-based signatures resistant to quantum computer attacks
- **Epoch-Based Signing**: Support for time-bounded key usage with activation and expiration epochs
- **SSZ Serialization**: Full support for Ethereum's Simple Serialize format
- **FFI Interface**: C-compatible API for cross-language integration (Go, C, C++)
- **Type Safety**: Strongly-typed Rust API with comprehensive error handling
- **Optimized Implementation**: Uses Poseidon hash with optimized parameters (Lifetime 2^32, Dim 64, Base 8)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
pq-leansig = { git = "https://github.com/shaaibu/pq-leansig" }
```

## API

The library provides both a Rust API and C FFI interface for cross-language integration. Key operations include:

- Key generation with epoch parameters
- Message signing with epoch-based validation
- Signature verification
- SSZ serialization and deserialization for all types

## Architecture

### Core Types

- **`LeanSignatureScheme`**: XMSS instantiation with Poseidon hash (Lifetime 2^32, Dim 64, Base 8)
- **`SecretKey`**: Private key for signing operations
- **`PublicKey`**: Public key for signature verification
- **`Signature`**: XMSS signature structure
- **`Keypair`**: Combined public and private key pair

### Epoch-Based Key Management

Keys are generated with specific activation and expiration parameters:

- **`activation_epoch`**: The epoch when the key becomes valid
- **`num_active_epochs`**: Number of epochs the key remains valid

This design enables:
- Time-bounded key validity
- Planned key rotation
- Forward security guarantees

### Error Handling

The library provides typed errors for robust error handling:

- **`SigningError`**: Errors during message signing
- **`SignatureVerificationError`**: Errors during signature verification

## Security Considerations

1. **Quantum Resistance**: XMSS is a hash-based signature scheme proven secure against quantum attacks
2. **Stateful Signatures**: XMSS requires careful state management - never reuse the same key state
3. **Epoch Management**: Ensure signatures are created and verified with correct epoch values
4. **Key Lifetime**: Plan key rotation according to your `num_active_epochs` parameter

## Dependencies

- **leansig**: Core XMSS implementation from Lean Ethereum
- **ethereum_ssz**: SSZ serialization for Ethereum compatibility
- **rand**: Cryptographically secure random number generation
- **serde**: Serialization framework
- **thiserror**: Error handling utilities

## Testing

Run the test suite:

```bash
cargo test
```

The library includes comprehensive tests covering key generation, signing, verification, SSZ serialization, FFI interface correctness, and error conditions.

## License

See [LICENSE](LICENSE) file for details.


## Support

For issues, questions, or contributions, please open an issue on the GitHub repository.
