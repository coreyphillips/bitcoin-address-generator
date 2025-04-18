# bitcoin-address-generator

A Rust library for Bitcoin key derivation and address generation.

[![Crates.io](https://img.shields.io/crates/v/bitcoin-key-derivation.svg)](https://crates.io/crates/bitcoin-key-derivation)
[![Documentation](https://docs.rs/bitcoin-key-derivation/badge.svg)](https://docs.rs/bitcoin-key-derivation)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- 🔐 **Secure Memory Handling**: Sensitive data like private keys and seeds are automatically zeroized when no longer needed
- 🔑 **BIP39 Mnemonic Generation**: Create new mnemonic phrases with various word counts (12, 15, 18, 21, 24 words)
- 💼 **Multiple Address Types**:
    - Legacy addresses (P2PKH) via BIP44
    - Nested SegWit addresses (P2SH-WPKH) via BIP49
    - Native SegWit addresses (P2WPKH) via BIP84
    - Taproot addresses (P2TR) via BIP86
- 🌐 **Network Support**: Works with Bitcoin mainnet, testnet, regtest, and signet
- 🛠️ **Script Hash Calculation**: Calculate script hashes for Bitcoin addresses (compatible with Electrum servers)
- 📋 **Private Key Export**: Derive private keys in WIF format
- 🧩 **BIP32 HD Wallet**: Supports custom derivation paths
- 📚 **Multi-language Support**: Generate mnemonics in different languages

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
bitcoin-address-generator = "0.1.0"
```

## Usage Examples

### Generate a New Mnemonic Phrase

```rust
use bitcoin_address_generator::{generate_mnemonic, WordCount};
use bip39::Language;

fn main() {
    // Generate a default 12-word mnemonic in English
    let mnemonic = generate_mnemonic(None, None).unwrap();
    println!("Generated mnemonic: {}", mnemonic);
    
    // Generate a 24-word mnemonic in English
    let mnemonic = generate_mnemonic(Some(WordCount::Words24), None).unwrap();
    println!("24-word mnemonic: {}", mnemonic);
    
    // Generate a 12-word mnemonic in Japanese
    let mnemonic = generate_mnemonic(None, Some(Language::Japanese)).unwrap();
    println!("Japanese mnemonic: {}", mnemonic);
}
```

### Derive Different Address Types from a Mnemonic

```rust
use bitcoin_address_generator::derive_bitcoin_address;
use bitcoin::Network;

fn main() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    // Derive a Legacy (P2PKH) address
    let p2pkh_addr = derive_bitcoin_address(
        mnemonic,
        Some("m/44'/0'/0'/0/0"),
        Some(Network::Bitcoin),
        None
    ).unwrap();
    println!("Legacy address: {}", p2pkh_addr.address);
    
    // Derive a Nested SegWit (P2SH-WPKH) address
    let p2sh_wpkh_addr = derive_bitcoin_address(
        mnemonic,
        Some("m/49'/0'/0'/0/0"),
        Some(Network::Bitcoin),
        None
    ).unwrap();
    println!("Nested SegWit address: {}", p2sh_wpkh_addr.address);
    
    // Derive a Native SegWit (P2WPKH) address
    let p2wpkh_addr = derive_bitcoin_address(
        mnemonic,
        Some("m/84'/0'/0'/0/0"),
        Some(Network::Bitcoin),
        None
    ).unwrap();
    println!("Native SegWit address: {}", p2wpkh_addr.address);
    
    // Derive a Taproot (P2TR) address
    let p2tr_addr = derive_bitcoin_address(
        mnemonic,
        Some("m/86'/0'/0'/0/0"),
        Some(Network::Bitcoin),
        None
    ).unwrap();
    println!("Taproot address: {}", p2tr_addr.address);
    
    // Derive a testnet address
    let testnet_addr = derive_bitcoin_address(
        mnemonic,
        Some("m/84'/1'/0'/0/0"),
        Some(Network::Testnet),
        None
    ).unwrap();
    println!("Testnet address: {}", testnet_addr.address);
}
```

### Derive Multiple Addresses at Once
```rust
use bitcoin_address_generator::derive_bitcoin_addresses;
use bitcoin::Network;

fn main() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    // Derive 5 consecutive receiving addresses (m/84'/0'/0'/0/0 through m/84'/0'/0'/0/4)
    let receive_addresses = derive_bitcoin_addresses(
        mnemonic,
        Some("m/84'/0'/0'"),  // Base path up to account level
        Some(Network::Bitcoin),
        None,                  // No BIP39 passphrase
        Some(false),           // Receiving addresses (false = receiving, true = change)
        Some(0),               // Start index
        Some(5)                // Number of addresses to generate
    ).unwrap();
    
    println!("Generated {} receiving addresses:", receive_addresses.addresses.len());
    for (i, addr) in receive_addresses.addresses.iter().enumerate() {
        println!("Address {}: {} (path: {})", i, addr.address, addr.path);
    }
    
    // Derive 3 change addresses (m/84'/0'/0'/1/0 through m/84'/0'/0'/1/2)
    let change_addresses = derive_bitcoin_addresses(
        mnemonic,
        Some("m/84'/0'/0'"),  // Base path up to account level
        Some(Network::Bitcoin),
        None,                  // No BIP39 passphrase
        Some(true),            // Change addresses (false = receiving, true = change)
        Some(0),               // Start index
        Some(3)                // Number of addresses to generate
    ).unwrap();
    
    println!("\nGenerated {} change addresses:", change_addresses.addresses.len());
    for (i, addr) in change_addresses.addresses.iter().enumerate() {
        println!("Change Address {}: {} (path: {})", i, addr.address, addr.path);
    }
    
    // You can also start from a specific index
    let custom_range = derive_bitcoin_addresses(
        mnemonic,
        Some("m/84'/0'/0'"),
        Some(Network::Bitcoin),
        None,
        Some(false),
        Some(10),              // Start from index 10
        Some(2)                // Generate 2 addresses
    ).unwrap();
    
    println!("\nCustom range addresses:");
    for addr in custom_range.addresses.iter() {
        println!("{} (path: {})", addr.address, addr.path);
    }
}
```

### Calculate a Script Hash for an Address

```rust
use bitcoin_address_generator::calculate_script_hash;
use bitcoin::Network;

fn main() {
    // Calculate script hash for a P2PKH address
    let script_hash = calculate_script_hash(
        "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
        Some(Network::Bitcoin)
    ).unwrap();
    println!("Script hash: {}", script_hash);
    
    // This can be used with Electrum servers for transaction history
}
```

### Derive a Private Key in WIF Format

```rust
use bitcoin_address_generator::derive_private_key;
use bitcoin::Network;

fn main() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    // Derive private key for a specific derivation path
    let private_key = derive_private_key(
        mnemonic,
        Some("m/84'/0'/0'/0/0"),
        Some(Network::Bitcoin),
        None
    ).unwrap();
    println!("Private key (WIF): {}", private_key);
}
```

### Using a BIP39 Passphrase (Optional Extra Security)

```rust
use bitcoin_address_generator::derive_bitcoin_address;
use bitcoin::Network;

fn main() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let passphrase = "my secret passphrase";
    
    // Derive address with a BIP39 passphrase
    let addr = derive_bitcoin_address(
        mnemonic,
        Some("m/84'/0'/0'/0/0"),
        Some(Network::Bitcoin),
        Some(passphrase)
    ).unwrap();
    println!("Address with passphrase: {}", addr.address);
    println!("Public key: {}", addr.public_key);
}
```

## API Documentation

### Main Functions

#### `generate_mnemonic(word_count: Option<WordCount>, language: Option<Language>) -> Result<String, DerivationError>`

Generates a new BIP39 mnemonic phrase.

- `word_count`: Optional. Number of words (12, 15, 18, 21, or 24). Defaults to 12.
- `language`: Optional. Mnemonic language. Defaults to English.
- Returns: The mnemonic phrase as a string, or an error.

#### `derive_bitcoin_address(mnemonic_phrase: &str, derivation_path_str: Option<&str>, network: Option<Network>, bip39_passphrase: Option<&str>) -> Result<GetAddressResponse, DerivationError>`

Derives a Bitcoin address from a mnemonic phrase.

- `mnemonic_phrase`: The BIP39 mnemonic phrase.
- `derivation_path_str`: Optional. BIP32 derivation path. Defaults to "m/84'/0'/0'/0/0".
- `network`: Optional. Bitcoin network. Defaults to Bitcoin mainnet.
- `bip39_passphrase`: Optional. BIP39 passphrase. Defaults to empty string.
- Returns: A `GetAddressResponse` containing address, derivation path, and public key, or an error.

#### `derive_bitcoin_addresses(mnemonic_phrase: &str, derivation_path_str: Option<&str>, network: Option<Network>, bip39_passphrase: Option<&str>, is_change: Option<bool>, start_index: Option<u32>, count: Option<u32>) -> Result<GetAddressesResponse, DerivationError>`

Derives multiple Bitcoin addresses from a single mnemonic by iterating through a range of indices.

- `mnemonic_phrase`: The BIP39 mnemonic phrase.
- `derivation_path_str`: Optional. Base path up to the account level (e.g., "m/84'/0'/0'"). Defaults to "m/84'/0'/0'".
- `network`: Optional. Bitcoin network. Defaults to Bitcoin mainnet.
- `bip39_passphrase`: Optional. BIP39 passphrase. Defaults to empty string.
- `is_change`: Optional. Whether to derive change addresses (true) or receiving addresses (false). Defaults to false.
- `start_index`: Optional. Starting index for address derivation. Defaults to 0.
- `count`: Optional. Number of addresses to generate. Defaults to 1.
  Returns: A `GetAddressesResponse` containing a collection of addresses, or an error.

#### `calculate_script_hash(address: &str, network: Option<Network>) -> Result<String, DerivationError>`

Calculates a script hash for a Bitcoin address.

- `address`: The Bitcoin address.
- `network`: Optional. Bitcoin network. Defaults to Bitcoin mainnet.
- Returns: The script hash as a hex string, or an error.

#### `derive_private_key(mnemonic_phrase: &str, derivation_path_str: Option<&str>, network: Option<Network>, bip39_passphrase: Option<&str>) -> Result<String, DerivationError>`

Derives a private key in WIF format.

- `mnemonic_phrase`: The BIP39 mnemonic phrase.
- `derivation_path_str`: Optional. BIP32 derivation path. Defaults to "m/84'/0'/0'/0/0".
- `network`: Optional. Bitcoin network. Defaults to Bitcoin mainnet.
- `bip39_passphrase`: Optional. BIP39 passphrase. Defaults to empty string.
- Returns: The private key in WIF format, or an error.

### Data Structures

#### `GetAddressResponse`

Holds the result of address derivation.

```rust
pub struct GetAddressResponse {
    pub address: String,
    pub path: String,
    pub public_key: String,
}
```

#### `GetAddressesResponse`

Holds the result of multiple address derivation.

```rust
pub struct GetAddressesResponse {
    pub addresses: Vec<GetAddressResponse>,
}
```

#### `WordCount`

Enum representing the possible number of words in a mnemonic phrase.

```rust
pub enum WordCount {
    Words12 = 12,
    Words15 = 15,
    Words18 = 18,
    Words21 = 21,
    Words24 = 24,
}
```

#### `DerivationError`

Error type for key derivation operations.

## Security Considerations

1. **Protecting Private Keys**: This library uses the `zeroize` crate to automatically clear sensitive data from memory when it's no longer needed.

2. **Mnemonic Phrases**: Treat mnemonic phrases with the same level of security as private keys. They should never be stored unencrypted or shared.

3. **BIP39 Passphrases**: Using a BIP39 passphrase adds an extra layer of security, but also means you must remember both the mnemonic and the passphrase to recover your wallet.

4. **Network Validation**: The library validates that the derivation path's coin type matches the requested network to prevent address derivation on the wrong network.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request


Run tests and show logs

```rust
cargo test -- --nocapture
```

Run a specific test

```rust
cargo test <test_name> -- --nocapture
cargo test test_generate_mnemonic -- --nocapture
```