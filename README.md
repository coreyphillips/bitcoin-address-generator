# bitcoin-address-generator

A Rust library for Bitcoin key derivation and address generation.

[![Crates.io](https://img.shields.io/crates/v/bitcoin-address-generator.svg)](https://crates.io/crates/bitcoin-address-generator)
[![Documentation](https://docs.rs/bitcoin-address-generator/badge.svg)](https://docs.rs/bitcoin-address-generator)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Quick Links

### Core Functions
- [`generate_mnemonic`](#generate-a-new-mnemonic-phrase) - Generate new BIP39 mnemonic phrases
- [`derive_bitcoin_address`](#derive-different-address-types-from-a-mnemonic) - Derive a single Bitcoin address
- [`derive_bitcoin_addresses`](#derive-multiple-addresses-at-once) - Derive multiple addresses in batch
- [`calculate_script_hash`](#calculate-a-script-hash-for-an-address) - Calculate script hash for Electrum compatibility
- [`derive_private_key`](#derive-a-private-key-in-wif-format) - Export private keys in WIF format

### BIP39 Mnemonic Utilities
- [`validate_mnemonic`](#validate-a-mnemonic-phrase) - Validate BIP39 mnemonic phrases
- [`is_valid_bip39_word`](#check-if-a-word-is-valid) - Check if a word is in the BIP39 wordlist
- [`get_bip39_suggestions`](#get-word-suggestions) - Get autocomplete suggestions for partial words
- [`get_bip39_wordlist`](#get-the-complete-wordlist) - Access the full BIP39 wordlist
- [`mnemonic_to_entropy`](#convert-mnemonic-to-entropy) - Convert mnemonic to entropy bytes
- [`entropy_to_mnemonic`](#convert-entropy-to-mnemonic) - Convert entropy to mnemonic phrase
- [`mnemonic_to_seed`](#convert-mnemonic-to-seed) - Generate seed from mnemonic with optional passphrase

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

### Validate a Mnemonic Phrase

```rust
use bitcoin_address_generator::validate_mnemonic;

fn main() {
    let valid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    match validate_mnemonic(valid_mnemonic) {
        Ok(()) => println!("Valid mnemonic!"),
        Err(e) => println!("Invalid mnemonic: {:?}", e),
    }

    let invalid_mnemonic = "invalid word sequence";
    match validate_mnemonic(invalid_mnemonic) {
        Ok(()) => println!("Valid mnemonic!"),
        Err(e) => println!("Invalid mnemonic: {:?}", e),
    }
}
```

### Check if a Word is Valid

```rust
use bitcoin_address_generator::is_valid_bip39_word;
use bip39::Language;

fn main() {
    // Check English words (default)
    println!("'abandon' is valid: {}", is_valid_bip39_word("abandon", None));
    println!("'notaword' is valid: {}", is_valid_bip39_word("notaword", None));

    // Check words in other languages
    println!("'abarcar' is valid Spanish: {}",
             is_valid_bip39_word("abarcar", Some(Language::Spanish)));
}
```

### Get Word Suggestions

```rust
use bitcoin_address_generator::get_bip39_suggestions;
use bip39::Language;

fn main() {
    // Get up to 5 suggestions for words starting with "ab"
    let suggestions = get_bip39_suggestions("ab", 5, None);
    println!("Suggestions for 'ab': {:?}", suggestions);
    // Output: ["abandon", "ability", "able", "about", "above"]

    // Get suggestions in Japanese
    let japanese_suggestions = get_bip39_suggestions("あ", 3, Some(Language::Japanese));
    println!("Japanese suggestions: {:?}", japanese_suggestions);
}
```

### Get the Complete Wordlist

```rust
use bitcoin_address_generator::get_bip39_wordlist;
use bip39::Language;

fn main() {
    // Get English wordlist (default)
    let wordlist = get_bip39_wordlist(None);
    println!("Total words: {}", wordlist.len()); // 2048
    println!("First word: {}", wordlist[0]);
    println!("Last word: {}", wordlist[wordlist.len() - 1]);

    // Get wordlist for other languages
    let french_wordlist = get_bip39_wordlist(Some(Language::French));
    println!("French wordlist size: {}", french_wordlist.len());
}
```

### Convert Mnemonic to Entropy

```rust
use bitcoin_address_generator::mnemonic_to_entropy;

fn main() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    match mnemonic_to_entropy(mnemonic) {
        Ok(entropy) => {
            println!("Entropy length: {} bytes", entropy.len()); // 16 bytes for 12 words
            println!("Entropy hex: {}", hex::encode(&entropy));
            // Important: Securely clear entropy when done
            // Consider using zeroize::Zeroize trait
        }
        Err(e) => println!("Error: {:?}", e),
    }
}
```

### Convert Entropy to Mnemonic

```rust
use bitcoin_address_generator::entropy_to_mnemonic;
use bip39::Language;

fn main() {
    // Create 128-bit entropy (will generate 12-word mnemonic)
    let entropy = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    // Convert to English mnemonic
    let mnemonic = entropy_to_mnemonic(&entropy, None).unwrap();
    println!("Mnemonic: {}", mnemonic);

    // Convert to Japanese mnemonic
    let japanese_mnemonic = entropy_to_mnemonic(&entropy, Some(Language::Japanese)).unwrap();
    println!("Japanese: {}", japanese_mnemonic);
}
```

### Convert Mnemonic to Seed

```rust
use bitcoin_address_generator::mnemonic_to_seed;

fn main() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Without passphrase
    let seed = mnemonic_to_seed(mnemonic, None).unwrap();
    println!("Seed length: {} bytes", seed.len()); // Always 64 bytes
    println!("Seed hex: {}", hex::encode(&seed));

    // With passphrase
    let seed_with_pass = mnemonic_to_seed(mnemonic, Some("my passphrase")).unwrap();
    println!("Seed with passphrase: {}", hex::encode(&seed_with_pass));

    // Important: Seeds are sensitive! Clear from memory when done
    // Consider using zeroize::Zeroize trait
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

### BIP39 Utility Functions

#### `validate_mnemonic(mnemonic_phrase: &str) -> Result<(), DerivationError>`

Validates a BIP39 mnemonic phrase.

- `mnemonic_phrase`: The mnemonic phrase to validate.
- Returns: Ok if valid, error otherwise.

#### `is_valid_bip39_word(word: &str, language: Option<Language>) -> bool`

Checks if a word is valid in the BIP39 wordlist.

- `word`: The word to check.
- `language`: Optional. Language to check against. Defaults to English.
- Returns: true if the word is valid, false otherwise.

#### `get_bip39_suggestions(partial_word: &str, limit: usize, language: Option<Language>) -> Vec<String>`

Gets word suggestions for partial input (autocomplete).

- `partial_word`: The partial word to get suggestions for.
- `limit`: Maximum number of suggestions to return.
- `language`: Optional. Language for suggestions. Defaults to English.
- Returns: A sorted list of suggested words.

#### `get_bip39_wordlist(language: Option<Language>) -> Vec<String>`

Gets the full BIP39 wordlist for the specified language.

- `language`: Optional. Language for the wordlist. Defaults to English.
- Returns: The complete wordlist (2048 words).

#### `mnemonic_to_entropy(mnemonic_phrase: &str) -> Result<Vec<u8>, DerivationError>`

Converts a mnemonic phrase to entropy bytes.

- `mnemonic_phrase`: The mnemonic phrase to convert.
- Returns: The entropy bytes or an error.
- **Security**: The returned entropy is sensitive cryptographic material and should be securely cleared from memory when no longer needed.

#### `entropy_to_mnemonic(entropy: &[u8], language: Option<Language>) -> Result<String, DerivationError>`

Converts entropy bytes to a mnemonic phrase.

- `entropy`: The entropy bytes to convert.
- `language`: Optional. Language for the mnemonic. Defaults to English.
- Returns: The mnemonic phrase or an error.

#### `mnemonic_to_seed(mnemonic_phrase: &str, passphrase: Option<&str>) -> Result<Vec<u8>, DerivationError>`

Converts a mnemonic phrase to a seed with optional passphrase.

- `mnemonic_phrase`: The mnemonic phrase to convert.
- `passphrase`: Optional. BIP39 passphrase. Defaults to empty string.
- Returns: The seed bytes (always 64 bytes) or an error.
- **Security**: The returned seed is highly sensitive cryptographic material and should be securely cleared from memory when no longer needed.

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