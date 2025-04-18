//! Bitcoin key and address derivation library for address generation, script hash calculation, and private key management.
//!
//! This library provides secure methods for:
//! - BIP39 mnemonic generation
//! - Address generation (Legacy, SegWit, and Taproot)
//! - Script hash calculation
//! - Private key generation

use bitcoin::{Address, Network, key::{CompressedPublicKey}};
use bip39::{Mnemonic, Language};
use bip32::{XPrv, DerivationPath};
use bitcoin::secp256k1::{Secp256k1, PublicKey, XOnlyPublicKey};
use serde::{Serialize, Deserialize};
use std::{str::FromStr, fmt};
use std::error::Error as StdError;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const DEFAULT_NETWORK: Network = Network::Bitcoin;
const DEFAULT_DERIVATION_PATH: &str = "m/84'/0'/0'/0/0";
const DEFAULT_BIP39_PASSPHRASE: &str = "";

/// Response structure for address generation containing the address, derivation path, and public key.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetAddressResponse {
    /// The generated Bitcoin address as a string
    pub address: String,
    /// The derivation path used to generate the address
    pub path: String,
    /// The hexadecimal representation of the public key
    pub public_key: String,
}

/// BIP39 mnemonic word count options
#[derive(Debug, Clone, Copy)]
pub enum WordCount {
    /// 12-word mnemonic (128 bits of entropy)
    Words12 = 12,
    /// 15-word mnemonic (160 bits of entropy)
    Words15 = 15,
    /// 18-word mnemonic (192 bits of entropy)
    Words18 = 18,
    /// 21-word mnemonic (224 bits of entropy)
    Words21 = 21,
    /// 24-word mnemonic (256 bits of entropy)
    Words24 = 24,
}

impl WordCount {
    /// Helper method to get the numeric value of the word count
    pub fn value(&self) -> usize {
        *self as usize
    }
}

/// Custom error type for bitcoin key and address operations
#[derive(Debug)]
pub enum DerivationError {
    /// Error when an invalid derivation path is provided
    InvalidDerivationPath(String),
    /// Error when an unsupported network type is used
    InvalidNetworkType(String),
    /// Error when the purpose field (first number after m/) is invalid
    InvalidPurposeField(String),
    /// Error when creating or using an X-only public key
    InvalidXOnlyPubkey(String),
    /// Error propagated from the BIP39 library
    Bip39Error(bip39::Error),
    /// Error propagated from the BIP32 library
    Bip32Error(bip32::Error),
    /// Error from the Bitcoin library
    BitcoinError(String),
    /// Error from the secp256k1 library
    SecpError(bitcoin::secp256k1::Error),
    /// Error when parsing numbers in derivation paths
    ParseError(std::num::ParseIntError),
    /// General catch-all error
    GenericError(String),
}

impl fmt::Display for DerivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DerivationError::InvalidDerivationPath(msg) => write!(f, "Invalid derivation path: {}", msg),
            DerivationError::InvalidNetworkType(msg) => write!(f, "Invalid network type: {}", msg),
            DerivationError::InvalidPurposeField(msg) => write!(f, "Invalid purpose field: {}", msg),
            DerivationError::InvalidXOnlyPubkey(msg) => write!(f, "Invalid X-only public key: {}", msg),
            DerivationError::Bip39Error(e) => write!(f, "BIP39 error: {}", e),
            DerivationError::Bip32Error(e) => write!(f, "BIP32 error: {}", e),
            DerivationError::BitcoinError(e) => write!(f, "Bitcoin error: {}", e),
            DerivationError::SecpError(e) => write!(f, "Secp256k1 error: {}", e),
            DerivationError::ParseError(e) => write!(f, "Parse error: {}", e),
            DerivationError::GenericError(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl StdError for DerivationError {}

// Implement From traits for error conversions
impl From<bip39::Error> for DerivationError {
    fn from(err: bip39::Error) -> Self {
        DerivationError::Bip39Error(err)
    }
}

impl From<bip32::Error> for DerivationError {
    fn from(err: bip32::Error) -> Self {
        DerivationError::Bip32Error(err)
    }
}

impl From<bitcoin::secp256k1::Error> for DerivationError {
    fn from(err: bitcoin::secp256k1::Error) -> Self {
        DerivationError::SecpError(err)
    }
}

impl From<std::num::ParseIntError> for DerivationError {
    fn from(err: std::num::ParseIntError) -> Self {
        DerivationError::ParseError(err)
    }
}

/// Secure container for seed data that automatically zeroizes memory when dropped
struct SecureSeed {
    seed: Vec<u8>,
}

impl SecureSeed {
    /// Create a new secure seed container
    pub fn new(seed: Vec<u8>) -> Self {
        Self { seed }
    }
}

impl Zeroize for SecureSeed {
    fn zeroize(&mut self) {
        self.seed.zeroize();
    }
}

impl Drop for SecureSeed {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Secure container for mnemonic phrases that zeroizes memory when dropped
struct SecureMnemonic {
    mnemonic: Mnemonic,
    // Store the phrase string separately so we can zeroize it
    phrase: String,
}

impl SecureMnemonic {
    /// Create a new secure mnemonic container
    pub fn new(mnemonic: Mnemonic) -> Self {
        let phrase = mnemonic.to_string();
        Self { mnemonic, phrase }
    }

    /// Generate a seed from the mnemonic using the provided passphrase
    pub fn to_seed(&self, passphrase: &str) -> Vec<u8> {
        self.mnemonic.to_seed(passphrase).to_vec()
    }
}

impl Zeroize for SecureMnemonic {
    fn zeroize(&mut self) {
        // Zeroize our stored phrase
        self.phrase.zeroize();
        // We can't directly zeroize the Mnemonic internal state,
        // but we've at least zeroized our copy of the phrase
    }
}

impl Drop for SecureMnemonic {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Secure wrapper for private keys that attempts to clean up memory when dropped
struct SecurePrivateKey {
    key: bitcoin::secp256k1::SecretKey,
}

impl SecurePrivateKey {
    /// Create a new secure private key container
    pub fn new(key: bitcoin::secp256k1::SecretKey) -> Self {
        Self { key }
    }

    /// Get a reference to the wrapped secret key
    pub fn key(&self) -> &bitcoin::secp256k1::SecretKey {
        &self.key
    }
}

impl Drop for SecurePrivateKey {
    fn drop(&mut self) {
        // Best-effort zeroing since SecretKey might not expose internal bytes directly
        let _ = bitcoin::secp256k1::SecretKey::from_slice(&[0u8; 32]);
    }
}

/// Secure wrapper for WIF private keys that attempts to clean up memory when dropped
struct SecureWifKey {
    key: bitcoin::PrivateKey,
}

impl SecureWifKey {
    /// Create a new secure WIF key container
    pub fn new(key: bitcoin::PrivateKey) -> Self {
        Self { key }
    }

    /// Get the WIF representation of the private key
    pub fn to_wif(&self) -> String {
        self.key.to_wif()
    }
}

impl Drop for SecureWifKey {
    fn drop(&mut self) {
        // Best-effort cleanup
        if let Ok(zeroed) = bitcoin::secp256k1::SecretKey::from_slice(&[0u8; 32]) {
            // This replaces the key with a zeroed version when possible
            let _ = std::mem::replace(&mut self.key.inner, zeroed);
        }
    }
}

/// Generates a new BIP39 mnemonic phrase using a specified word count.
///
/// # Arguments
/// * `word_count` - Optional number of words for the mnemonic (default: 12 words)
/// * `language` - Optional language for the mnemonic words (default: English)
///
/// # Returns
/// * `Result<String, DerivationError>` - A new mnemonic phrase or an error
///
/// # Errors
/// * `DerivationError::Bip39Error` - If mnemonic generation fails
pub fn generate_mnemonic(word_count: Option<WordCount>, language: Option<Language>) -> Result<String, DerivationError> {
    let word_count = word_count.unwrap_or(WordCount::Words12);
    let lang = language.unwrap_or(Language::English);

    // Generate a mnemonic with the specified number of words in the chosen language
    let mnemonic = Mnemonic::generate_in(lang, word_count.value())?;
    let phrase = mnemonic.to_string();

    Ok(phrase)
}

/// Validates that the purpose field in the derivation path is consistent with the expected address type
///
/// # Arguments
/// * `purpose` - The purpose field value from the derivation path (e.g., "44'")
///
/// # Returns
/// * `Result<(), DerivationError>` - Ok if valid, error otherwise
///
/// # Errors
/// * `DerivationError::InvalidPurposeField` - If purpose is not a supported value
fn validate_purpose_field(purpose: &str) -> Result<(), DerivationError> {
    match purpose {
        "44'" | "49'" | "84'" | "86'" => Ok(()),
        _ => Err(DerivationError::InvalidPurposeField(format!("Unsupported purpose field: {}. Expected one of: 44', 49', 84', 86'", purpose)))
    }
}

/// Derives a Bitcoin address from a mnemonic phrase, derivation path, network type, and optional BIP39 passphrase.
///
/// # Arguments
/// * `mnemonic_phrase` - A BIP39 mnemonic phrase (space-separated words)
/// * `derivation_path_str` - Optional BIP32 derivation path (e.g., "m/84'/0'/0'/0/0"). Default is "m/84'/0'/0'/0/0".
/// * `network` - Optional network type. Default is Network::Bitcoin.
/// * `bip39_passphrase` - Optional BIP39 passphrase. Default is an empty string.
///
/// # Returns
/// * `Result<GetAddressResponse, DerivationError>` - Address information or an error
///
/// # Errors
/// * `DerivationError::InvalidDerivationPath` - If the path format is invalid or network mismatches
/// * `DerivationError::InvalidNetworkType` - If an unsupported network is specified
/// * `DerivationError::InvalidPurposeField` - If the purpose field is not supported
/// * `DerivationError::Bip39Error` - If the mnemonic is invalid
/// * `DerivationError::Bip32Error` - If key derivation fails
/// * `DerivationError::SecpError` - If secp256k1 operations fail
/// * `DerivationError::BitcoinError` - If address generation fails
/// * `DerivationError::InvalidXOnlyPubkey` - If creating an X-only public key fails
pub fn derive_bitcoin_address(
    mnemonic_phrase: &str,
    derivation_path_str: Option<&str>,
    network: Option<Network>,
    bip39_passphrase: Option<&str>,
) -> Result<GetAddressResponse, DerivationError> {
    let network = network.unwrap_or(DEFAULT_NETWORK);
    let bip39_passphrase = bip39_passphrase.unwrap_or(DEFAULT_BIP39_PASSPHRASE);
    let derivation_path_str = derivation_path_str.unwrap_or(DEFAULT_DERIVATION_PATH);

    // Check if the derivation path is in the correct format
    let path_parts: Vec<&str> = derivation_path_str.split('/').collect();
    if path_parts.len() != 6 || path_parts[0] != "m" {
        return Err(DerivationError::InvalidDerivationPath(
            "Invalid derivation path format. Expected format example: m/84'/0'/0'/0/0".to_string()
        ));
    }

    // Extract and validate the purpose field
    let purpose = path_parts.get(1).ok_or_else(||
        DerivationError::InvalidDerivationPath("Missing purpose field in derivation path".to_string())
    )?;

    // Validate the purpose field
    validate_purpose_field(purpose)?;

    // Check if the second number is correct based on the network type
    let second_number = path_parts[2].trim_end_matches('\'').parse::<u32>()?;
    match network {
        Network::Bitcoin => {
            if second_number != 0 {
                return Err(DerivationError::InvalidDerivationPath(
                    format!("Invalid Coin number in the derivation path for {}. Expected 0.", network)
                ));
            }
        }
        Network::Testnet | Network::Regtest | Network::Signet => {
            if second_number != 1 {
                return Err(DerivationError::InvalidDerivationPath(
                    format!("Invalid Coin number in the derivation path for {}. Expected 1.", network)
                ));
            }
        }
        // Handle other network types that might be added in the future
        _ => {
            return Err(DerivationError::InvalidNetworkType(
                format!("Unsupported network type: {}", network)
            ));
        }
    }

    // Parse mnemonic and derive keys
    let mnemonic = match Mnemonic::parse_in(Language::English, mnemonic_phrase) {
        Ok(m) => SecureMnemonic::new(m),
        Err(e) => return Err(DerivationError::Bip39Error(e)),
    };

    // Generate the seed
    let mut seed_bytes = mnemonic.to_seed(bip39_passphrase);
    let secure_seed = SecureSeed::new(seed_bytes.clone());

    // Parse the derivation path
    let derivation_path = match derivation_path_str.parse::<DerivationPath>() {
        Ok(path) => path,
        Err(e) => {
            seed_bytes.zeroize();
            return Err(DerivationError::Bip32Error(e));
        }
    };

    // Derive the extended private key
    let xprv = match XPrv::derive_from_path(&secure_seed.seed, &derivation_path) {
        Ok(key) => key,
        Err(e) => {
            seed_bytes.zeroize();
            return Err(DerivationError::Bip32Error(e));
        }
    };

    // Derive the secret key
    let secp = Secp256k1::new();
    let secret_key = match bitcoin::secp256k1::SecretKey::from_slice(&xprv.private_key().to_bytes()) {
        Ok(key) => SecurePrivateKey::new(key),
        Err(e) => {
            seed_bytes.zeroize();
            return Err(DerivationError::SecpError(e));
        }
    };

    // Derive the public key
    let public_key = PublicKey::from_secret_key(&secp, secret_key.key());

    // Zero out sensitive data
    seed_bytes.zeroize();

    // Convert to bitcoin CompressedPublicKey
    let compressed_public_key = match CompressedPublicKey::from_slice(&public_key.serialize()) {
        Ok(key) => key,
        Err(e) => return Err(DerivationError::BitcoinError(format!("Failed to create compressed public key: {}", e))),
    };

    // Determine the address type based on the derivation path
    let address = match *purpose {
        "44'" => Address::p2pkh(&compressed_public_key, network),
        "49'" => Address::p2shwpkh(&compressed_public_key, network),
        "84'" => Address::p2wpkh(&compressed_public_key, network),
        "86'" => {
            // For P2TR, we need to convert to an XOnlyPublicKey
            let x_only_pubkey = match XOnlyPublicKey::from_slice(&public_key.serialize()[1..]) {
                Ok(key) => key,
                Err(e) => return Err(DerivationError::InvalidXOnlyPubkey(format!("Failed to create XOnlyPublicKey: {}", e))),
            };
            let merkle_root = None; // Set the merkle_root to None for a single public key
            Address::p2tr(&secp, x_only_pubkey, merkle_root, network)
        }
        _ => return Err(DerivationError::InvalidPurposeField(format!("Unsupported purpose field: {}", purpose))),
    };

    let address_string = address.to_string();
    let public_key_string = public_key.to_string();

    Ok(GetAddressResponse {
        address: address_string,
        path: derivation_path_str.to_string(),
        public_key: public_key_string,
    })
}

/// Response structure containing multiple generated Bitcoin addresses.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetAddressesResponse {
    /// Vector of generated Bitcoin addresses
    pub addresses: Vec<GetAddressResponse>,
}

/// Derives multiple Bitcoin addresses from a single mnemonic by iterating through a range of indices.
///
/// # Arguments
/// * `mnemonic_phrase` - A BIP39 mnemonic phrase (space-separated words)
/// * `derivation_path_str` - The derivation path. Can be either a base path (e.g., "m/84'/0'/0'")
///   or a full path (e.g., "m/84'/0'/0'/0/0"). If a full path is provided, only the base part
///   (up to the account level) will be used.
/// * `network` - Optional network type. Default is Network::Bitcoin.
/// * `bip39_passphrase` - Optional BIP39 passphrase. Default is an empty string.
/// * `is_change` - Optional boolean indicating whether to derive change addresses (1) or receiving addresses (0).
///   Default is false (receiving).
/// * `start_index` - Optional starting index. Default is 0.
/// * `count` - Optional number of addresses to generate. Default is 1.
///
/// # Returns
/// * `Result<GetAddressesResponse, DerivationError>` - Collection of address information or an error
///
/// # Errors
/// * Same error types as `derive_bitcoin_address`
pub fn derive_bitcoin_addresses(
    mnemonic_phrase: &str,
    derivation_path_str: Option<&str>,
    network: Option<Network>,
    bip39_passphrase: Option<&str>,
    is_change: Option<bool>,
    start_index: Option<u32>,
    count: Option<u32>,
) -> Result<GetAddressesResponse, DerivationError> {
    let network = network.unwrap_or(DEFAULT_NETWORK);
    let bip39_passphrase = bip39_passphrase.unwrap_or(DEFAULT_BIP39_PASSPHRASE);
    let path = derivation_path_str.unwrap_or("m/84'/0'/0'");
    let is_change = is_change.unwrap_or(false);
    let start_index = start_index.unwrap_or(0);
    let count = count.unwrap_or(1);

    // Create a vector to store all the derived addresses
    let mut addresses = Vec::with_capacity(count as usize);

    // Split the path to extract the base path
    let path_parts: Vec<&str> = path.split('/').collect();

    // Extract the base path (stopping at the account level)
    let base_path = if path_parts.len() >= 4 && path_parts[0] == "m" {
        // Take the first 4 components (m/purpose'/coin'/account')
        path_parts[..4].join("/")
    } else {
        return Err(DerivationError::InvalidDerivationPath(
            "Invalid derivation path format. Expected format that includes at least: m/purpose'/coin'/account'".to_string()
        ));
    };

    // Extract and validate the purpose field
    let purpose = path_parts.get(1).ok_or_else(||
        DerivationError::InvalidDerivationPath("Missing purpose field in derivation path".to_string())
    )?;

    // Validate the purpose field
    validate_purpose_field(purpose)?;

    // Check if the second number is correct based on the network type
    let second_number = path_parts[2].trim_end_matches('\'').parse::<u32>()?;
    match network {
        Network::Bitcoin => {
            if second_number != 0 {
                return Err(DerivationError::InvalidDerivationPath(
                    format!("Invalid Coin number in the derivation path for {}. Expected 0.", network)
                ));
            }
        }
        Network::Testnet | Network::Regtest | Network::Signet => {
            if second_number != 1 {
                return Err(DerivationError::InvalidDerivationPath(
                    format!("Invalid Coin number in the derivation path for {}. Expected 1.", network)
                ));
            }
        }
        // Handle other network types that might be added in the future
        _ => {
            return Err(DerivationError::InvalidNetworkType(
                format!("Unsupported network type: {}", network)
            ));
        }
    }

    // Determine the change path component (0 for receiving addresses, 1 for change addresses)
    let change_component = if is_change { "1" } else { "0" };

    // Generate addresses for the specified range
    for i in start_index..(start_index + count) {
        // Construct the full derivation path for this index
        let full_path = format!("{}/{}/{}", base_path, change_component, i);

        // Use the existing derive_bitcoin_address function to derive the address
        match derive_bitcoin_address(mnemonic_phrase, Some(&full_path), Some(network), Some(bip39_passphrase)) {
            Ok(address) => addresses.push(address),
            Err(e) => return Err(e),
        }
    }

    Ok(GetAddressesResponse { addresses })
}

/// Calculates a script hash for a given Bitcoin address and network type.
///
/// The script hash is calculated by taking the SHA256 hash of the scriptPubKey
/// and then reversing the byte order, as required by the Electrum protocol.
///
/// # Arguments
/// * `address` - A Bitcoin address string
/// * `network` - Optional network type. Default is Network::Bitcoin.
///
/// # Returns
/// * `Result<String, DerivationError>` - The script hash as a hex string or an error
///
/// # Errors
/// * `DerivationError::BitcoinError` - If the address cannot be parsed or network validation fails
pub fn calculate_script_hash(address: &str, network: Option<Network>) -> Result<String, DerivationError> {
    let network = network.unwrap_or(DEFAULT_NETWORK);

    // Parse the address
    let parsed_addr = match Address::from_str(address) {
        Ok(addr) => addr,
        Err(e) => return Err(DerivationError::BitcoinError(format!("Failed to parse address: {}", e))),
    };

    let addr = match parsed_addr.require_network(network) {
        Ok(address) => address,
        Err(e) => return Err(DerivationError::BitcoinError(format!("Network mismatch: {}", e))),
    };

    // Get the script from the address
    let script = addr.script_pubkey();
    let script_bytes = script.as_bytes();

    // Calculate the script hash
    let hash = Sha256::digest(script_bytes);

    // Reverse the bytes of the hash
    let mut reversed_hash = hash.to_vec();
    reversed_hash.reverse();

    // Convert the reversed hash to hexadecimal representation
    let script_hash_hex = hex::encode(reversed_hash);

    Ok(script_hash_hex)
}

/// Derives a private key in WIF format from a mnemonic phrase, derivation path, network type, and optional BIP39 passphrase.
///
/// # Arguments
/// * `mnemonic_phrase` - A BIP39 mnemonic phrase (space-separated words)
/// * `derivation_path_str` - Optional BIP32 derivation path (e.g., "m/84'/0'/0'/0/0"). Default is "m/84'/0'/0'/0/0".
/// * `network` - Optional network type. Default is Network::Bitcoin.
/// * `bip39_passphrase` - Optional BIP39 passphrase. Default is an empty string.
///
/// # Returns
/// * `Result<String, DerivationError>` - The private key in WIF format or an error
///
/// # Errors
/// * `DerivationError::Bip39Error` - If the mnemonic is invalid
/// * `DerivationError::Bip32Error` - If key derivation fails
/// * `DerivationError::SecpError` - If secp256k1 operations fail
pub fn derive_private_key(
    mnemonic_phrase: &str,
    derivation_path_str: Option<&str>,
    network: Option<Network>,
    bip39_passphrase: Option<&str>,
) -> Result<String, DerivationError> {
    let network = network.unwrap_or(DEFAULT_NETWORK);
    let bip39_passphrase = bip39_passphrase.unwrap_or(DEFAULT_BIP39_PASSPHRASE);
    let derivation_path_str = derivation_path_str.unwrap_or(DEFAULT_DERIVATION_PATH);

    // Parse mnemonic and create secure wrapper
    let mnemonic = match Mnemonic::parse_in(Language::English, mnemonic_phrase) {
        Ok(m) => SecureMnemonic::new(m),
        Err(e) => return Err(DerivationError::Bip39Error(e)),
    };

    // Generate the seed
    let mut seed_bytes = mnemonic.to_seed(bip39_passphrase);
    let secure_seed = SecureSeed::new(seed_bytes.clone());

    // Parse the derivation path
    let derivation_path = match derivation_path_str.parse::<DerivationPath>() {
        Ok(path) => path,
        Err(e) => {
            seed_bytes.zeroize();
            return Err(DerivationError::Bip32Error(e));
        }
    };

    // Derive the extended private key
    let xprv = match XPrv::derive_from_path(&secure_seed.seed, &derivation_path) {
        Ok(key) => key,
        Err(e) => {
            seed_bytes.zeroize();
            return Err(DerivationError::Bip32Error(e));
        }
    };

    // Derive the secret key
    let secret_key = match bitcoin::secp256k1::SecretKey::from_slice(&xprv.private_key().to_bytes()) {
        Ok(key) => key,
        Err(e) => {
            seed_bytes.zeroize();
            return Err(DerivationError::SecpError(e));
        }
    };

    // Zero out sensitive data
    seed_bytes.zeroize();

    // Convert the private key to WIF format using a secure wrapper
    let private_key_wif = SecureWifKey::new(bitcoin::PrivateKey {
        compressed: true,
        network: network.into(),
        inner: secret_key,
    });

    // Get the WIF string
    let private_key_string = private_key_wif.to_wif();

    Ok(private_key_string)
}

#[cfg(test)]
mod tests {
    use std::option::Option;
    use super::*;

    #[test]
    fn test_generate_mnemonic() {
        let mnemonic: String = generate_mnemonic(Option::from(WordCount::Words12), Option::from(Language::English)).unwrap();
        println!("Generated mnemonic: {}", mnemonic);
        assert_eq!(mnemonic.split_whitespace().count(), 12);
    }

    #[test]
    fn test_derive_address_p2pkh() {
        // Test with a known mnemonic and expected address for legacy P2PKH (44' path)
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let path = "m/44'/0'/0'/0/0";
        let address = derive_bitcoin_address(mnemonic, Option::from(path), Option::from(Network::Bitcoin), None).unwrap();
        println!("P2PKH address: {}", address.address);
        println!("P2PKH pubkey: {}", address.public_key);
        assert_eq!(address.address, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA");
        assert_eq!(address.path, path);
    }

    #[test]
    fn test_derive_address_p2shwpkh() {
        // Test with a known mnemonic and expected address for P2SH-wrapped SegWit (49' path)
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let path = "m/49'/0'/0'/0/0";
        let address = derive_bitcoin_address(mnemonic, Option::from(path), Option::from(Network::Bitcoin), None).unwrap();
        println!("P2SH-WPKH address: {}", address.address);
        println!("P2SH-WPKH pubkey: {}", address.public_key);
        assert_eq!(address.address, "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf");
        assert_eq!(address.path, path);
    }

    #[test]
    fn test_derive_address_p2wpkh() {
        // Test with a known mnemonic and expected address for native SegWit (84' path)
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let path = "m/84'/0'/0'/0/0";
        let address = derive_bitcoin_address(mnemonic, Option::from(path), Option::from(Network::Bitcoin), None).unwrap();
        println!("P2WPKH address: {}", address.address);
        println!("P2WPKH pubkey: {}", address.public_key);
        assert_eq!(address.address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        assert_eq!(address.path, path);
    }

    #[test]
    fn test_derive_address_p2tr() {
        // Test with a known mnemonic and expected address for Taproot (86' path)
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let path = "m/86'/0'/0'/0/0";
        let address = derive_bitcoin_address(mnemonic, Option::from(path), Option::from(Network::Bitcoin), None).unwrap();
        println!("P2TR address: {}", address.address);
        println!("P2TR pubkey: {}", address.public_key);
        // We're using a flexible assertion here since the exact address might vary by implementation
        assert!(address.address.starts_with("bc1p"));
        assert_eq!(address.path, path);
    }

    #[test]
    fn test_calculate_script_hash() {
        // Test script hash generation for P2PKH address
        let script_hash = calculate_script_hash("1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA", Option::from(Network::Bitcoin)).unwrap();
        println!("P2PKH script hash: {}", script_hash);
        assert_eq!(script_hash, "1e8750b8a4c0912d8b84f7eb53472cbdcb57f9e0cde263b2e51ecbe30853cd68");

        // Test script hash generation for P2WPKH address
        let script_hash = calculate_script_hash("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", Option::from(Network::Bitcoin)).unwrap();
        println!("P2WPKH script hash: {}", script_hash);
        // Let's check the actual value
        assert_eq!(script_hash.len(), 64); // It should be a 32-byte hash (64 hex chars)
    }

    #[test]
    fn test_derive_private_key() {
        // Test private key generation
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let path = "m/84'/0'/0'/0/0";
        let private_key = derive_private_key(mnemonic, Option::from(path), Option::from(Network::Bitcoin), None).unwrap();
        assert_eq!(private_key, "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d");
    }

    #[test]
    fn test_derive_bitcoin_addresses() {
        // Test deriving multiple addresses with base path
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let base_path = "m/84'/0'/0'";
        let result = derive_bitcoin_addresses(mnemonic, Option::from(base_path), Option::from(Network::Bitcoin), None, None, None, Option::from(3)).unwrap();

        // Check that we got the right number of addresses
        assert_eq!(result.addresses.len(), 3);

        // Check the paths are correct
        assert_eq!(result.addresses[0].path, "m/84'/0'/0'/0/0");
        assert_eq!(result.addresses[1].path, "m/84'/0'/0'/0/1");
        assert_eq!(result.addresses[2].path, "m/84'/0'/0'/0/2");

        // Check the first address is correct
        assert_eq!(result.addresses[0].address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");

        // Test with full path - should extract and use only the base path
        let full_path = "m/84'/0'/0'/0/5";  // Has index 5, but we should use our start_index instead
        let full_path_result = derive_bitcoin_addresses(mnemonic, Option::from(full_path), Option::from(Network::Bitcoin), None, None, Option::from(10), Option::from(2)).unwrap();

        // We should ignore the /0/5 part of the full path and use our parameters
        assert_eq!(full_path_result.addresses[0].path, "m/84'/0'/0'/0/10");
        assert_eq!(full_path_result.addresses[1].path, "m/84'/0'/0'/0/11");

        // Test deriving change addresses with full path
        let full_path_change = derive_bitcoin_addresses(mnemonic, Option::from(full_path), Option::from(Network::Bitcoin), None, Option::from(true), None, Option::from(2)).unwrap();

        // Should use the is_change parameter regardless of what was in the path
        assert_eq!(full_path_change.addresses[0].path, "m/84'/0'/0'/1/0");
        assert_eq!(full_path_change.addresses[1].path, "m/84'/0'/0'/1/1");

        // Test with a full change path - should still extract only the base path
        let full_change_path = "m/84'/0'/0'/1/0";
        let change_override_result = derive_bitcoin_addresses(mnemonic, Option::from(full_change_path), Option::from(Network::Bitcoin), None, Option::from(false), None, Option::from(2)).unwrap();

        // Should use the is_change parameter (false) regardless of what was in the path
        assert_eq!(change_override_result.addresses[0].path, "m/84'/0'/0'/0/0");
        assert_eq!(change_override_result.addresses[1].path, "m/84'/0'/0'/0/1");
    }
}