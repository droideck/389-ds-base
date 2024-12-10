#![deny(warnings)]
#[macro_use]
extern crate slapi_r_plugin;
use base64;
use openssl::{hash::MessageDigest, pkcs5::pbkdf2_hmac, rand::rand_bytes};
use slapi_r_plugin::prelude::*;
use std::fmt::Write;
use once_cell::sync::Lazy;
use std::sync::RwLock;
use std::convert::TryInto;
use std::os::raw::c_char;

const DEFAULT_PBKDF2_ROUNDS: usize = 10_000;
const MIN_PBKDF2_ROUNDS: usize = 10_000;
const MAX_PBKDF2_ROUNDS: usize = 1_000_000;

const PBKDF2_ROUNDS_ATTR: &str = "nsslapd-pwdPBKDF2Rounds";
static PBKDF2_ROUNDS: Lazy<RwLock<usize>> = Lazy::new(|| RwLock::new(DEFAULT_PBKDF2_ROUNDS));

const PBKDF2_SALT_LEN: usize = 24;
const PBKDF2_SHA1_EXTRACT: usize = 20;
const PBKDF2_SHA256_EXTRACT: usize = 32;
const PBKDF2_SHA512_EXTRACT: usize = 64;

struct PwdChanCrypto;

// OpenLDAP based their PBKDF2 implementation on passlib from python, that uses a
// non-standard base64 altchar set and padding that is not supported by
// anything else in the world. To manage this, we only ever encode to base64 with
// no pad but we have to remap ab64 to b64. This function allows b64 standard with
// padding to pass, and remaps ab64 to b64 standard with padding.
macro_rules! ab64_to_b64 {
    ($ab64:expr) => {{
        let mut s = $ab64.replace(".", "+");
        match s.len() & 3 {
            0 => {
                // Do nothing
            }
            1 => {
                // One is invalid, do nothing, we'll error in base64
            }
            2 => s.push_str("=="),
            3 => s.push_str("="),
            _ => unreachable!(),
        }
        s
    }};
}

// Create a module for each plugin type to avoid name conflicts
mod pbkdf2_default {
    use super::*;
    
    pub struct PwdChanPbkdf2;
    slapi_r_plugin_hooks!(pwdchan_pbkdf2, PwdChanPbkdf2);
    
    impl super::Pbkdf2Plugin for PwdChanPbkdf2 {
        fn digest_type() -> MessageDigest { MessageDigest::sha1() }
        fn scheme_name() -> &'static str { "PBKDF2" }
    }
}

mod pbkdf2_sha1 {
    use super::*;
    
    pub struct PwdChanPbkdf2Sha1;
    slapi_r_plugin_hooks!(pwdchan_pbkdf2_sha1, PwdChanPbkdf2Sha1);
    
    impl super::Pbkdf2Plugin for PwdChanPbkdf2Sha1 {
        fn digest_type() -> MessageDigest { MessageDigest::sha1() }
        fn scheme_name() -> &'static str { "PBKDF2-SHA1" }
    }
}

mod pbkdf2_sha256 {
    use super::*;
    
    pub struct PwdChanPbkdf2Sha256;
    slapi_r_plugin_hooks!(pwdchan_pbkdf2_sha256, PwdChanPbkdf2Sha256);
    
    impl super::Pbkdf2Plugin for PwdChanPbkdf2Sha256 {
        fn digest_type() -> MessageDigest { MessageDigest::sha256() }
        fn scheme_name() -> &'static str { "PBKDF2-SHA256" }
    }
}

mod pbkdf2_sha512 {
    use super::*;
    
    pub struct PwdChanPbkdf2Sha512;
    slapi_r_plugin_hooks!(pwdchan_pbkdf2_sha512, PwdChanPbkdf2Sha512);
    
    impl super::Pbkdf2Plugin for PwdChanPbkdf2Sha512 {
        fn digest_type() -> MessageDigest { MessageDigest::sha512() }
        fn scheme_name() -> &'static str { "PBKDF2-SHA512" }
    }
}

// Common trait for PBKDF2 functionality
trait Pbkdf2Plugin {
    fn digest_type() -> MessageDigest;
    fn scheme_name() -> &'static str;
}

// Implement common plugin functionality
macro_rules! impl_slapi_pbkdf2_plugin {
    ($plugin_type:ty) => {
        impl SlapiPlugin3 for $plugin_type {
            type TaskData = ();

            fn start(pb: &mut PblockRef) -> Result<(), PluginError> {
                log_error!(ErrorLevel::Trace, "{} plugin start", Self::scheme_name());
                PwdChanCrypto::handle_pbkdf2_rounds_config(pb)?;
                Ok(())
            }

            fn close(_pb: &mut PblockRef) -> Result<(), PluginError> {
                log_error!(ErrorLevel::Trace, "{} plugin close", Self::scheme_name());
                Ok(())
            }

            fn has_pwd_storage() -> bool { 
                true 
            }

            fn pwd_scheme_name() -> &'static str {
                Self::scheme_name()
            }

            fn pwd_storage_encrypt(cleartext: &str) -> Result<String, PluginError> {
                PwdChanCrypto::pbkdf2_encrypt(cleartext, Self::digest_type())
            }

            fn pwd_storage_compare(cleartext: &str, encrypted: &str) -> Result<bool, PluginError> {
                PwdChanCrypto::pbkdf2_compare(cleartext, encrypted, Self::digest_type())
            }
        }
    };
}

// Apply the implementation to all plugin types
impl_slapi_pbkdf2_plugin!(pbkdf2_default::PwdChanPbkdf2);
impl_slapi_pbkdf2_plugin!(pbkdf2_sha1::PwdChanPbkdf2Sha1);
impl_slapi_pbkdf2_plugin!(pbkdf2_sha256::PwdChanPbkdf2Sha256);
impl_slapi_pbkdf2_plugin!(pbkdf2_sha512::PwdChanPbkdf2Sha512);

impl PwdChanCrypto {
    #[inline(always)]
    fn pbkdf2_decompose(encrypted: &str) -> Result<(usize, Vec<u8>, Vec<u8>), PluginError> {
        let mut part_iter = encrypted.split('$');

        let iter = part_iter
            .next()
            .ok_or(PluginError::MissingValue)
            .and_then(|iter_str| {
                usize::from_str_radix(iter_str, 10).map_err(|e| {
                    log_error!(ErrorLevel::Error, "Invalid Integer {} -> {:?}", iter_str, e);
                    PluginError::InvalidStrToInt
                })
            })?;

        let salt = part_iter
            .next()
            .ok_or(PluginError::MissingValue)
            .and_then(|ab64| {
                let s = ab64_to_b64!(ab64);
                base64::decode_config(&s, base64::STANDARD.decode_allow_trailing_bits(true))
                    .map_err(|e| {
                        log_error!(ErrorLevel::Error, "Invalid Base 64 {} -> {:?}", s, e);
                        PluginError::InvalidBase64
                    })
            })?;

        let hash = part_iter
            .next()
            .ok_or(PluginError::MissingValue)
            .and_then(|ab64| {
                let s = ab64_to_b64!(ab64);
                base64::decode_config(&s, base64::STANDARD.decode_allow_trailing_bits(true))
                    .map_err(|e| {
                        log_error!(ErrorLevel::Error, "Invalid Base 64 {} -> {:?}", s, e);
                        PluginError::InvalidBase64
                    })
            })?;

        Ok((iter, salt, hash))
    }

    fn pbkdf2_compare(
        cleartext: &str,
        encrypted: &str,
        digest: MessageDigest,
    ) -> Result<bool, PluginError> {
        let (iter, salt, hash_expected) = Self::pbkdf2_decompose(encrypted).map_err(|e| {
            // This means our DB content is flawed.
            log_error!(ErrorLevel::Error, "invalid hashed pw -> {:?}", e);
            e
        })?;
        // Need to pre-alloc the space as as_mut_slice can't resize.
        let mut hash_input: Vec<u8> = (0..hash_expected.len()).map(|_| 0).collect();

        pbkdf2_hmac(
            cleartext.as_bytes(),
            &salt,
            iter,
            digest,
            hash_input.as_mut_slice(),
        )
        .map_err(|e| {
            log_error!(ErrorLevel::Error, "OpenSSL Error -> {:?}", e);
            PluginError::OpenSSL
        })
        .map(|()| hash_input == hash_expected)
    }

    fn pbkdf2_encrypt(cleartext: &str, digest: MessageDigest) -> Result<String, PluginError> {
        let (hash_length, str_length, header) = if digest == MessageDigest::sha1() {
            (PBKDF2_SHA1_EXTRACT, 80, "{PBKDF2-SHA1}")
        } else if digest == MessageDigest::sha256() {
            (PBKDF2_SHA256_EXTRACT, 100, "{PBKDF2-SHA256}")
        } else if digest == MessageDigest::sha512() {
            (PBKDF2_SHA512_EXTRACT, 140, "{PBKDF2-SHA512}")
        } else {
            return Err(PluginError::Unknown);
        };

        // generate salt
        let mut salt: Vec<u8> = (0..PBKDF2_SALT_LEN).map(|_| 0).collect();
        rand_bytes(salt.as_mut_slice()).map_err(|e| {
            log_error!(ErrorLevel::Error, "OpenSSL Error -> {:?}", e);
            PluginError::OpenSSL
        })?;

        let mut hash_input: Vec<u8> = (0..hash_length).map(|_| 0).collect();

        let rounds = Self::get_pbkdf2_rounds()?;

        pbkdf2_hmac(
            cleartext.as_bytes(),
            &salt,
            rounds,
            digest,
            hash_input.as_mut_slice(),
        )
        .map_err(|e| {
            log_error!(ErrorLevel::Error, "OpenSSL Error -> {:?}", e);
            PluginError::OpenSSL
        })?;

        let mut output = String::with_capacity(str_length);
        // Write the header
        output.push_str(header);
        // The iter + delim
        write!(&mut output, "{}$", rounds).map_err(|e| {
            log_error!(ErrorLevel::Error, "Format Error -> {:?}", e);
            PluginError::Format
        })?;
        // the base64 salt
        base64::encode_config_buf(&salt, base64::STANDARD, &mut output);
        // Push the delim
        output.push('$');
        // Finally the base64 hash
        base64::encode_config_buf(&hash_input, base64::STANDARD, &mut output);
        // Return it
        Ok(output)
    }

    pub fn handle_pbkdf2_rounds_config(pb: &mut PblockRef) -> Result<(), PluginError> {
        let mut rounds = DEFAULT_PBKDF2_ROUNDS;
        let mut source = "default";

        // Try to get the entry from the parameter block
        let entry = pb.get_op_add_entryref()
            .map_err(|_| PluginError::InvalidConfiguration)?;

        // Check if the rounds attribute exists and get its value
        if let Some(value_array) = entry.get_attr(PBKDF2_ROUNDS_ATTR) {
            if let Some(value) = value_array.first() {
                let rounds_str: String = value
                    .as_ref()
                    .try_into()
                    .map_err(|_| {
                        log_error!(
                            ErrorLevel::Error,
                            "Failed to parse {} value",
                            PBKDF2_ROUNDS_ATTR
                        );
                        PluginError::InvalidConfiguration
                    })?;

                rounds = rounds_str.parse::<usize>().map_err(|e| {
                    log_error!(
                        ErrorLevel::Error,
                        "Invalid PBKDF2 rounds value '{}': {}",
                        rounds_str,
                        e
                    );
                    PluginError::InvalidConfiguration
                })?;
                source = "configuration";
            }
        }

        // Use the existing set_pbkdf2_rounds function to validate and set the rounds
        Self::set_pbkdf2_rounds(rounds)?;
        
        log_error!(
            ErrorLevel::Plugin,
            "handle_pbkdf2_rounds_config -> PBKDF2 rounds set to {} from {}",
            rounds,
            source
        );
        Ok(())
    }

    pub fn set_pbkdf2_rounds(rounds: usize) -> Result<(), PluginError> {
        if rounds < MIN_PBKDF2_ROUNDS || rounds > MAX_PBKDF2_ROUNDS {
            log_error!(
                ErrorLevel::Error,
                "Invalid PBKDF2 rounds {}, must be between {} and {}",
                rounds,
                MIN_PBKDF2_ROUNDS,
                MAX_PBKDF2_ROUNDS
            );
            return Err(PluginError::InvalidConfiguration);
        }

        match PBKDF2_ROUNDS.write() {
            Ok(mut rounds_guard) => {
                *rounds_guard = rounds;
                Ok(())
            }
            Err(e) => {
                log_error!(
                    ErrorLevel::Error,
                    "Failed to acquire write lock for PBKDF2 rounds: {}",
                    e
                );
                Err(PluginError::LockError)
            }
        }
    }

    fn get_pbkdf2_rounds() -> Result<usize, PluginError> {
        match PBKDF2_ROUNDS.read() {
            Ok(rounds_guard) => Ok(*rounds_guard),
            Err(e) => {
                log_error!(
                    ErrorLevel::Error,
                    "Failed to acquire read lock for PBKDF2 rounds: {}",
                    e
                );
                Err(PluginError::LockError)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PwdChanCrypto;

    struct TestPbkdf2Sha1;
    struct TestPbkdf2Sha256;
    struct TestPbkdf2Sha512;

    impl Pbkdf2Plugin for TestPbkdf2Sha1 {
        fn digest_type() -> MessageDigest { MessageDigest::sha1() }
        fn scheme_suffix() -> &'static str { "-SHA1" }
    }

    impl Pbkdf2Plugin for TestPbkdf2Sha256 {
        fn digest_type() -> MessageDigest { MessageDigest::sha256() }
        fn scheme_suffix() -> &'static str { "-SHA256" }
    }

    impl Pbkdf2Plugin for TestPbkdf2Sha512 {
        fn digest_type() -> MessageDigest { MessageDigest::sha512() }
        fn scheme_suffix() -> &'static str { "-SHA512" }
    }

    /*
     * '{PBKDF2}10000$IlfapjA351LuDSwYC0IQ8Q$saHqQTuYnjJN/tmAndT.8mJt.6w'
     * '{PBKDF2-SHA1}10000$ZBEH6B07rgQpJSikyvMU2w$TAA03a5IYkz1QlPsbJKvUsTqNV'
     * '{PBKDF2-SHA256}10000$henZGfPWw79Cs8ORDeVNrQ$1dTJy73v6n3bnTmTZFghxHXHLsAzKaAy8SksDfZBPIw'
     * '{PBKDF2-SHA512}10000$Je1Uw19Bfv5lArzZ6V3EPw$g4T/1sqBUYWl9o93MVnyQ/8zKGSkPbKaXXsT8WmysXQJhWy8MRP2JFudSL.N9RklQYgDPxPjnfum/F2f/TrppA'
     * '{ARGON2}$argon2id$v=19$m=65536,t=2,p=1$IyTQMsvzB2JHDiWx8fq7Ew$VhYOA7AL0kbRXI5g2kOyyp8St1epkNj7WZyUY4pAIQQ'
     */

    #[test]
    fn test_pbkdf2_rounds_configuration() {
        // Test valid rounds configuration
        assert!(PwdChanCrypto::set_pbkdf2_rounds(15000).is_ok());
        assert_eq!(PwdChanCrypto::get_pbkdf2_rounds().unwrap(), 15000);
    }

    #[test]
    fn test_pbkdf2_rounds_limits() {
        // Test maximum rounds
        assert!(matches!(
            PwdChanCrypto::set_pbkdf2_rounds(MAX_PBKDF2_ROUNDS + 1),
            Err(PluginError::InvalidConfiguration)
        ));

        // Test valid minimum
        assert!(PwdChanCrypto::set_pbkdf2_rounds(MIN_PBKDF2_ROUNDS).is_ok());

        // Test valid maximum
        assert!(PwdChanCrypto::set_pbkdf2_rounds(MAX_PBKDF2_ROUNDS).is_ok());

        // Test invalid rounds - too low
        assert!(matches!(
            PwdChanCrypto::set_pbkdf2_rounds(5000),
            Err(PluginError::InvalidConfiguration)
        ));

        // Test invalid rounds - too high
        assert!(matches!(
            PwdChanCrypto::set_pbkdf2_rounds(2_000_000),
            Err(PluginError::InvalidConfiguration)
        ));
    }

    #[test]
    fn test_pbkdf2_encrypt_with_rounds() {
        // Set a specific number of rounds
        PwdChanCrypto::set_pbkdf2_rounds(15000).unwrap();

        // Test each hash type
        let test_password = "test_password";

        // Test using generic functions through traits
        for (plugin_type, header) in [
            (TestPbkdf2Sha1::digest_type(), "{PBKDF2-SHA1}"),
            (TestPbkdf2Sha256::digest_type(), "{PBKDF2-SHA256}"),
            (TestPbkdf2Sha512::digest_type(), "{PBKDF2-SHA512}")
        ] {
            let result = PwdChanCrypto::pbkdf2_encrypt(test_password, plugin_type).unwrap();
            assert!(result.contains("15000$"));
            
            let encrypted = result.replace(header, "");
            assert!(PwdChanCrypto::pbkdf2_compare(
                test_password,
                &encrypted,
                plugin_type
            ).unwrap());
        }
    }

    #[test]
    fn test_pbkdf2_decompose() {
        let valid_hash = "10000$salt123$hash456";
        let result = PwdChanCrypto::pbkdf2_decompose(valid_hash);
        assert!(result.is_ok());
        let (iter, salt, hash) = result.unwrap();
        assert_eq!(iter, 10000);

        // Test invalid format
        let invalid_hash = "invalid";
        assert!(PwdChanCrypto::pbkdf2_decompose(invalid_hash).is_err());
    }

    #[test]
    fn pwdchan_pbkdf2_sha1_basic() {
        let encrypted = "10000$IlfapjA351LuDSwYC0IQ8Q$saHqQTuYnjJN/tmAndT.8mJt.6w";
        assert!(PwdChanCrypto::pbkdf2_compare("password", encrypted, MessageDigest::sha1()) == Ok(true));
        assert!(PwdChanCrypto::pbkdf2_compare("password!", encrypted, MessageDigest::sha1()) == Ok(false));
        assert!(PwdChanCrypto::pbkdf2_compare("incorrect", encrypted, MessageDigest::sha1()) == Ok(false));

        let encrypted = "10000$ZBEH6B07rgQpJSikyvMU2w$TAA03a5IYkz1QlPsbJKvUsTqNV";
        assert!(PwdChanCrypto::pbkdf2_compare("password", encrypted, MessageDigest::sha1()) == Ok(true));
        assert!(PwdChanCrypto::pbkdf2_compare("password!", encrypted, MessageDigest::sha1()) == Ok(false));

        let test_enc = PwdChanCrypto::pbkdf2_encrypt("password", MessageDigest::sha1()).expect("Failed to hash");
        let test_enc = test_enc.replace("{PBKDF2-SHA1}", "");
        assert!(PwdChanCrypto::pbkdf2_compare("password", &test_enc, MessageDigest::sha1()) == Ok(true));
        assert!(PwdChanCrypto::pbkdf2_compare("password!", &test_enc, MessageDigest::sha1()) == Ok(false));
    }

    #[test]
    fn pwdchan_pbkdf2_sha256_basic() {
        let encrypted = "10000$henZGfPWw79Cs8ORDeVNrQ$1dTJy73v6n3bnTmTZFghxHXHLsAzKaAy8SksDfZBPIw";
        assert!(PwdChanCrypto::pbkdf2_compare("password", encrypted, MessageDigest::sha256()) == Ok(true));
        assert!(PwdChanCrypto::pbkdf2_compare("password!", encrypted, MessageDigest::sha256()) == Ok(false));
        assert!(PwdChanCrypto::pbkdf2_compare("incorrect", encrypted, MessageDigest::sha256()) == Ok(false));

        // This is a django password with their pbkdf2_sha256$ type.
        // "pbkdf2_sha256$36000$xIEozuZVAoYm$uW1b35DUKyhvQAf1mBqMvoBDcqSD06juzyO/nmyV0+w="
        //            salt -->  xIEozuZVAoYm
        // django doesn't base64 it's salt, so you need to base64 it to:
        //                      eElFb3p1WlZBb1lt
        let encrypted = "36000$eElFb3p1WlZBb1lt$uW1b35DUKyhvQAf1mBqMvoBDcqSD06juzyO/nmyV0+w=";
        assert!(
            PwdChanCrypto::pbkdf2_compare("eicieY7ahchaoCh0eeTa", encrypted, MessageDigest::sha256()) == Ok(true)
        );
        assert!(PwdChanCrypto::pbkdf2_compare("password!", encrypted, MessageDigest::sha256()) == Ok(false));

        let test_enc = PwdChanCrypto::pbkdf2_encrypt("password", MessageDigest::sha256()).expect("Failed to hash");
        // Remove the header and check.
        let test_enc = test_enc.replace("{PBKDF2-SHA256}", "");
        assert!(PwdChanCrypto::pbkdf2_compare("password", &test_enc, MessageDigest::sha256()) == Ok(true));
        assert!(PwdChanCrypto::pbkdf2_compare("password!", &test_enc, MessageDigest::sha256()) == Ok(false));
    }

    #[test]
    fn pwdchan_pbkdf2_sha512_basic() {
        let encrypted = "10000$Je1Uw19Bfv5lArzZ6V3EPw$g4T/1sqBUYWl9o93MVnyQ/8zKGSkPbKaXXsT8WmysXQJhWy8MRP2JFudSL.N9RklQYgDPxPjnfum/F2f/TrppA";
        assert!(PwdChanCrypto::pbkdf2_compare("password", encrypted, MessageDigest::sha512()) == Ok(true));
        assert!(PwdChanCrypto::pbkdf2_compare("password!", encrypted, MessageDigest::sha512()) == Ok(false));
        assert!(PwdChanCrypto::pbkdf2_compare("incorrect", encrypted, MessageDigest::sha512()) == Ok(false));

        let test_enc = PwdChanCrypto::pbkdf2_encrypt("password", MessageDigest::sha512()).expect("Failed to hash");
        // Remove the header and check.
        let test_enc = test_enc.replace("{PBKDF2-SHA512}", "");
        assert!(PwdChanCrypto::pbkdf2_compare("password", &test_enc, MessageDigest::sha512()) == Ok(true));
        assert!(PwdChanCrypto::pbkdf2_compare("password!", &test_enc, MessageDigest::sha512()) == Ok(false));
    }
}
