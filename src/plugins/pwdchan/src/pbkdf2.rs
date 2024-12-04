use crate::PwdChanCrypto;
use slapi_r_plugin::prelude::*;
use std::os::raw::c_char;
use std::convert::TryInto;

/*
 *                    /---- plugin ident
 *                    |          /---- Struct name.
 *                    V          V
 */
slapi_r_plugin_hooks!(pwdchan_pbkdf2, PwdChanPbkdf2);

// PBKDF2 == PBKDF2-SHA1
struct PwdChanPbkdf2;

impl SlapiPlugin3 for PwdChanPbkdf2 {
    // We require a newer rust for default associated types.
    type TaskData = ();

    fn start(pb: &mut PblockRef) -> Result<(), PluginError> {
        log_error!(ErrorLevel::Trace, "PBKDF2 plugin starting");

        // Handle initial configuration
        Self::handle_pbkdf2_rounds_config(pb)?;

        log_error!(
            ErrorLevel::Info,
            "PBKDF2 plugin started successfully"
        );
        Ok(())
    }

    fn close(_pb: &mut PblockRef) -> Result<(), PluginError> {
        log_error!(ErrorLevel::Trace, "PBKDF2 plugin closing");
        Ok(())
    }

    fn has_pwd_storage() -> bool {
        true
    }

    fn pwd_scheme_name() -> &'static str {
        "PBKDF2"
    }

    fn pwd_storage_encrypt(cleartext: &str) -> Result<String, PluginError> {
        PwdChanCrypto::pbkdf2_sha1_encrypt(cleartext)
    }

    fn pwd_storage_compare(cleartext: &str, encrypted: &str) -> Result<bool, PluginError> {
        PwdChanCrypto::pbkdf2_sha1_compare(cleartext, encrypted)
    }

    fn handle_pbkdf2_rounds_config(pb: &mut PblockRef) -> Result<(), PluginError> {
        const PBKDF2_ROUNDS_ATTR: &str = "passwordPBKDF2Rounds";

        if let Ok(entry) = pb.get_op_add_entryref() {
            if let Some(value_array) = entry.get_attr(PBKDF2_ROUNDS_ATTR) {
                if let Some(value) = value_array.first() {
                    let rounds_str: String = value
                        .as_ref()
                        .try_into()
                        .map_err(|_| {
                            log_error!(
                                ErrorLevel::Error,
                                "Failed to parse passwordPBKDF2Rounds value"
                            );
                            PluginError::InvalidConfiguration
                        })?;

                    let rounds = rounds_str.parse::<usize>().map_err(|e| {
                        log_error!(
                            ErrorLevel::Error,
                            "Invalid PBKDF2 rounds value '{}': {}",
                            rounds_str,
                            e
                        );
                        PluginError::InvalidConfiguration
                    })?;

                    PwdChanCrypto::set_pbkdf2_rounds(rounds)?;
                    
                    log_error!(
                        ErrorLevel::Info,
                        "PBKDF2 rounds configured to {} from entry attribute",
                        rounds
                    );
                }
            }
        }
        Ok(())
    }
}
