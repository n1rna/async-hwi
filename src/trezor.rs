use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;
use bitcoin::{
    bip32::{DerivationPath, Fingerprint, Xpub},
    psbt::Psbt,
    Network,
};

use crate::{AddressScript, DeviceKind, Error as HWIError, Version, HWI};

pub use trezor_client as api;
use trezor_client::{InputScriptType, TrezorMessage, TrezorResponse};

pub struct Trezor {
    client: Arc<Mutex<trezor_client::Trezor>>,
    network: Network,
    passphrase: String,
}

impl std::fmt::Debug for Trezor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Trezor")
            .field("network", &self.network)
            .finish()
    }
}

impl Trezor {
    pub fn new(client: trezor_client::Trezor, network: Network) -> Self {
        Self {
            client: Arc::new(Mutex::new(client)),
            network,
            passphrase: String::new(),
        }
    }

    pub fn with_passphrase(mut self, passphrase: String) -> Self {
        self.passphrase = passphrase;
        self
    }

    fn client(&self) -> Result<MutexGuard<'_, trezor_client::Trezor>, HWIError> {
        self.client
            .lock()
            .map_err(|_| HWIError::Unexpected("Failed to unlock"))
    }
}

impl From<trezor_client::Trezor> for Trezor {
    fn from(client: trezor_client::Trezor) -> Self {
        Self::new(client, Network::Bitcoin)
    }
}

/// Drive through Trezor interaction requests (button confirmations, passphrase, etc.)
/// until we get a final Ok result or an error.
fn handle_interaction<T, R: TrezorMessage>(
    resp: TrezorResponse<'_, T, R>,
    passphrase: &str,
) -> Result<T, HWIError> {
    match resp {
        TrezorResponse::Ok(t) => Ok(t),
        TrezorResponse::Failure(f) => {
            let msg = f.message().to_string();
            let msg_lower = msg.to_lowercase();
            if msg_lower.contains("cancelled")
                || msg_lower.contains("canceled")
                || msg_lower.contains("rejected")
            {
                Err(HWIError::UserRefused)
            } else if msg.is_empty() {
                Err(HWIError::Device("Unknown device failure".into()))
            } else {
                Err(HWIError::Device(msg))
            }
        }
        TrezorResponse::ButtonRequest(r) => {
            let resp = r.ack().map_err(Into::<HWIError>::into)?;
            handle_interaction(resp, passphrase)
        }
        TrezorResponse::PinMatrixRequest(_) => {
            Err(HWIError::Device("Device is locked (PIN required)".into()))
        }
        TrezorResponse::PassphraseRequest(r) => {
            let resp = r.ack_passphrase(passphrase.into()).map_err(Into::<HWIError>::into)?;
            handle_interaction(resp, passphrase)
        }
    }
}

impl From<trezor_client::Error> for HWIError {
    fn from(e: trezor_client::Error) -> Self {
        match e {
            trezor_client::Error::NoDeviceFound => HWIError::DeviceNotFound,
            _ => HWIError::Device(e.to_string()),
        }
    }
}


#[async_trait]
impl HWI for Trezor {
    fn device_kind(&self) -> DeviceKind {
        DeviceKind::Trezor
    }

    async fn get_version(&self) -> Result<Version, HWIError> {
        let client = self.client()?;
        let features = client
            .features()
            .ok_or_else(|| HWIError::Device("Device not initialized".into()))?;
        let major = features.major_version();
        let minor = features.minor_version();
        let patch = features.patch_version();
        Ok(Version {
            major,
            minor,
            patch,
            prerelease: None,
        })
    }

    async fn get_master_fingerprint(&self) -> Result<Fingerprint, HWIError> {
        let mut client = self.client()?;
        // Get xpub at m/0h to derive the master fingerprint, matching the Python HWI reference.
        let path = "m/0h"
            .parse::<DerivationPath>()
            .map_err(|e| HWIError::Device(e.to_string()))?;
        let resp = client
            .get_public_key(&path, InputScriptType::SPENDADDRESS, self.network, false)
            .map_err(Into::<HWIError>::into)?;
        let xpub = handle_interaction(resp, &self.passphrase)?;
        Ok(xpub.parent_fingerprint)
    }

    async fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<Xpub, HWIError> {
        let mut client = self.client()?;
        // Always use SPENDADDRESS to get standard xpub encoding.
        // Script-type-specific prefixes (zpub, ypub) are not parseable by bitcoin::bip32::Xpub.
        let resp = client
            .get_public_key(path, InputScriptType::SPENDADDRESS, self.network, false)
            .map_err(Into::<HWIError>::into)?;
        handle_interaction(resp, &self.passphrase)
    }

    async fn register_wallet(
        &self,
        _name: &str,
        _policy: &str,
    ) -> Result<Option<[u8; 32]>, HWIError> {
        Ok(None)
    }

    async fn is_wallet_registered(&self, _name: &str, _policy: &str) -> Result<bool, HWIError> {
        Ok(true)
    }

    async fn display_address(&self, script: &AddressScript) -> Result<(), HWIError> {
        match script {
            AddressScript::P2TR(path) => {
                let mut client = self.client()?;
                let resp = client
                    .get_address(path, InputScriptType::SPENDTAPROOT, self.network, true)
                    .map_err(Into::<HWIError>::into)?;
                handle_interaction(resp, &self.passphrase)?;
                Ok(())
            }
            AddressScript::Miniscript { .. } => Err(HWIError::UnimplementedMethod),
        }
    }

    async fn sign_tx(&self, psbt: &mut Psbt) -> Result<(), HWIError> {
        let mut client = self.client()?;

        let resp = client
            .sign_tx(psbt, self.network)
            .map_err(Into::<HWIError>::into)?;
        let mut progress = handle_interaction(resp, &self.passphrase)?;

        let mut signatures: Vec<Option<Vec<u8>>> = vec![None; psbt.inputs.len()];

        loop {
            // Collect any signature provided at this step.
            if let Some((index, sig)) = progress.get_signature() {
                if index < signatures.len() {
                    signatures[index] = Some(sig.to_vec());
                }
            }

            if progress.finished() {
                break;
            }

            let resp = progress
                .ack_psbt(psbt, self.network)
                .map_err(Into::<HWIError>::into)?;
            progress = handle_interaction(resp, &self.passphrase)?;
        }

        // Merge signatures into the PSBT.
        for (i, sig) in signatures.into_iter().enumerate() {
            if let Some(sig_bytes) = sig {
                if psbt.inputs[i].tap_internal_key.is_some() {
                    // Taproot key signature (Schnorr)
                    if let Ok(sig) = bitcoin::taproot::Signature::from_slice(&sig_bytes) {
                        psbt.inputs[i].tap_key_sig = Some(sig);
                    }
                } else {
                    // Legacy/segwit ECDSA signature
                    if let Some(pk) = psbt.inputs[i]
                        .bip32_derivation
                        .keys()
                        .next()
                        .map(|k| bitcoin::PublicKey::new(*k))
                    {
                        if let Ok(sig) = bitcoin::ecdsa::Signature::from_slice(&sig_bytes) {
                            psbt.inputs[i].partial_sigs.insert(pk, sig);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl From<Trezor> for Box<dyn HWI + Send> {
    fn from(s: Trezor) -> Box<dyn HWI + Send> {
        Box::new(s)
    }
}

impl From<Trezor> for Arc<dyn HWI + Sync + Send> {
    fn from(s: Trezor) -> Arc<dyn HWI + Sync + Send> {
        Arc::new(s)
    }
}

/// Check if a HID device is a Trezor.
#[cfg(feature = "hidapi")]
pub fn is_trezor(device_info: &hidapi::DeviceInfo) -> bool {
    const TREZOR_LEGACY_VID: u16 = 0x534C;
    const TREZOR_LEGACY_PID: u16 = 0x0001;
    const TREZOR_MODERN_VID: u16 = 0x1209;
    const TREZOR_MODERN_PID: u16 = 0x53C1;

    let vid = device_info.vendor_id();
    let pid = device_info.product_id();
    (vid == TREZOR_LEGACY_VID && pid == TREZOR_LEGACY_PID)
        || (vid == TREZOR_MODERN_VID && pid == TREZOR_MODERN_PID)
}
