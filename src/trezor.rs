use std::sync::Mutex;

use bitcoin::{
    bip32::{DerivationPath, Fingerprint, Xpub},
    hashes::{sha256d, Hash},
    psbt::{Input as PsbtInput, Psbt},
    Network,
};
pub use trezor_client as api;

use trezor_client::{
    client::handle_interaction,
    protos::{
        self,
        tx_ack::{
            transaction_type::{TxInputType, TxOutputBinType, TxOutputType},
            TransactionType,
        },
        OutputScriptType,
    },
    InputScriptType, Trezor as TrezorClient,
};

use async_trait::async_trait;

use crate::{AddressScript, DeviceKind, Error as HWIError, HWI};

fn to_rev_bytes(hash: &sha256d::Hash) -> [u8; 32] {
    let mut bytes = hash.to_byte_array();
    bytes.reverse();
    bytes
}

fn from_rev_bytes(rev_bytes: &[u8]) -> Option<sha256d::Hash> {
    let mut bytes = rev_bytes.to_vec();
    bytes.reverse();
    sha256d::Hash::from_slice(&bytes).ok()
}

fn psbt_find_input(psbt: &Psbt, txid: sha256d::Hash) -> Result<&PsbtInput, TrezorError> {
    let idx = psbt
        .unsigned_tx
        .input
        .iter()
        .position(|tx| *tx.previous_output.txid.as_raw_hash() == txid)
        .ok_or(TrezorError::UnknownTxid)?;
    psbt.inputs.get(idx).ok_or(TrezorError::InvalidIndex(idx))
}

fn address_from_script(
    script: &bitcoin::Script,
    network: Network,
) -> Option<bitcoin::Address> {
    bitcoin::Address::from_script(script, bitcoin::params::Params::new(network)).ok()
}

fn ack_input(
    req: &protos::TxRequest,
    psbt: &Psbt,
) -> Result<protos::TxAck, TrezorError> {
    let input_index = req.details.request_index() as usize;

    let input = if req.details.has_tx_hash() {
        let req_hash = from_rev_bytes(req.details.tx_hash()).ok_or(TrezorError::MalformedRequest)?;
        let psbt_input = psbt_find_input(psbt, req_hash)?;
        let tx = psbt_input
            .non_witness_utxo
            .as_ref()
            .ok_or(TrezorError::MissingInputTx)?;
        tx.input.get(input_index).ok_or(TrezorError::InvalidIndex(input_index))?
    } else {
        psbt.unsigned_tx
            .input
            .get(input_index)
            .ok_or(TrezorError::InvalidIndex(input_index))?
    };

    let mut data_input = TxInputType::new();
    data_input.set_prev_hash(
        to_rev_bytes(input.previous_output.txid.as_raw_hash()).to_vec(),
    );
    data_input.set_prev_index(input.previous_output.vout);
    data_input.set_script_sig(input.script_sig.to_bytes());
    data_input.set_sequence(input.sequence.to_consensus_u32());

    if !req.details.has_tx_hash() {
        let psbt_input = psbt
            .inputs
            .get(input_index)
            .ok_or(TrezorError::InvalidIndex(input_index))?;

        let txout = if let Some(ref txout) = psbt_input.witness_utxo {
            txout
        } else if let Some(ref tx) = psbt_input.non_witness_utxo {
            tx.output
                .get(input.previous_output.vout as usize)
                .ok_or(TrezorError::InvalidIndex(input.previous_output.vout as usize))?
        } else {
            return Err(TrezorError::MissingUtxo(input_index));
        };

        let script_pubkey = &txout.script_pubkey;

        data_input.set_amount(txout.value.to_sat());

        if script_pubkey.is_p2tr() {
            // Try keypath first (internal key, no leaf hashes)
            let keypath = psbt_input.tap_internal_key.as_ref().and_then(|ik| {
                psbt_input
                    .tap_key_origins
                    .get(ik)
                    .filter(|(leaf_hashes, _)| leaf_hashes.is_empty())
                    .map(|(_, (_, path))| path)
            });

            // Fall back to script path (key with leaf hashes)
            let script_path = if keypath.is_none() {
                psbt_input
                    .tap_key_origins
                    .iter()
                    .find(|(_, (leaf_hashes, _))| !leaf_hashes.is_empty())
                    .map(|(_, (_, (_, path)))| path)
            } else {
                None
            };

            if let Some(path) = keypath.or(script_path) {
                data_input.address_n =
                    path.as_ref().iter().map(|i| u32::from(*i)).collect();
                data_input.set_script_type(InputScriptType::SPENDTAPROOT);
            } else {
                data_input.set_script_type(InputScriptType::EXTERNAL);
                data_input.set_script_pubkey(script_pubkey.to_bytes());
            }
        } else {
            if psbt_input.bip32_derivation.len() == 1 {
                let (_, (_, path)) = psbt_input.bip32_derivation.iter().next().unwrap();
                data_input.address_n = path.as_ref().iter().map(|i| u32::from(*i)).collect();
            }
            let script_type = if script_pubkey.is_p2pkh() {
                InputScriptType::SPENDADDRESS
            } else if script_pubkey.is_p2wpkh() || script_pubkey.is_p2wsh() {
                InputScriptType::SPENDWITNESS
            } else if script_pubkey.is_p2sh() && psbt_input.witness_script.is_some() {
                InputScriptType::SPENDP2SHWITNESS
            } else {
                InputScriptType::EXTERNAL
            };
            data_input.set_script_type(script_type);
        }

        data_input.set_amount(txout.value.to_sat());
    }

    let mut txdata = TransactionType::new();
    txdata.inputs.push(data_input);
    let mut msg = protos::TxAck::new();
    msg.tx = protobuf::MessageField::some(txdata);
    Ok(msg)
}

fn ack_output(
    req: &protos::TxRequest,
    psbt: &Psbt,
    network: Network,
) -> Result<protos::TxAck, TrezorError> {
    let mut txdata = TransactionType::new();

    if req.details.has_tx_hash() {
        let output_index = req.details.request_index() as usize;
        let req_hash = from_rev_bytes(req.details.tx_hash()).ok_or(TrezorError::MalformedRequest)?;
        let psbt_input = psbt_find_input(psbt, req_hash)?;
        let output = if let Some(ref tx) = psbt_input.non_witness_utxo {
            tx.output
                .get(output_index)
                .ok_or(TrezorError::InvalidIndex(output_index))?
        } else if let Some(ref utxo) = psbt_input.witness_utxo {
            utxo
        } else {
            return Err(TrezorError::MissingInputTx);
        };

        let mut bin_output = TxOutputBinType::new();
        bin_output.set_amount(output.value.to_sat());
        bin_output.set_script_pubkey(output.script_pubkey.to_bytes());
        txdata.bin_outputs.push(bin_output);
    } else {
        let output_index = req.details.request_index() as usize;
        let output = psbt
            .unsigned_tx
            .output
            .get(output_index)
            .ok_or(TrezorError::InvalidIndex(output_index))?;
        let psbt_output = psbt
            .outputs
            .get(output_index)
            .ok_or(TrezorError::InvalidIndex(output_index))?;

        let mut data_output = TxOutputType::new();
        data_output.set_amount(output.value.to_sat());

        let script_pubkey = &output.script_pubkey;

        if script_pubkey.is_p2tr() {
            let keypath = if let Some(ref internal_key) = psbt_output.tap_internal_key {
                psbt_output
                    .tap_key_origins
                    .get(internal_key)
                    .map(|(_, (_, path))| path)
            } else if psbt_output.tap_key_origins.len() == 1 {
                psbt_output
                    .tap_key_origins
                    .values()
                    .next()
                    .map(|(_, (_, path))| path)
            } else {
                None
            };
            if let Some(path) = keypath {
                data_output.address_n =
                    path.as_ref().iter().map(|i| u32::from(*i)).collect();
                data_output.set_script_type(OutputScriptType::PAYTOTAPROOT);
            } else {
                data_output.set_script_type(OutputScriptType::PAYTOADDRESS);
                if let Some(addr) = address_from_script(script_pubkey, network) {
                    data_output.set_address(addr.to_string());
                }
            }
        } else {
            data_output.set_script_type(OutputScriptType::PAYTOADDRESS);
            if let Some(addr) = address_from_script(script_pubkey, network) {
                data_output.set_address(addr.to_string());
            }

            if psbt_output.bip32_derivation.len() == 1 {
                let (_, (_, path)) = psbt_output.bip32_derivation.iter().next().unwrap();
                data_output.address_n = path.as_ref().iter().map(|i| u32::from(*i)).collect();
                if script_pubkey.is_op_return() {
                    data_output.set_script_type(OutputScriptType::PAYTOOPRETURN);
                    data_output.set_op_return_data(script_pubkey.as_bytes()[1..].to_vec());
                } else if psbt_output.witness_script.is_some() {
                    if psbt_output.redeem_script.is_some() {
                        data_output.set_script_type(OutputScriptType::PAYTOP2SHWITNESS);
                    } else {
                        data_output.set_script_type(OutputScriptType::PAYTOWITNESS);
                    }
                }
            }
        }

        txdata.outputs.push(data_output);
    }

    let mut msg = protos::TxAck::new();
    msg.tx = protobuf::MessageField::some(txdata);
    Ok(msg)
}

fn ack_meta(req: &protos::TxRequest, psbt: &Psbt) -> Result<protos::TxAck, TrezorError> {
    let tx = if req.details.has_tx_hash() {
        let req_hash = from_rev_bytes(req.details.tx_hash()).ok_or(TrezorError::MalformedRequest)?;
        let psbt_input = psbt_find_input(psbt, req_hash)?;
        psbt_input
            .non_witness_utxo
            .as_ref()
            .map(|tx| tx as &bitcoin::Transaction)
            .ok_or(TrezorError::MissingInputTx)?
    } else {
        &psbt.unsigned_tx
    };

    let mut txdata = TransactionType::new();
    txdata.set_version(tx.version.0 as u32);
    txdata.set_lock_time(tx.lock_time.to_consensus_u32());
    txdata.set_inputs_cnt(tx.input.len() as u32);
    txdata.set_outputs_cnt(tx.output.len() as u32);

    let mut msg = protos::TxAck::new();
    msg.tx = protobuf::MessageField::some(txdata);
    Ok(msg)
}

fn apply_signature(psbt: &mut Psbt, index: usize, sig_bytes: &[u8]) -> Result<(), TrezorError> {
    let input = psbt.inputs.get_mut(index).ok_or(TrezorError::InvalidIndex(index))?;
    let is_taproot = input
        .witness_utxo
        .as_ref()
        .map(|o| o.script_pubkey.is_p2tr())
        .unwrap_or(false);

    if is_taproot {
        // Trezor firmware always produces keypath signatures for SPENDTAPROOT
        let sig = bitcoin::taproot::Signature::from_slice(sig_bytes)
            .map_err(|e| TrezorError::Device(format!("Invalid Schnorr signature: {}", e)))?;
        input.tap_key_sig = Some(sig);
    } else {
        let pubkey = input.bip32_derivation.keys().next().copied();
        if let Some(pk) = pubkey {
            if let Ok(sig) = bitcoin::ecdsa::Signature::from_slice(sig_bytes) {
                input.partial_sigs.insert(pk.into(), sig);
            }
        }
    }
    Ok(())
}

fn sign_psbt(client: &mut TrezorClient, psbt: &mut Psbt, network: Network) -> Result<(), TrezorError> {
    use trezor_client::protos::tx_request::RequestType as TxRequestType;

    let mut progress = handle_interaction(
        client
            .sign_tx(psbt, network)
            .map_err(|e| TrezorError::Device(e.to_string()))?,
    )
    .map_err(|e| TrezorError::Device(e.to_string()))?;

    loop {
        if let Some((index, sig_bytes)) = progress.get_signature() {
            apply_signature(psbt, index, sig_bytes.to_vec().as_slice())?;
        }

        if progress.finished() {
            break;
        }

        let tx_req = progress.tx_request();
        let ack = match tx_req.request_type() {
            TxRequestType::TXINPUT => ack_input(tx_req, psbt)?,
            TxRequestType::TXOUTPUT => ack_output(tx_req, psbt, network)?,
            TxRequestType::TXMETA => ack_meta(tx_req, psbt)?,
            TxRequestType::TXFINISHED => break,
            _ => return Err(TrezorError::Device("unhandled TxRequest type".to_owned())),
        };

        progress = handle_interaction(
            progress
                .ack_msg(ack)
                .map_err(|e| TrezorError::Device(e.to_string()))?,
        )
        .map_err(|e| TrezorError::Device(e.to_string()))?;
    }

    Ok(())
}

pub struct Trezor {
    client: Mutex<TrezorClient>,
    network: Network,
}

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

impl std::fmt::Debug for Trezor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Trezor")
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

impl Trezor {
    pub fn new(client: TrezorClient, network: Network) -> Self {
        Self {
            client: Mutex::new(client),
            network,
        }
    }

    pub fn enumerate() -> Vec<trezor_client::AvailableDevice> {
        trezor_client::find_devices(false)
    }
}

#[async_trait]
impl HWI for Trezor {
    fn device_kind(&self) -> DeviceKind {
        DeviceKind::Trezor
    }

    async fn get_version(&self) -> Result<crate::Version, HWIError> {
        let client = self.client.lock().map_err(|_| HWIError::DeviceDisconnected)?;
        let features = client.features().ok_or(HWIError::DeviceNotFound)?;
        let major = features.major_version() as u32;
        let minor = features.minor_version() as u32;
        let patch = features.patch_version() as u32;
        Ok(crate::Version {
            major,
            minor,
            patch,
            prerelease: None,
        })
    }

    async fn get_master_fingerprint(&self) -> Result<Fingerprint, HWIError> {
        let mut client = self.client.lock().map_err(|_| HWIError::DeviceDisconnected)?;
        let path: DerivationPath = "m".parse().unwrap();
        let resp = client
            .get_public_key(&path, InputScriptType::SPENDADDRESS, self.network, false)
            .map_err(|e| HWIError::Device(e.to_string()))?;
        let xpub = handle_interaction(resp).map_err(|e| HWIError::Device(e.to_string()))?;
        Ok(xpub.fingerprint())
    }

    async fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<Xpub, HWIError> {
        let mut client = self.client.lock().map_err(|_| HWIError::DeviceDisconnected)?;
        // Use SPENDADDRESS to get standard xpub/tpub version bytes.
        // Script-type-specific types (SPENDWITNESS, etc.) cause Trezor to
        // return SLIP-0132 encoded keys (zpub/vpub/ypub/upub) which the
        // bitcoin crate's Xpub parser does not recognize.
        let resp = client
            .get_public_key(path, InputScriptType::SPENDADDRESS, self.network, false)
            .map_err(|e| HWIError::Device(e.to_string()))?;
        handle_interaction(resp).map_err(|e| HWIError::Device(e.to_string()))
    }

    async fn register_wallet(
        &self,
        _name: &str,
        _policy: &str,
    ) -> Result<Option<[u8; 32]>, HWIError> {
        Err(HWIError::UnimplementedMethod)
    }

    async fn is_wallet_registered(
        &self,
        _name: &str,
        _policy: &str,
    ) -> Result<bool, HWIError> {
        Err(HWIError::UnimplementedMethod)
    }

    async fn display_address(&self, _script: &AddressScript) -> Result<(), HWIError> {
        Err(HWIError::UnimplementedMethod)
    }

    async fn sign_tx(&self, psbt: &mut Psbt) -> Result<(), HWIError> {
        let mut client = self.client.lock().map_err(|_| HWIError::DeviceDisconnected)?;
        sign_psbt(&mut client, psbt, self.network).map_err(Into::into)
    }
}

fn script_type_for_path(path: &DerivationPath) -> InputScriptType {
    let purpose = path.into_iter().next().map(|c| u32::from(*c));
    match purpose {
        Some(0x8000_0056) => InputScriptType::SPENDTAPROOT,
        Some(0x8000_0054) => InputScriptType::SPENDWITNESS,
        Some(0x8000_0031) => InputScriptType::SPENDP2SHWITNESS,
        Some(0x8000_002c) => InputScriptType::SPENDADDRESS,
        _ => InputScriptType::SPENDADDRESS,
    }
}

#[derive(Debug)]
pub enum TrezorError {
    DeviceNotFound,
    UnsupportedNetwork,
    MalformedRequest,
    MissingInputTx,
    MissingUtxo(usize),
    UnknownTxid,
    InvalidIndex(usize),
    Device(String),
}

impl std::fmt::Display for TrezorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeviceNotFound => write!(f, "Trezor device not found"),
            Self::UnsupportedNetwork => write!(f, "Unsupported network"),
            Self::MalformedRequest => write!(f, "Malformed TxRequest from device"),
            Self::MissingInputTx => write!(f, "PSBT input missing non_witness_utxo"),
            Self::MissingUtxo(i) => write!(f, "No UTXO data for PSBT input {}", i),
            Self::UnknownTxid => write!(f, "Device referenced unknown txid"),
            Self::InvalidIndex(i) => write!(f, "Invalid index: {}", i),
            Self::Device(e) => write!(f, "Trezor error: {}", e),
        }
    }
}

impl std::error::Error for TrezorError {}

impl From<TrezorError> for HWIError {
    fn from(e: TrezorError) -> HWIError {
        match e {
            TrezorError::DeviceNotFound => HWIError::DeviceNotFound,
            TrezorError::Device(e) => HWIError::Device(e),
            other => HWIError::Device(other.to_string()),
        }
    }
}
