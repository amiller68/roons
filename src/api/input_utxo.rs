use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::blockdata::script::ScriptBuf;
use bitcoin::blockdata::transaction::{OutPoint, TxIn, TxOut};
use bitcoin::key::CompressedPublicKey;
use bitcoin::key::UntweakedPublicKey;
use bitcoin::psbt::{Input as PsbtInput, PsbtSighashType};
use bitcoin::Amount;
use bitcoin::Sequence;
use bitcoin::TapLeafHash;
use bitcoin::XOnlyPublicKey;
use bitcoin::{Txid, Witness};
use serde::Deserialize;

use super::pubkey::Pubkey;

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct InputUtxo {
    /// The txid of the utxo
    pub txid: Txid,
    /// The vout of the output to spend (the index of the output in the transaction)
    pub vout: u32,
    /// the value of the utxo, in satoshi
    pub value: Amount,
    /// the hex of the script_pub_key of the output needed to spend
    pub script_pubkey: ScriptBuf,
}

impl InputUtxo {
    pub fn outpoint(&self) -> OutPoint {
        OutPoint::new(self.txid, self.vout)
    }
    pub fn txin(&self) -> TxIn {
        TxIn {
            previous_output: self.outpoint(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            script_sig: ScriptBuf::default(),
            witness: Witness::default(),
        }
    }
    pub fn script_pubkey(&self) -> ScriptBuf {
        self.script_pubkey.clone()
    }
    pub fn value(&self) -> Amount {
        self.value
    }
    pub fn p2shwpkh_spend(&self, pubkey: &Pubkey) -> PsbtInput {
        let compressed_pubkey = pubkey.compressed_pubkey();
        let derivation_path = pubkey.derivation_path();
        let master_fingerprint = pubkey.master_fingerprint();
        let redeem_script = pubkey.p2shwpkh_redeem_script();

        // Get the spending script_pubkey for the input
        let script_pubkey = self.script_pubkey();
        // And say that just the compressed pubkey is the key
        // that needs to sign
        let bip32_derivation = BTreeMap::from_iter(vec![(
            compressed_pubkey.0,
            (*master_fingerprint, derivation_path.clone()),
        )]);

        PsbtInput {
            witness_utxo: Some(TxOut {
                value: self.value(),
                script_pubkey,
            }),
            redeem_script: Some(redeem_script),
            sighash_type: Some(PsbtSighashType::from_str("SIGHASH_ALL").unwrap()),
            bip32_derivation,
            ..Default::default()
        }
    }
    pub fn p2tr_spend(&self, pubkey: &Pubkey) -> PsbtInput {
        let compressed_pubkey: &CompressedPublicKey = pubkey.compressed_pubkey();
        let derivation_path = pubkey.derivation_path();
        let master_fingerprint = pubkey.master_fingerprint();

        // Get the spending script_pubkey for the input
        let script_pubkey = self.script_pubkey();
        // No redeem script for taproot!
        // Interpret the compressed pubkey as an interal taproot key
        let untweaked_pubkey: UntweakedPublicKey = compressed_pubkey.clone().into();
        let xonly_pubkey = untweaked_pubkey;
        let tap_internal_key = Some(xonly_pubkey);
        // And say that just the compressed pubkey is the key
        // that needs to sign
        // NOTE: this should work for simple p2tr spends, but not for multisig
        //  or other complex scripts
        let tap_key_origins: BTreeMap<
            XOnlyPublicKey,
            (Vec<TapLeafHash>, (Fingerprint, DerivationPath)),
        > = BTreeMap::from_iter(vec![(
            xonly_pubkey,
            (vec![], (*master_fingerprint, derivation_path.clone())),
        )]);

        PsbtInput {
            witness_utxo: Some(TxOut {
                value: self.value(),
                script_pubkey,
            }),
            tap_key_origins,
            tap_internal_key,
            sighash_type: Some(PsbtSighashType::from_str("SIGHASH_ALL").unwrap()),
            ..Default::default()
        }
    }
}

pub fn finalize_p2shwpkh_input(psbt_input: &mut PsbtInput) {
    let mut script_witness = Witness::new();
    // NOTE: this is fine for single signers, but idk about multisig
    for (key, sig) in psbt_input.partial_sigs.iter() {
        let compressed_pubkey: CompressedPublicKey = key.clone().try_into().unwrap();
        script_witness.push(sig.serialize());
        script_witness.push(compressed_pubkey.to_bytes());
    }
    // TODO: unjankify
    let redeem_script = psbt_input.redeem_script.as_ref().unwrap();
    let final_script_sig_hex = format!("16{:x}", redeem_script);
    let final_script_sig = ScriptBuf::from_hex(&final_script_sig_hex).unwrap();

    psbt_input.final_script_witness = Some(script_witness);
    // NOTE: I think this is safe to do, but I'm not sure
    psbt_input.final_script_sig = Some(final_script_sig);
    // And set anything else relevant to default
    psbt_input.partial_sigs = BTreeMap::new();
    psbt_input.sighash_type = None;
    psbt_input.redeem_script = None;
    psbt_input.witness_script = None;
    psbt_input.bip32_derivation = BTreeMap::new();
}

pub fn finalize_p2tr_input(psbt_input: &mut PsbtInput) {
    let script_witness = Witness::p2tr_key_spend(&psbt_input.tap_key_sig.unwrap());
    psbt_input.final_script_witness = Some(script_witness);
    // And set anything else relevant to default
    psbt_input.final_script_sig = None;
    psbt_input.partial_sigs = BTreeMap::new();
    psbt_input.sighash_type = None;
    psbt_input.redeem_script = None;
    psbt_input.witness_script = None;
    psbt_input.bip32_derivation = BTreeMap::new();
    psbt_input.tap_internal_key = None;
    psbt_input.tap_key_origins = BTreeMap::new();
}
