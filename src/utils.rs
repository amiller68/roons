use std::str::FromStr;

use bitcoin::bip32::DerivationPath;
use bitcoin::bip32::Xpriv;
use bitcoin::secp256k1::{Secp256k1, Signing};
use bitcoin::Address;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;

const TAPROOT_DERIVATION_PATH: &str = "m/86'/0'/0'/0/0";
const SEGWIT_DERIVATION_PATH: &str = "m/49'/0'/0'/0/0";

use super::api::input_utxo::InputUtxo;
use super::api::pubkey::Pubkey;

#[derive(Debug, Deserialize)]
pub struct Utxo {
    txid: String,
    vout: u32,
    value: u64,
}

impl Utxo {
    pub fn txid(&self) -> Txid {
        Txid::from_str(&self.txid).unwrap()
    }

    pub fn value(&self) -> bitcoin::Amount {
        bitcoin::Amount::from_sat(self.value)
    }

    pub fn vout(&self) -> u32 {
        self.vout
    }
}

pub fn derive_segwit<C: Signing>(secp: &Secp256k1<C>, master_xpriv: Xpriv) -> (Xpriv, Pubkey) {
    let master_fingerprint = master_xpriv.fingerprint(&secp);
    let derivation_path: DerivationPath = SEGWIT_DERIVATION_PATH.parse().unwrap();
    let child_priv = master_xpriv.derive_priv(secp, &derivation_path).unwrap();
    let compressed_pubkey = child_priv.to_priv().public_key(secp).try_into().unwrap();
    (
        child_priv,
        Pubkey {
            compressed_pubkey,
            derivation_path,
            master_fingerprint,
        },
    )
}

pub fn derive_taproot<C: Signing>(secp: &Secp256k1<C>, master_xpriv: Xpriv) -> (Xpriv, Pubkey) {
    let master_fingerprint = master_xpriv.fingerprint(&secp);
    let derivation_path: DerivationPath = TAPROOT_DERIVATION_PATH.parse().unwrap();
    let child_priv = master_xpriv.derive_priv(secp, &derivation_path).unwrap();
    let compressed_pubkey = child_priv.to_priv().public_key(secp).try_into().unwrap();
    (
        child_priv,
        Pubkey {
            compressed_pubkey,
            derivation_path,
            master_fingerprint,
        },
    )
}

pub async fn get_utxos(segwit_address: &Address, rpc_url: &str) -> Vec<Utxo> {
    let client = Client::new();
    let response = client
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "1.0",
            "id": "curltest",
            "method": "bb_getutxos",
            "params": [segwit_address.to_string(), json!({"confirmed": true})]
        }))
        .send()
        .await
        .unwrap();
    let response_json: serde_json::Value = response.json().await.unwrap();
    let utxo_json = response_json["result"].as_array().unwrap();
    let utxos: Vec<Utxo> = utxo_json
        .iter()
        .map(|utxo| Utxo {
            txid: utxo["txid"].as_str().unwrap().to_string(),
            vout: utxo["vout"].as_u64().unwrap() as u32,
            value: utxo["value"].as_str().unwrap().parse().unwrap(),
        })
        .collect();
    utxos
}

pub async fn get_input_utxos(utxos: &Vec<&Utxo>, rpc_url: &str) -> Vec<InputUtxo> {
    let mut input_utxos = Vec::new();
    for utxo in utxos {
        let script_pubkey = get_script_pubkey(utxo, rpc_url).await;
        let input_utxo = InputUtxo {
            txid: utxo.txid(),
            vout: utxo.vout(),
            value: utxo.value(),
            script_pubkey,
        };
        input_utxos.push(input_utxo);
    }
    input_utxos
}

async fn get_script_pubkey(utxo: &Utxo, rpc_url: &str) -> ScriptBuf {
    let client = Client::new();
    let response = client
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "1.0",
            "id": "curltest",
            "method": "bb_gettxspecific",
            "params": [utxo.txid().to_string()]
        }))
        .send()
        .await
        .unwrap();
    let response_json: serde_json::Value = response.json().await.unwrap();
    let vout_json = response_json["result"]["vout"].as_array().unwrap();
    let script_pubkey_hex = vout_json[utxo.vout() as usize]["scriptPubKey"]["hex"]
        .as_str()
        .unwrap();
    ScriptBuf::from_hex(script_pubkey_hex).unwrap()
}

pub async fn get_fee_rate(rpc_url: &str) -> u64 {
    let client = Client::new();
    let response = client
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "1.0",
            "id": "curltest",
            "method": "estimatesmartfee",
            "params": [1]
        }))
        .send()
        .await
        .unwrap();
    let response_json: serde_json::Value = response.json().await.unwrap();
    let fee_rate_btc_p_kvb = response_json["result"]["feerate"].as_f64().unwrap();
    (fee_rate_btc_p_kvb * 100_000.0) as u64
}

pub async fn broadcast_raw_txn(raw_txn: &str, rpc_url: &str) -> Option<String> {
    use std::{thread, time};

    let client = Client::new();
    let decode_txn = client
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "1.0",
            "id": "curltest",
            "method": "decoderawtransaction",
            "params": [raw_txn]
        }))
        .send()
        .await
        .unwrap();
    /*
    println!(
        "Sending {:#?}",
        decode_txn.json::<serde_json::Value>().await.unwrap()
    );
    */

    let retry = 7;
    let mut txn_id = None;
    for i in 0..retry {
        let response = client
            .post(rpc_url)
            .json(&json!({
                "jsonrpc": "1.0",
                "id": "curltest",
                "method": "sendrawtransaction",
                "params": [raw_txn, 0]
            }))
            .send()
            .await
            .unwrap();
        let response_json: serde_json::Value = response.json().await.unwrap();
        if response_json["error"].is_null() {
            txn_id = Some(response_json["result"].as_str().unwrap().to_string());
            break;
        }
        // Otherwise if the response says bad-txns-inputs-missingorspent
        else if response_json["error"]["message"].as_str().unwrap()
            != "bad-txns-inputs-missingorspent"
        {
            println!("Unrecoverable Error {}: {:?}", i, response_json);
            break;
        }
        // Sleep
        let sleep_time = time::Duration::from_millis(1500 * 2_u64.pow(i));
        println!("Parent txn not found. Retrying in {:?}", sleep_time);
        thread::sleep(sleep_time);
    }
    txn_id
}
