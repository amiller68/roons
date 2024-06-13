use std::env;
use std::str::FromStr;

use bitcoin::bip32::Xpriv;
use bitcoin::Network;
use dotenv::dotenv;

mod api;
mod utils;

use api::input_utxo::{finalize_p2shwpkh_input, finalize_p2tr_input};
use api::mint_runes::{self, MintRunesRequest};

#[tokio::main]
async fn main() {
    dotenv().ok();
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let rpc_url = env::var("BITCOIN_RPC_URL").expect("BITCOIN_RPC_URL must be set");
    let master_xpriv_str = env::var("MASTER_XPRIV").expect("MASTER_XPRIV must be set");
    let network = Network::Bitcoin;

    let master_xpriv = Xpriv::from_str(&master_xpriv_str).unwrap();
    let (_segwit_xpriv, segwit_pubkey) = utils::derive_segwit(&secp, master_xpriv);
    let (_taproot_xpriv, taproot_pubkey) = utils::derive_taproot(&secp, master_xpriv);

    let segwit_address = segwit_pubkey.p2shwpkh_address(network);
    let taproot_address = taproot_pubkey.p2tr_address(&secp, network);
    let fee_rate = utils::get_fee_rate(&rpc_url).await;

    println!("Segwit Address: {}", segwit_address);
    println!("Taproot Address: {}", taproot_address);
    println!("Fee rate: {}", fee_rate);

    let utxos = utils::get_utxos(&segwit_address, &rpc_url).await;

    // Pretty print UTXOs
    for (i, utxo) in utxos.iter().enumerate() {
        println!("UTXO {}", i);
        println!("  txid: {}", utxo.txid());
        println!("  vout: {}", utxo.vout());
        println!("  value: {}", utxo.value());
    }

    let selected_utxo_indices = [1];
    let selected_utxos = utxos
        .iter()
        .enumerate()
        .filter(|(i, _)| selected_utxo_indices.contains(i))
        .map(|(_, utxo)| utxo)
        .collect::<Vec<_>>();
    let rune_block = 840_000;
    let rune_txn = 65;
    let mint_count = 20;
    let input_utxos = utils::get_input_utxos(&selected_utxos, &rpc_url).await;

    let mint_runes_request = MintRunesRequest {
        segwit_pubkey: segwit_pubkey.clone(),
        taproot_pubkey,
        input_utxos: input_utxos.clone(),
        rune_block,
        rune_txn,
        repeats: mint_count,
        fee_rate,
    };

    let response = mint_runes::handler(mint_runes_request).await;

    println!("Response: ");
    println!("  vbytes: {}", response.vbytes);
    println!("  miner_fee: {}", response.miner_fee);

    let segwit_psbt = response.psbts[0].clone();
    let taproot_psbts = &response.psbts[1..];

    println!("Input UTXOs: {:#?}", input_utxos);

    let signed_segwit_raw_txn = segwit_finalize(&secp, master_xpriv, segwit_psbt);
    let signed_taproot_raw_txns = taproot_psbts
        .iter()
        .map(|psbt| taproot_finalize(&secp, master_xpriv, psbt.clone()))
        .collect::<Vec<_>>();

    let broadcast_segwit = utils::broadcast_raw_txn(&signed_segwit_raw_txn, &rpc_url)
        .await
        .expect("broadcast segwit txn");
    println!("Segwit: {:?}", broadcast_segwit);
    for (i, signed_taproot_raw_txn) in signed_taproot_raw_txns.iter().enumerate() {
        let broadcast_taproot = utils::broadcast_raw_txn(signed_taproot_raw_txn, &rpc_url)
            .await
            .expect("broadcast taproot txn");
        println!("Taproot {}: {:?}", i, broadcast_taproot);
    }
}

use bitcoin::consensus;
use bitcoin::secp256k1::{Secp256k1, Signing, Verification};
use bitcoin::Psbt;

fn segwit_finalize<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    master_xpriv: Xpriv,
    mut psbt: Psbt,
) -> String {
    psbt.sign(&master_xpriv, &secp).expect("valid signature");

    psbt.inputs.iter_mut().for_each(|input| {
        finalize_p2shwpkh_input(input);
    });

    // BOOM! Transaction signed and ready to broadcast.
    let psbt_fee = psbt.fee().expect("valid fee");
    let signed_tx = psbt.extract_tx().expect("valid transaction");
    let vbytes = signed_tx.vsize();
    let signed_txid = signed_tx.compute_txid();
    // let huh = signed_tx.compute_wtxid();

    println!(
        "Signed TX @ {:?} | {:?} vB | {:?} fee",
        signed_txid, vbytes, psbt_fee
    );

    consensus::encode::serialize_hex(&signed_tx)
}

fn taproot_finalize<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    master_xpriv: Xpriv,
    mut psbt: Psbt,
) -> String {
    psbt.sign(&master_xpriv, &secp).expect("valid signature");

    psbt.inputs.iter_mut().for_each(|input| {
        finalize_p2tr_input(input);
    });

    // BOOM! Transaction signed and ready to broadcast.
    let psbt_fee = psbt.fee().expect("valid fee");
    let signed_tx = psbt.extract_tx().expect("valid transaction");
    let vbytes = signed_tx.vsize();
    let serialized_signed_tx = consensus::encode::serialize_hex(&signed_tx);
    let signed_txid = signed_tx.compute_txid();

    println!(
        "Signed TX @ {:?} | {:?} vB | {:?} fee",
        signed_txid, vbytes, psbt_fee
    );

    serialized_signed_tx
}
