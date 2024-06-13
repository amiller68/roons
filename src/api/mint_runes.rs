use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::blockdata::transaction::{OutPoint, Transaction, TxIn, TxOut};
use bitcoin::blockdata::{
    opcodes,
    script::{self, ScriptBuf},
};
use bitcoin::constants::MAX_SCRIPT_ELEMENT_SIZE;
use bitcoin::key::CompressedPublicKey;
use bitcoin::psbt::{Input as PsbtInput, Psbt};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::TapSighashType;
use bitcoin::{Address, Amount, Sequence, Witness};
use bitcoin::{FeeRate, Network};

use serde::{Deserialize, Serialize};

use super::constants::{P2SHWPKH_DUST_LIMIT, P2TR_DUST_LIMIT};
use super::input_utxo::{finalize_p2shwpkh_input, finalize_p2tr_input, InputUtxo};
use super::pubkey::Pubkey;

pub enum RunesTag {
    Mint,
}

impl From<RunesTag> for u128 {
    fn from(tag: RunesTag) -> u128 {
        match tag {
            RunesTag::Mint => 20,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintRunesRequest {
    // NOTE: you need to pass valid derivation path + master fingerprint here
    /// The public key of the segwit spender
    pub segwit_pubkey: Pubkey,
    /// the public key of the taproot recipient
    // NOTE: you need to pass a valid derivation path + master fingerprint here
    pub taproot_pubkey: Pubkey,
    /// The rune block height
    pub rune_block: u64,
    /// The txn index in the block
    pub rune_txn: u32,
    /// The number of mints to create
    pub repeats: u32,
    /// Input Utxos
    pub input_utxos: Vec<InputUtxo>,
    /// the tax value remitted to the tax_compressed_pubkey, in satoshi
    pub tax_value: u64,
    /// the tax compressed public key
    pub tax_compressed_pubkey: CompressedPublicKey,
    /// the fee rate in satoshi per vbyte
    pub fee_rate: u64,
}

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MintRunesResponse {
    /// The serialized transaction
    pub psbts: Vec<Psbt>,
    /// The estimated miner fee, in satoshi
    pub miner_fee: u64,
    /// The estimated change amount, in satoshi
    pub change_amount: u64,
    /// The combined total vbytes of all raw_txns
    pub vbytes: u64,
}

pub async fn handler(req: MintRunesRequest) -> MintRunesResponse {
    let secp = Secp256k1::new();
    let network = Network::Bitcoin;

    let segwit_address = req.segwit_pubkey.p2shwpkh_address(network);

    let taproot_address = req.taproot_pubkey.p2tr_address(&secp, network);

    let input_utxos = &req.input_utxos;

    let tax_value = Amount::from_sat(req.tax_value);

    let tax_compressed_pubkey = req.tax_compressed_pubkey;
    let tax_segwit_address = Address::p2shwpkh(&tax_compressed_pubkey, Network::Bitcoin);

    let fee_rate = match FeeRate::from_sat_per_vb(req.fee_rate) {
        Some(fee_rate) => fee_rate,
        None => panic!("Invalid fee rate (sat / vB)"),
    };

    // Sum up the input utxos to get the total input value
    let total_input_value = input_utxos.iter().map(|utxo| utxo.value).sum::<Amount>();
    // Extract how many levels of minting we need to do
    let mint_count = req.repeats;
    // Determine the minimum total output value
    let total_output_value = tax_value + P2TR_DUST_LIMIT * mint_count as u64;
    // Determine the right stone for this rune
    let mint_rune_script_pubkey = build_mint_rune_script_pubkey(req.rune_block, req.rune_txn);

    /*
     * First we're going to determine how large our
     *  txns are gonna be by forming some dummy psbts
     * */

    let dummy_secp = secp.clone();
    let dummy_xpriv = Xpriv::new_master(Network::Bitcoin, &[1u8; 32]).unwrap();
    let dummy_pubkey = Pubkey {
        compressed_pubkey: Xpub::from_priv(&dummy_secp, &dummy_xpriv).to_pub(),
        master_fingerprint: dummy_xpriv.fingerprint(&dummy_secp),
        derivation_path: DerivationPath::from_str("m").unwrap(),
    };

    // Dummy parent -- this is a p2shwpkh spend kicking off the minting process

    // Dummy unsigned raw
    let mut dummy_parent_txn = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: LockTime::ZERO,
        input: input_utxos.iter().map(|i| i.txin()).collect(),
        output: vec![
            // Mint a rune
            TxOut {
                value: Amount::ZERO,
                script_pubkey: mint_rune_script_pubkey.clone(),
            },
            // to the taproot address
            TxOut {
                value: P2TR_DUST_LIMIT,
                script_pubkey: taproot_address.script_pubkey(),
            },
            // and set a temporary change output. this might
            //  not in fact be used if the change output is too small
            //   to be worth it, but at the worst case we'll just
            //    overpay the fees a bit
            TxOut {
                value: Amount::MAX,
                script_pubkey: segwit_address.script_pubkey(),
            },
        ],
    };
    // In the case where we only have one mint and we need to pay the tax
    if mint_count == 1 && tax_value > P2SHWPKH_DUST_LIMIT {
        // Pay the tax
        dummy_parent_txn.output.push(TxOut {
            value: tax_value,
            script_pubkey: tax_segwit_address.script_pubkey(),
        });
    } else if mint_count != 1 {
        // Otherwise we need to pay some fees forward to the next mint
        dummy_parent_txn.output.push(TxOut {
            value: Amount::MAX,
            script_pubkey: taproot_address.script_pubkey(),
        });
    }
    // Dummy unsigned psbt
    let mut dummy_parent_psbt =
        Psbt::from_unsigned_tx(dummy_parent_txn).expect("valid unsigned tx");
    dummy_parent_psbt.inputs = input_utxos
        .iter()
        .map(|i| i.p2shwpkh_spend(&dummy_pubkey))
        .collect();
    // Sign the dummy psbt
    dummy_parent_psbt
        .sign(&dummy_xpriv, &dummy_secp)
        .expect("valid signature");
    // Finalize the dummy psbt
    dummy_parent_psbt.inputs.iter_mut().for_each(|input| {
        finalize_p2shwpkh_input(input);
    });
    // And get a dummy vsize and txid while we're at it
    let dummy_parent_tx = dummy_parent_psbt.extract_tx_unchecked_fee_rate();
    let dummy_parent_vsize = dummy_parent_tx.vsize();
    let dummy_parent_txid = dummy_parent_tx.compute_txid();

    // Dummy children -- these are p2tr spends minting additional levels of runes

    // NOTE: this doesn't need to be correct at all, for
    //  the purposes of vsize estimation,
    //   but why not look close to the real thing?
    let mut dummy_prev_output = InputUtxo {
        txid: dummy_parent_txid,
        // This is always 3 in the case where having this
        //  matters (at least here, where the change output
        //   is always included)
        vout: 3,
        value: Amount::MAX,
        script_pubkey: taproot_address.script_pubkey(),
    };
    let mut dummy_children_vsizes = vec![];
    // Push any additional levels of minting we need to do
    for i in 1..mint_count {
        let mut dummy_child_txn = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![dummy_prev_output.txin()],
            output: vec![
                // Mint a rune
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: mint_rune_script_pubkey.clone(),
                },
                // to the taproot address
                TxOut {
                    value: P2TR_DUST_LIMIT,
                    script_pubkey: taproot_address.script_pubkey(),
                },
            ],
        };

        // Is this the last mint?
        // NOTE: idt this needs to happen for the purposes of
        //  vsize estimation, but we'll do it anyway
        if i == mint_count - 1 {
            // Then we need to pay the tax
            dummy_child_txn.output.push(TxOut {
                value: tax_value,
                script_pubkey: tax_segwit_address.script_pubkey(),
            });
        } else {
            // Otherwise we need to pay some fees forward
            //  to the next mint. We'll just set this to MAX
            //    here.
            dummy_child_txn.output.push(TxOut {
                value: Amount::MAX,
                script_pubkey: taproot_address.script_pubkey(),
            });
        }
        // Dummy unsigned psbt
        let mut dummy_child_psbt =
            Psbt::from_unsigned_tx(dummy_child_txn).expect("valid unsigned tx");
        dummy_child_psbt.inputs = vec![dummy_prev_output.p2tr_spend(&dummy_pubkey)];
        // Sign the dummy psbt
        dummy_child_psbt
            .sign(&dummy_xpriv, &dummy_secp)
            .expect("valid signature");
        // Finalize the dummy psbt
        dummy_child_psbt.inputs.iter_mut().for_each(|input| {
            finalize_p2tr_input(input);
        });
        // And get a dummy vsize and txid while we're at it
        let dummy_child_tx = dummy_child_psbt.extract_tx_unchecked_fee_rate();
        let dummy_child_vsize = dummy_child_tx.vsize();
        let dummy_child_txid = dummy_child_tx.compute_txid();

        dummy_prev_output = InputUtxo {
            txid: dummy_child_txid,
            // NOTE: this is always correct if we
            //  have another level of minting. Otherwise
            //   it doesn't matter
            vout: 2,
            // We'll just set this to MAX here
            value: Amount::MAX,
            script_pubkey: taproot_address.script_pubkey(),
        };
        dummy_children_vsizes.push(dummy_child_vsize);
    }

    /*
     * Determine the total vsize of all the dummy psbts
     *  This will be used to determine the total fees and change amount
     */

    let mut total_vsize = dummy_parent_vsize;
    for vsize in dummy_children_vsizes.iter() {
        total_vsize += vsize;
    }
    let miner_fee = match fee_rate.fee_vb(total_vsize as u64) {
        Some(fee) => fee,
        None => panic!("Estimated miner fee overflow"),
    };
    if miner_fee > total_input_value - total_output_value {
        panic!(
            "Estimated miner fee is greater than leftover value: {} > {} | {} vb @ {} sat/vb",
            miner_fee,
            total_input_value - total_output_value,
            total_vsize,
            fee_rate.to_sat_per_vb_ceil()
        );
    };
    let change_amount = total_input_value - total_output_value - miner_fee;

    /* Go and create our final unsigned transactions */

    // We'll keep track of the relay fees we've paid so far.
    //  We'll start at where we'll be at the end of the parent txn
    let mut paid_relay_fee = FeeRate::BROADCAST_MIN
        .fee_vb(dummy_parent_vsize as u64)
        .expect("valid fee");
    // We'll also keep track of how much more output value we need to mint.
    //  We'll start at the total output value minus the value of the parent txn.
    let mut remaining_output_value = total_output_value - P2TR_DUST_LIMIT;

    // We'll create our parent tx first
    let mut parent_outputs = vec![
        // Mint a rune
        TxOut {
            value: Amount::ZERO,
            script_pubkey: mint_rune_script_pubkey.clone(),
        },
        // to the taproot address
        TxOut {
            value: P2TR_DUST_LIMIT,
            script_pubkey: taproot_address.script_pubkey(),
        },
    ];
    // If we have enough change to be worth it, we'll go ahead
    //  and add a change output
    if change_amount > P2SHWPKH_DUST_LIMIT {
        // and set a temporary change output. this might
        //  not in fact be used if the change output is too small
        //   to be worth it, but at the worst case we'll just
        //    overpay the fees a bit
        parent_outputs.push(TxOut {
            value: change_amount,
            script_pubkey: segwit_address.script_pubkey(),
        });
    }
    // In the case where we only have one mint and we need to pay the tax
    if mint_count == 1 && tax_value > P2SHWPKH_DUST_LIMIT {
        //  we need to pay the tax
        parent_outputs.push(TxOut {
            value: tax_value,
            script_pubkey: tax_segwit_address.script_pubkey(),
        });
    } else if mint_count != 1 {
        // Otherwise we need to pay some fees forward to the next mint
        parent_outputs.push(TxOut {
            // We need to pay forward the remaining output value (following
            //  those paid in this parent )and miner fee, discounting the relay
            //   fees we've paid "so far" (these are implicitly the relay fees
            //    for this parent txn)
            value: miner_fee + remaining_output_value - paid_relay_fee,
            script_pubkey: taproot_address.script_pubkey(),
        });
    }
    // Create the parent txn
    let parent_txn = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: LockTime::ZERO,
        input: input_utxos.iter().map(|i| i.txin()).collect(),
        output: parent_outputs,
    };
    // Create the parent psbt
    let mut parent_psbt = Psbt::from_unsigned_tx(parent_txn).expect("valid unsigned tx");
    parent_psbt.inputs = input_utxos
        .iter()
        .map(|i| i.p2shwpkh_spend(&req.segwit_pubkey))
        .collect();
    // We'll actually fake finalize here, since we need to tag this
    //  with the final script sig, as that will affect the txid we compute
    let mut fake_parent_psbt = parent_psbt.clone();
    fake_parent_psbt.inputs.iter_mut().for_each(|input| {
        finalize_p2shwpkh_input(input);
    });
    let parent_txid = fake_parent_psbt
        .extract_tx_unchecked_fee_rate()
        .compute_txid();

    // Move on to the children

    let prev_vout = if mint_count == 1 {
        // Doen't actually matter here, since
        //  we wont use this value really
        0
    } else if change_amount > P2SHWPKH_DUST_LIMIT {
        // If we included a change amount, our
        //  pay-forward should be at index 3
        3
    } else {
        // Otherwise its at 2
        2
    };
    let mut prev_output = InputUtxo {
        txid: parent_txid,
        vout: prev_vout,
        // NOTE: should be the same as what we set in the parent
        value: miner_fee + remaining_output_value - paid_relay_fee,
        script_pubkey: taproot_address.script_pubkey(),
    };
    let mut children = vec![];
    // Push any additional levels of minting we need to do
    for i in 1..mint_count {
        // NOTE: this is gauranteed to be a ok -- point's back to the
        //  index of the child we're creating rn
        let dummy_child_index = (i - 1) as usize;
        let child_vsize = dummy_children_vsizes[dummy_child_index];
        // Update the paid relay fee to reflect where we'll
        //  be at once we're done with this (it should just discount
        //   the expeected vsizes of the child)
        paid_relay_fee = paid_relay_fee
            + FeeRate::BROADCAST_MIN
                .fee_vb(child_vsize as u64)
                .expect("valid fee");
        // Update the remaining output value to reflect where
        //  we'll be at the end of this child txn (it should just
        //   discount the p2tr dist limit to reflect a mint)
        remaining_output_value = remaining_output_value - P2TR_DUST_LIMIT;

        let mut child_txn = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: vec![prev_output.txin()],
            output: vec![
                // Mint a rune
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: mint_rune_script_pubkey.clone(),
                },
                // to the taproot address
                TxOut {
                    value: P2TR_DUST_LIMIT,
                    script_pubkey: taproot_address.script_pubkey(),
                },
            ],
        };

        // Is this the last mint?
        if i == mint_count - 1 {
            // Then we need to pay the tax
            child_txn.output.push(TxOut {
                value: tax_value,
                script_pubkey: tax_segwit_address.script_pubkey(),
            });
        } else {
            // Otherwise we need to pay some fees forward
            //  to the next mint.
            child_txn.output.push(TxOut {
                value: miner_fee + remaining_output_value - paid_relay_fee,
                script_pubkey: taproot_address.script_pubkey(),
            });
        }
        // Dummy unsigned psbt
        let mut child_psbt = Psbt::from_unsigned_tx(child_txn).expect("valid unsigned tx");
        child_psbt.inputs = vec![prev_output.p2tr_spend(&req.taproot_pubkey)];
        // We don't need to (fake) finalize here, since taproot inputs
        //  don't have a script sig -- ebverything else is witness data
        let child_tx = child_psbt.clone().extract_tx_unchecked_fee_rate();
        let child_txid = child_tx.compute_txid();

        // Update the prev output for the next iteration
        prev_output = InputUtxo {
            txid: child_txid,
            // NOTE: this is always correct if we
            //  have another level of minting. Otherwise
            //   it doesn't matter
            vout: 2,
            // NOTE: It's important that this is the same as the
            //  value we set in the child txn
            value: miner_fee + remaining_output_value - paid_relay_fee,
            script_pubkey: taproot_address.script_pubkey(),
        };
        // and push the child
        children.push(child_psbt);
    }

    /* Woo */

    let mut psbts = vec![parent_psbt];
    psbts.extend(children);

    // Sum up the fees
    let psbts_fee = psbts
        .iter()
        .map(|psbt| match psbt.fee() {
            Ok(fee) => fee,
            Err(_) => {
                println!("WARN: failed to determine fee");
                Amount::ZERO
            }
        })
        .sum::<Amount>();
    if psbts_fee != miner_fee {
        println!(
            "WARN: Estimated miner fee mismatch: {} != {}",
            miner_fee, psbts_fee
        );
    }

    // Return the serialized transaction
    MintRunesResponse {
        psbts,
        miner_fee: psbts_fee.to_sat(),
        change_amount: change_amount.to_sat(),
        vbytes: total_vsize as u64,
    }
}

// NOTE: this is a low effort port of the logic
//  contained the ordinals/ord repo for generating
//   mint-runes op_return script:
//    https://github.com/ordinals/ord/blob/88aa27fea0e3b9f2c43f46f3ba7075b622c5b4ed/crates/ordinals/src/runestone.rs#L129
fn build_mint_rune_script_pubkey(rune_block: u64, rune_txn: u32) -> ScriptBuf {
    let mut payload = Vec::new();
    let values: Vec<u128> = vec![rune_block.into(), rune_txn.into()];
    for value in values {
        encode_to_vec(RunesTag::Mint.into(), &mut payload);
        encode_to_vec(value, &mut payload);
    }

    let mut builder = script::Builder::new()
        .push_opcode(opcodes::all::OP_RETURN)
        .push_opcode(opcodes::all::OP_PUSHNUM_13);

    for chunk in payload.chunks(MAX_SCRIPT_ELEMENT_SIZE) {
        let push: &script::PushBytes = chunk.try_into().unwrap();
        builder = builder.push_slice(push);
    }

    builder.into_script()
}

fn encode_to_vec(mut n: u128, v: &mut Vec<u8>) {
    while n >> 7 > 0 {
        v.push(n.to_le_bytes()[0] | 0b1000_0000);
        n >>= 7;
    }
    v.push(n.to_le_bytes()[0]);
}
