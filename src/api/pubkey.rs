use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::key::CompressedPublicKey;
use bitcoin::secp256k1::{self, Secp256k1};
use bitcoin::Address;
use bitcoin::Network;
use bitcoin::ScriptBuf;
use bitcoin::WitnessProgram;
use serde::Deserialize;

// NOTE: maybe this should really be called 'signing pub key'
// NOTE: really, the compressed public key
//  should be that of the master, since I think
//   we can derive the pathed child from the derivation path.
//    We should be using HD keys more properly, generally.
#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Pubkey {
    /// The compressed public key of the derived child
    pub compressed_pubkey: CompressedPublicKey,
    /// The derivation path of the derived child
    pub derivation_path: DerivationPath,
    /// The fingerprint of the master key
    pub master_fingerprint: Fingerprint,
}

impl Pubkey {
    pub fn compressed_pubkey(&self) -> &CompressedPublicKey {
        &self.compressed_pubkey
    }

    pub fn derivation_path(&self) -> &DerivationPath {
        &self.derivation_path
    }

    pub fn master_fingerprint(&self) -> &Fingerprint {
        &self.master_fingerprint
    }

    pub fn p2tr_address<C: secp256k1::Context + secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        network: Network,
    ) -> Address {
        Address::p2tr(secp, self.compressed_pubkey.into(), None, network)
    }

    pub fn p2shwpkh_address(&self, network: Network) -> Address {
        Address::p2shwpkh(&self.compressed_pubkey, network)
    }

    pub fn p2shwpkh_redeem_script(&self) -> ScriptBuf {
        ScriptBuf::new_witness_program(&WitnessProgram::p2wpkh(self.compressed_pubkey()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const TAPROOT_JSON: &str = r#"
    {
        "compressedPubkey": "02d24d10c2d1984b46417efc53c9bb2f6b090829a37bfb4fb14a10c790cb1e0e89",
        "derivationPath": "m/86'/0'/0'/0/0",
        "masterFingerprint": "4fa08b26"
    }
    "#;
    const TAPROOT_ADDRESS: &str = "bc1pastdkpw8gejv7rgf4t8r699tzd586zrc20fxs5rphetevna7x8wssxu0nt";
    const SEGWIT_JSON: &str = r#"
    {
        "compressedPubkey": "027918f72790b3799148ce3f1ef78c1cb206cda8d2c6165d1815cb52809a4481ca",
        "derivationPath": "m/49'/0'/0'/0/0",
        "masterFingerprint": "4fa08b26"
    }
    "#;
    const SEGWIT_ADDRESS: &str = "3Fnr9WwcKLWWo4KPhbdup2FGz9aTJpnkiw";

    #[test]
    fn test_taproot_address() {
        let public_key: Pubkey = serde_json::from_str(TAPROOT_JSON).unwrap();
        let secp = Secp256k1::new();
        let address = public_key.taproot_address(&secp, Network::Bitcoin);
        assert_eq!(address.to_string(), TAPROOT_ADDRESS);
    }

    #[test]
    fn test_segwit_address() {
        let public_key: Pubkey = serde_json::from_str(SEGWIT_JSON).unwrap();
        let address = public_key.segwit_address(Network::Bitcoin);
        assert_eq!(address.to_string(), SEGWIT_ADDRESS);
    }
}
