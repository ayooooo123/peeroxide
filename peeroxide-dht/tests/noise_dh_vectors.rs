use peeroxide_dht::noise::{ed25519_dh, keypair_from_seed};

fn hex_32(value: &str) -> [u8; 32] {
    hex::decode(value)
        .expect("valid hex")
        .try_into()
        .expect("32-byte point")
}

#[test]
fn ed25519_dh_matches_sodium_native_vectors() {
    // Generated with sodium-native's crypto_scalarmult_ed25519_noclamp using
    // crypto_sign_seed_keypair(Buffer.alloc(32, 0x42)).
    let keypair = keypair_from_seed(&[0x42; 32]);
    let vectors = [
        (
            "generated",
            "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
            Some("fc9676f4c629824f0dbf558d898491536af6f7e1b33375234c458c597c03cabc"),
        ),
        (
            "basepoint",
            "5866666666666666666666666666666666666666666666666666666666666666",
            Some("2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"),
        ),
        (
            "identity",
            "0100000000000000000000000000000000000000000000000000000000000000",
            None,
        ),
        (
            "small_order_zero",
            "0000000000000000000000000000000000000000000000000000000000000000",
            None,
        ),
        (
            "small_order_minus_one",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            None,
        ),
        (
            "torsion",
            "c7176a703d4d4141d8ab75eb4dca135978a3d3d5d18e8b3a16d4a9e58dc4b60c",
            None,
        ),
        (
            "noncanonical_p",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            None,
        ),
        (
            "noncanonical_p_plus_one",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            None,
        ),
    ];

    for (name, point, expected) in vectors {
        let result = ed25519_dh(&keypair.secret_key, &hex_32(point));
        match expected {
            Some(expected) => assert_eq!(result.unwrap(), hex_32(expected), "{name}"),
            None => assert!(result.is_err(), "{name}"),
        }
    }
}

/// sodium-native refuses all 38 encodings `y + p` (y in 0..19, both sign bits).
#[test]
fn ed25519_dh_rejects_every_non_canonical_encoding() {
    let keypair = keypair_from_seed(&[0x42; 32]);
    for y in 0u8..19 {
        for sign in [0u8, 0x80] {
            // p = 2^255 - 19, little-endian: ed ff .. ff 7f
            let mut point = [0xff; 32];
            point[0] = 0xed + y;
            point[31] = 0x7f | sign;
            assert!(
                ed25519_dh(&keypair.secret_key, &point).is_err(),
                "y = p + {y}, sign {sign:#x}"
            );
        }
    }
}
