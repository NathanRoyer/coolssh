use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use super::{Rng, Keypair, parsedump::ParseDump, ed25519_blob_len};
use std::io::Cursor;

static HEX_TO_WORD: [u8; 256] = {
    const __: u8 = 255; // not a hex digit
    [
        //   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 0
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 1
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 2
        00, 01, 02, 03, 04, 05, 06, 07, 08, 09, __, __, __, __, __, __, // 3
        __, 10, 11, 12, 13, 14, 15, __, __, __, __, __, __, __, __, __, // 4
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 5
        __, 10, 11, 12, 13, 14, 15, __, __, __, __, __, __, __, __, __, // 6
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 7
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 8
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 9
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // A
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // B
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // C
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // D
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // E
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // F
    ]
};

const WORD_TO_HEX: &'static [u8; 16] = b"0123456789abcdef";

/// Returns an Hex-Encoded Key Pair
pub fn create_ed25519_keypair() -> String {
    let keypair = Keypair::generate(&mut Rng);

    let mut hex = String::with_capacity(128);
    for byte in keypair.to_bytes() {
        let hw = (byte >> 4) & 0xf;
        let lw =  byte       & 0xf;
        hex.push(WORD_TO_HEX[hw as usize] as char);
        hex.push(WORD_TO_HEX[lw as usize] as char);
    }

    hex
}

/// Create an OpenSSH-friendly representation of the public key
pub fn dump_ed25519_pk_openssh(hex_keypair: &str, username: &str) -> String {
    let keypair = {
        let bytes: [u8; 64] = decode_hex(hex_keypair).unwrap();
        Keypair::from_bytes(&bytes).unwrap()
    };

    let mut dumped = [0; ed25519_blob_len(32) as _];
    let pubkey = keypair.public.as_bytes().as_slice();

    let mut cursor = Cursor::new(&mut dumped[..]);
    "ssh-ed25519".dump(&mut cursor).unwrap();
    pubkey.dump(&mut cursor).unwrap();

    let mut encoded = "ssh-ed25519 ".into();
    STANDARD_NO_PAD.encode_string(dumped, &mut encoded);
    encoded += " ";
    encoded += username;
    encoded += "\n";
    encoded
}

pub(crate) fn decode_hex<const N: usize>(hex: &str) -> Option<[u8; N]> {
    if hex.len() == (N * 2) {
        let mut ret = [0; N];
        let mut iter = hex.as_bytes().iter();

        for i in 0..N {
            let hw = HEX_TO_WORD[*iter.next().unwrap() as usize];
            let lw = HEX_TO_WORD[*iter.next().unwrap() as usize];
            if hw == 255 || lw == 255 {
                return None;
            }

            ret[i] = (hw << 4) | lw;
        }

        Some(ret)
    } else {
        None
    }
}
