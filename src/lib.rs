//! Minimal SSH 2.0 Client

#![allow(dead_code)]

use std::io::{Result, Error, ErrorKind, BufReader, BufWriter, BufRead, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use core::mem::size_of;

use rand_core::OsRng as Rng;
use ed25519_dalek::Verifier;
use aes::cipher::{KeyIvInit, StreamCipher};
use hmac_sha256::HMAC;
use ed25519_dalek::{Keypair, Signer};

type Cipher = ctr::Ctr64BE<aes::Aes256>;

const VERSION_HEADER: &'static [u8] = b"SSH-2.0-tinyssh+1.0";
const U32: usize = size_of::<u32>();
const U8: usize = size_of::<u8>();

pub mod connection;
pub mod parsedump;
pub mod userauth;
pub mod messages;
pub mod packets;

#[doc(inline)]
pub use connection::{Connection, Auth};

pub struct Run {
    conn: Connection,
}

impl Run {
    pub fn stop(self) -> Connection {
        self.conn
    }
}

fn sha256<'b, P: parsedump::ParseDump<'b>>(data: &P) -> Result<[u8; 32]> {
    use hmac_sha256::Hash;

    struct Wrapper(Hash);
    impl Write for Wrapper {
        fn flush(&mut self) -> Result<()> { Ok(()) }
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.0.update(buf);
            Ok(buf.len())
        }
    }

    let mut hasher = Wrapper(Hash::new());
    data.dump(&mut hasher)?;

    Ok(hasher.0.finalize())
}

#[cfg(feature = "dump")]
pub fn dump_ed25519_pub(ed25519_pub: &[u8], username: &str) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
    use parsedump::ParseDump;
    use std::io::Cursor;

    let mut dumped = [0; ed25519_blob_len(32) as _];

    let mut cursor = Cursor::new(&mut dumped[..]);
    "ssh-ed25519".dump(&mut cursor).unwrap();
    ed25519_pub.dump(&mut cursor).unwrap();

    let mut encoded = "ssh-ed25519 ".into();
    STANDARD_NO_PAD.encode_string(dumped, &mut encoded);
    encoded += " ";
    encoded += username;
    encoded += "\n";
    encoded
}

#[cfg(feature = "dump")]
pub fn create_ed25519_keypair(username: &str) -> (String, Keypair) {
    let mut csprng = Rng;
    let keypair = Keypair::generate(&mut csprng);
    let ed25519_pub = keypair.public.as_bytes();
    (dump_ed25519_pub(ed25519_pub, username), keypair)
}

pub(crate) const fn ed25519_blob_len(content_len: u32) -> u32 {
    4 + 11 + 4 + content_len
}
