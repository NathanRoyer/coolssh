//! SSH 2.0 Client

#![allow(dead_code)]

use std::io::{Result, Error, ErrorKind, BufReader, BufWriter, BufRead, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use core::mem::size_of;

use rand_core::OsRng as Rng;
use ed25519_dalek::Verifier;
use aes::cipher::{KeyIvInit, StreamCipher};
use hmac_sha256::HMAC;

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
pub use connection::{Connection, Creds};

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

#[test]
fn connection() {
    if let Err(error) = Connection::connect("github.com:22", Creds::Password { username: "", password: "" }) {
        println!("{:#?}", error);
    }
}
