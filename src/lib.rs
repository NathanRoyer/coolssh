#![doc = include_str!("../README.md")]

use std::io::{Result as IoResult, Error as IoError, ErrorKind, BufReader, BufWriter, BufRead, Read, Write};
use std::net::TcpStream;
use core::mem::size_of;

use rand_core::OsRng as Rng;
use aes::cipher::{KeyIvInit, StreamCipher};
use hmac::Hmac;
use ed25519_dalek::{Keypair, Verifier, Signer};

type Cipher = ctr::Ctr64BE<aes::Aes256>;

const VERSION_HEADER: &'static [u8] = b"SSH-2.0-tinyssh+1.0";
const U32: usize = size_of::<u32>();
const U8: usize = size_of::<u8>();

mod connection;
mod parsedump;
mod userauth;
mod channelrequest;
mod messages;
mod packets;
mod run;
mod hmac;
mod keygen;

#[doc(inline)]
pub use {
    connection::{Connection, Auth},
    run::{Run, RunResult, RunEvent, ExitStatus},
    messages::MessageType,
    keygen::{create_ed25519_keypair, dump_ed25519_pk_openssh},
};

fn sha256<'b, P: parsedump::ParseDump<'b>>(data: &P) -> Result<[u8; 32]> {
    use sha2::{Sha256, Digest};

    struct Wrapper(Sha256);
    impl Write for Wrapper {
        fn flush(&mut self) -> IoResult<()> { Ok(()) }
        fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
            self.0.update(buf);
            Ok(buf.len())
        }
    }

    let mut hasher = Wrapper(Sha256::new());
    data.dump(&mut hasher)?;

    Ok(hasher.0.finalize().into())
}

pub(crate) const fn ed25519_blob_len(content_len: u32) -> u32 {
    4 + 11 + 4 + content_len
}

/// Fatal errors
#[derive(Copy, Clone, Debug)]
pub enum Error {
    /// No data to be read / send buffer is full.
    Timeout,
    /// Errors related to the TCP socket
    TcpError(ErrorKind),
    /// Invalid data type/encoding/size
    InvalidData,
    AuthenticationFailure,
    InvalidKeypair,
    ProcessHasExited,
    UnexpectedMessageType(MessageType),
    UnknownMessageType(u8),
    /// This can be raised instead of UnexpectedMessageType, if the peer sends random bytes
    Unimplemented,
}

pub type Result<T> = core::result::Result<T, Error>;

impl From<IoError> for Error {
    fn from(err: IoError) -> Self {
        Self::TcpError(err.kind())
    }
}
