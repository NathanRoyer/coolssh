//! SSH 2.0 Client
//! 
//! ### Example: Initiating a fetch from github
//! 
//! ```rust
//! let github_account_id = "john.doe@gmail.com";
//! let (openssh_encoded_pubkey, keypair) = create_ed25519_keypair(github_account_id);
//! 
//! println!("{}", openssh_encoded_pubkey);
//! // Add this public key to `authorized_keys` on your server
//! // -> https://github.com/settings/keys
//! 
//! let stream = TcpStream::connect("github.com:22").unwrap();
//! let mut conn = Connection::new(stream, ("git", &keypair).into()).unwrap();
//! 
//! // set appropriate timeout (preferably after authentication):
//! conn.mutate_stream(|stream| {
//!     let duration = std::time::Duration::from_millis(200);
//!     stream.set_read_timeout(Some(duration)).unwrap()
//! });
//! 
//! let run = conn.run("git-upload-pack rust-lang/rust.git").unwrap();
//! ```
//! 
//! ### Note
//! 
//! With few modifications, you can implement a server from this code.

#![allow(dead_code)]

use std::io::{Result, Error, ErrorKind, BufReader, BufWriter, BufRead, Read, Write};
use std::net::TcpStream;
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

mod connection;
mod parsedump;
mod userauth;
mod channelrequest;
mod messages;
mod packets;
mod run;

#[doc(inline)]
pub use {
    connection::{Connection, Auth},
    run::{Run, RunResult, RunEvent, ExitStatus},
};

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
