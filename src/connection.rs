use super::{
    Cipher, HMAC, VERSION_HEADER, Keypair, Rng, sha256, Error,
    TcpStream, BufReader, BufWriter, BufRead, Result, Write,
    ErrorKind, ed25519_blob_len,
};
use super::{KeyIvInit, Verifier};
use super::userauth::sign_userauth;
use super::messages::{
    Kexinit, KexdhInit, KexdhReply, ExchangeHash, Newkeys, UserauthPkOk,
    UnsignedMpInt, ServiceRequest, ServiceAccept, UserauthSuccess, Blob,
    UserauthRequest,
};
use super::parsedump::ParseDump;
use super::packets::{PacketReader, PacketWriter};

pub enum Auth<'a> {
    Password {
        username: &'a str,
        password: &'a str,
    },
    Ed25519 {
        username: &'a str,
        keypair: &'a Keypair,
    }
}

pub struct Connection {
    pub(crate) reader: PacketReader<TcpStream>,
    pub(crate) writer: PacketWriter<TcpStream>,
    pub(crate) next_client_channel: u32,
}

impl Connection {
    pub fn new(stream: TcpStream, auth: Auth) -> Result<Self> {
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut writer = BufWriter::new(stream);

        writer.write(VERSION_HEADER)?;
        writer.write(b"\r\n")?;
        writer.flush()?;

        let peer_version = {
            let mut peer_version = String::new();

            loop {
                reader.read_line(&mut peer_version)?;
                let sw = |prefix| peer_version.starts_with(prefix);
                match sw("SSH-2.0-") || sw("SSH-1.99-") {
                    true => break,
                    _    => continue,
                }
            }

            let lf = peer_version.pop();
            let cr = peer_version.pop();

            if (cr, lf) != (Some('\r'), Some('\n')) {
                return Err(Error::new(ErrorKind::InvalidData, format!("Invalid Version Header: {}", peer_version)));
            }

            peer_version
        };

        log::info!("peer_version: {}", peer_version);

        let mut reader = PacketReader::new(reader);
        let mut writer = PacketWriter::new(writer);

        let client_kexinit = Kexinit {
            cookie: [0; 16],
            kex_algorithms: "curve25519-sha256",
            server_host_key_algorithms: "ssh-ed25519",
            encryption_algorithms_client_to_server: "aes256-ctr",
            encryption_algorithms_server_to_client: "aes256-ctr",
            mac_algorithms_client_to_server: "hmac-sha2-256",
            mac_algorithms_server_to_client: "hmac-sha2-256",
            compression_algorithms_client_to_server: "none",
            compression_algorithms_server_to_client: "none",
            languages_client_to_server: "",
            languages_server_to_client: "",
            first_kex_packet_follows: false,
            nop: 0,
        };

        let mut client_kexinit_payload = Vec::new();
        client_kexinit.dump(&mut client_kexinit_payload)?;
        let client_kexinit_payload = &client_kexinit_payload.into_boxed_slice();

        writer.send(&client_kexinit)?;

        let server_kexinit_payload = reader.recv_raw()?.to_vec();
        let server_kexinit_payload = &server_kexinit_payload.into_boxed_slice();
        let (server_kexinit, _) = Kexinit::parse(server_kexinit_payload)?;
        server_kexinit.check_compat(&client_kexinit)?;

        let secret_key = x25519_dalek::EphemeralSecret::new(Rng);
        let public_key = x25519_dalek::PublicKey::from(&secret_key);
        let client_ephemeral_pubkey = public_key.as_bytes().as_slice();

        writer.send(&KexdhInit {
            client_ephemeral_pubkey,
        })?;

        let shared_secret_array;
        let (exchange_hash, shared_secret) = {
            let KexdhReply {
                server_public_host_key,
                server_ephemeral_pubkey,
                exchange_hash_signature: Blob {
                    blob_len: _,
                    header: _,
                    content: signature,
                },
            } = reader.recv()?;

            let Blob {
                blob_len: _,
                header: _,
                content: host_pubkey_bytes,
            } = server_public_host_key;

            if server_ephemeral_pubkey.len() != 32 || signature.len() != 64 || host_pubkey_bytes.len() != 32 {
                return Err(Error::new(ErrorKind::InvalidData, "problem"));
            }

            shared_secret_array = {
                let mut sep_array = [0; 32];
                sep_array.copy_from_slice(server_ephemeral_pubkey);
                secret_key.diffie_hellman(&sep_array.into())
            };

            let host_pubkey = ed25519_dalek::PublicKey::from_bytes(host_pubkey_bytes)
                .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

            let signature = {
                let mut sig_array = [0; 64];
                sig_array.copy_from_slice(signature);
                ed25519_dalek::Signature::from(sig_array)
            };

            let shared_secret = UnsignedMpInt(shared_secret_array.as_bytes());

            let exchange_hash = sha256(&ExchangeHash {
                client_header: VERSION_HEADER,
                server_header: peer_version.as_bytes(),
                client_kexinit_payload,
                server_kexinit_payload,
                server_public_host_key,
                client_ephemeral_pubkey,
                server_ephemeral_pubkey,
                shared_secret,
            })?;

            host_pubkey.verify(&exchange_hash, &signature)
                .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

            (exchange_hash, shared_secret)
        };

        let session_id = exchange_hash;

        writer.send(&Newkeys {})?;
        let _: Newkeys = reader.recv()?;

        log::trace!("Got server Newkeys");

        let kex = KeyExchangeOutput::new(shared_secret, &exchange_hash, &session_id)?;
        writer.set_encryptor(Cipher::new(&kex.c2s_key.into(), &kex.c2s_iv.into()), HMAC::new(&kex.c2s_hmac), 32);
        reader.set_decryptor(Cipher::new(&kex.s2c_key.into(), &kex.s2c_iv.into()), HMAC::new(&kex.s2c_hmac), 32, 32);

        log::trace!("Sending ServiceRequest");

        writer.send(&ServiceRequest {
            service_name: "ssh-userauth",
        })?;

        log::trace!("Awaiting ServiceAccept");
        let _: ServiceAccept = reader.recv()?;
        log::trace!("Got ServiceAccept");

        let service_name = "ssh-connection";
        match auth {
            Auth::Password {
                username,
                password,
            } => {
                writer.send(&UserauthRequest::Password {
                    username,
                    service_name,
                    password,
                    new_password: None,
                })?;
            },
            Auth::Ed25519 {
                username,
                keypair,
            } => {
                let algorithm = "ssh-ed25519";

                let ed25519_pub = Blob {
                    blob_len: ed25519_blob_len(32),
                    header: algorithm,
                    content: keypair.public.as_bytes().as_slice(),
                };

                writer.send(&UserauthRequest::PublicKey {
                    username,
                    service_name,
                    algorithm,
                    blob: ed25519_pub,
                    signature: None,
                })?;

                log::trace!("Awaiting UserauthPkOk");
                let _: UserauthPkOk = reader.recv()?;
                log::trace!("Got UserauthPkOk");

                let signature = sign_userauth(keypair, &session_id, username, service_name, &ed25519_pub)?;

                writer.send(&UserauthRequest::PublicKey {
                    username,
                    service_name,
                    algorithm,
                    blob: ed25519_pub,
                    signature: Some(Blob {
                        blob_len: ed25519_blob_len(64),
                        header: algorithm,
                        content: &signature,
                    }),
                })?;
            },
        }

        log::trace!("Awaiting UserauthSuccess");
        let _: UserauthSuccess = reader.recv()?;
        log::trace!("Got UserauthSuccess");

        Ok(Self {
            reader,
            writer,
            next_client_channel: 0,
        })
    }

    pub fn mutate_stream<F: Fn(&mut TcpStream)>(&mut self, func: F) {
        func(self.reader.inner.get_mut())
    }
}

pub struct KeyExchangeOutput {
    c2s_iv:   [u8; 16],
    s2c_iv:   [u8; 16],
    c2s_key:  [u8; 32],
    s2c_key:  [u8; 32],
    c2s_hmac: [u8; 32],
    s2c_hmac: [u8; 32],
}

impl KeyExchangeOutput {
    fn fill_array<const N: usize>(
        dumped_shared_secret: &[u8],
        exchange_hash: &[u8],
        session_id: &[u8],
        magic_byte: u8,
    ) -> Result<[u8; N]> {
        let mut out_key = [0u8; N];
        let mut progress = 0;

        let mut appendage = sha256(&[
            dumped_shared_secret,
            exchange_hash,
            &[magic_byte],
            session_id,
        ].as_slice())?;

        loop {
            let len = appendage.len().min(N - progress);
            out_key[progress..][..len].copy_from_slice(&appendage[..len]);
            progress += len;

            if progress != N {
                appendage = sha256(&[
                    dumped_shared_secret,
                    exchange_hash,
                    &out_key[..progress],
                ].as_slice())?;
            } else {
                break;
            }
        }

        Ok(out_key)
    }

    pub fn new(shared_secret: UnsignedMpInt, exchange_hash: &[u8], session_id: &[u8]) -> Result<Self> {
        let mut dumped_shared_secret = Vec::new();
        shared_secret.dump(&mut dumped_shared_secret)?;
        let dumped_shared_secret = dumped_shared_secret.as_slice();

        let kex_output_16 = |magic_byte| Self::fill_array(dumped_shared_secret, exchange_hash, session_id, magic_byte);
        let c2s_iv:   [u8; 16] = kex_output_16(b'A')?;
        let s2c_iv:   [u8; 16] = kex_output_16(b'B')?;

        let kex_output_32 = |magic_byte| Self::fill_array(dumped_shared_secret, exchange_hash, session_id, magic_byte);
        let c2s_key:  [u8; 32] = kex_output_32(b'C')?;
        let s2c_key:  [u8; 32] = kex_output_32(b'D')?;
        let c2s_hmac: [u8; 32] = kex_output_32(b'E')?;
        let s2c_hmac: [u8; 32] = kex_output_32(b'F')?;

        Ok(Self {
            c2s_iv,
            s2c_iv,
            c2s_key,
            s2c_key,
            c2s_hmac,
            s2c_hmac,
        })
    }
}

impl<'a> From<(&'a str, &'a Keypair)> for Auth<'a> {
    fn from(tuple: (&'a str, &'a Keypair)) -> Auth<'a> {
        let (username, keypair) = tuple;
        Self::Ed25519 {
            username,
            keypair,
        }
    }
}

impl core::fmt::Debug for Connection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Connection").finish()
    }
}
