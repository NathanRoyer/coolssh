use super::{
    Result, Error, ErrorKind, Write,
    TcpStream, ToSocketAddrs, BufReader, BufWriter, BufRead,
    Cipher, HMAC, VERSION_HEADER, Rng, sha256, Run,
};
use super::{KeyIvInit, Verifier};
use super::messages::{
    Kexinit, KexdhInit, KexdhReply, ExchangeHash, Unknown1, Newkeys,
    UnsignedMpInt, ServiceRequest, ServiceAccept,
};
use super::parsedump::ParseDump;
use super::packets::{PacketReader, PacketWriter};

pub enum Creds<'a> {
    Password {
        username: &'a str,
        password: &'a str,
    },
    PrivateKey {
        username: &'a str,
        priv_key: &'a [u8],
    }
}

pub struct Connection {
    reader: PacketReader<TcpStream>,
    writer: PacketWriter<TcpStream>,
    peer_version: String,
}

impl Connection {
    pub fn connect<A: ToSocketAddrs>(addr: A, _creds: Creds) -> Result<Self> {
        let stream = TcpStream::connect(addr)?;
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

        println!("peer_version: {}", peer_version);

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

        let KexdhReply {
            server_public_host_key,
            server_ephemeral_pubkey,
            exchange_hash_signature,
        } = reader.recv()?;

        let (Unknown1 {
            _unknown,
            content: host_pubkey_bytes,
        }, _) = Unknown1::parse(server_public_host_key)?;

        let (Unknown1 {
            _unknown,
            content: signature,
        }, _) = Unknown1::parse(exchange_hash_signature)?;

        if server_ephemeral_pubkey.len() != 32 || signature.len() != 64 || host_pubkey_bytes.len() != 32 {
            return Err(Error::new(ErrorKind::InvalidData, "problem"));
        }

        let shared_secret = {
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

        let shared_secret = UnsignedMpInt(shared_secret.as_bytes());

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

        let session_id = exchange_hash;

        writer.send(&Newkeys {})?;
        let _: Newkeys = reader.recv()?;

        println!("Got server Newkeys");

        let kex = KeyExchangeOutput::new(shared_secret, &exchange_hash, &session_id)?;
        writer.set_encryptor(Cipher::new(&kex.c2s_key.into(), &kex.c2s_iv.into()), HMAC::new(&kex.c2s_hmac), 32);
        reader.set_decryptor(Cipher::new(&kex.s2c_key.into(), &kex.s2c_iv.into()), HMAC::new(&kex.s2c_hmac), 32, 32);

        println!("Sending ServiceRequest");

        writer.send(&ServiceRequest {
            service_name: "ssh-userauth",
        })?;

        println!("Awaiting ServiceAccept");

        let accept: ServiceAccept = reader.recv()?;
        println!("accepted: {:?}", accept);

        Ok(Self {
            reader,
            writer,
            peer_version,
        })
    }

    pub fn run(self, _command: &str) -> Result<Run> {
        Ok(Run {
            conn: self,
        })
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
