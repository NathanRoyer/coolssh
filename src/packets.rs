use core::ops::Range;
use super::{
    Result, Error, U8, U32, Write, BufReader,
    BufWriter, Cipher, Hmac, ErrorKind, Read,
};
use super::StreamCipher;
use super::messages::{MessageType, GlobalRequest};
use super::parsedump::{ParseDump, try_u32};

pub struct PacketReader<R: Read> {
    pub(crate) inner: BufReader<R>,
    packet: Vec<u8>,
    packet_number: u32,
    negociated: Option<(Cipher, Hmac)>,
    block_size: usize,
    mac_size: usize,
}

impl<R: Read> PacketReader<R> {
    pub fn new(inner: BufReader<R>) -> Self {
        Self {
            inner,
            packet: Vec::new(),
            packet_number: 0,
            negociated: None,
            block_size: 8,
            mac_size: 0,
        }
    }

    pub fn set_decryptor(&mut self, decryptor: Cipher, hmac: Hmac, block_size: usize, mac_size: usize) {
        self.negociated = Some((decryptor, hmac));
        self.block_size = block_size;
        self.mac_size = mac_size;
    }

    fn pull(&mut self, to_pull: usize) -> Result<Range<usize>> {
        let old_len = self.packet.len();
        let new_len = old_len + to_pull;
        let range = old_len..new_len;

        self.packet.resize(new_len, 0);
        self.inner.read_exact(&mut self.packet[range.clone()])?;

        Ok(range)
    }

    fn pull_and_decrypt(&mut self, to_pull: usize) -> Result<()> {
        let range = self.pull(to_pull)?;

        if let Some((decryptor, _hmac)) = &mut self.negociated {
            decryptor.apply_keystream(&mut self.packet[range]);
        }

        Ok(())
    }

    pub fn recv_raw(&mut self) -> Result<&[u8]> {
        self.packet.clear();

        log::trace!("---------- PACKET ----------");
        log::trace!("packet_number = {}", self.packet_number);
        self.pull_and_decrypt(U32)?;

        let packet_length = try_u32(&self.packet).unwrap() as usize;
        log::trace!("packet_length = {}", packet_length);
        self.pull_and_decrypt(packet_length)?;
        log::trace!("self.packet.len() = {}", self.packet.len());

        if self.mac_size != 0 {
            log::trace!("self.mac_size = {}", self.mac_size);
            self.pull(self.mac_size)?;
            log::trace!("self.packet.len() = {}", self.packet.len());
        }

        let padding_length = self.packet[U32] as usize;
        log::trace!("padding_length = {}", padding_length);
        if let Some(payload_length) = packet_length.checked_sub(padding_length).and_then(|v| v.checked_sub(U8)) {
            let payload_offset = U32 + U8;

            if let Some((_decryptor, hmac)) = &self.negociated {
                let mut hmac = hmac.clone();
                hmac.update(self.packet_number.to_be_bytes().as_slice());

                let (packet, packet_hmac) = self.packet.split_at(packet_length + U32);
                log::trace!("hmac 2nd update: {} bytes", packet.len());
                hmac.update(packet);

                if packet_hmac.len() != self.mac_size {
                    log::error!("Incorrect Packet Mac Size ({})", packet_hmac.len());
                    return Err(Error::InvalidData);
                }

                if packet_hmac != &hmac.finalize() {
                    log::error!("Incorrect Packet Mac");
                    return Err(Error::InvalidData);
                }
            }

            self.packet_number = self.packet_number.wrapping_add(1);

            let range = payload_offset..(payload_offset + payload_length);
            let msg_type = self.packet[payload_offset];
            let msg_type = MessageType::try_from(msg_type)?;
            match msg_type {
                MessageType::Ignore => self.recv_raw(),
                MessageType::GlobalRequest => {
                    // THIS FILTERS OUT GLOBAL REQUESTS WITHOUT `want_reply`
                    let (global_req, _) = GlobalRequest::parse(&self.packet[range.clone()])?;
                    match global_req.want_reply {
                        true => Ok(&self.packet[range]),
                        false => {
                            log::info!("Ignoring global request (type = {})", global_req.request_name);
                            self.recv_raw()
                        },
                    }
                },
                _ => Ok(&self.packet[range]),
            }
        } else {
            log::error!("Invalid packet_length");
            Err(Error::InvalidData)
        }
    }

    pub fn recv<'a, 'b: 'a, M: ParseDump<'a>>(&'b mut self) -> Result<M> {
        M::parse(match self.recv_raw() {
            Ok(bytes) => Ok(bytes),
            Err(Error::TcpError(ErrorKind::WouldBlock | ErrorKind::TimedOut)) => Err(Error::Timeout),
            Err(e) => Err(e),
        }?).map(|(m, _)| m)
    }
}

pub struct PacketWriter<W: Write> {
    inner: BufWriter<W>,
    packet: Vec<u8>,
    packet_number: u32,
    negociated: Option<(Cipher, Hmac)>,
    block_size: usize,
}

impl<W: Write> PacketWriter<W> {
    pub fn new(inner: BufWriter<W>) -> Self {
        Self {
            inner,
            packet: Vec::new(),
            packet_number: 0,
            negociated: None,
            block_size: 8,
        }
    }

    pub fn set_encryptor(&mut self, encryptor: Cipher, hmac: Hmac, block_size: usize) {
        self.negociated = Some((encryptor, hmac));
        self.block_size = block_size;
    }

    fn send_raw<'a, M: ParseDump<'a>>(&mut self, message: &M) -> Result<()> {
        self.packet.clear();
        // make room for packet_length & padding_length
        self.packet.resize(U32 + U8, 0);

        message.dump(&mut self.packet)?;

        // todo: compress payload

        let mut packet_length = U8 + self.packet.len() - (U32 + U8);
        let mut encrypted_length = U32 + packet_length;
        let padding_length = match encrypted_length % self.block_size {
            0 => 0,
            n => self.block_size - n,
        };
        packet_length += padding_length;
        encrypted_length += padding_length;
        assert_eq!(encrypted_length % self.block_size, 0);

        // set correct values for packet_length & padding_length
        self.packet[..U32].copy_from_slice(&(packet_length as u32).to_be_bytes());
        self.packet[U32] = padding_length as u8;

        // pad
        self.packet.resize(encrypted_length, 0);

        if let Some((encryptor, hmac)) = &mut self.negociated {
            let mut hmac = hmac.clone();
            hmac.update(self.packet_number.to_be_bytes().as_slice());
            hmac.update(self.packet.as_slice());

            // encrypt then push hmac
            encryptor.apply_keystream(&mut self.packet);
            self.packet.extend_from_slice(&hmac.finalize());
        }

        self.packet_number = self.packet_number.wrapping_add(1);

        self.inner.write_all(&self.packet)?;
        self.inner.flush()?;

        Ok(())
    }

    pub fn send<'a, M: ParseDump<'a>>(&mut self, message: &M) -> Result<()> {
        match self.send_raw(message) {
            Ok(()) => Ok(()),
            Err(Error::TcpError(ErrorKind::WouldBlock | ErrorKind::TimedOut)) => Err(Error::Timeout),
            Err(e) => Err(e),
        }
    }
}
