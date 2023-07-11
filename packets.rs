use std::io::{Result, Error, ErrorKind, BufReader, BufWriter, Read, Write};
use core::str::from_utf8;
use core::ops::Range;
use super::{U8, U32, Cipher, StreamCipher, Context as HMAC};

fn too_short() -> Error {
    Error::new(ErrorKind::UnexpectedEof, "Missing Bytes / Input Too Short")
}

pub trait ParseDump<'b>: Sized {
    fn parse(bytes: &'b[u8]) -> Result<(Self, usize)>;
    fn dump<W: Write>(&self, sink: &mut W) -> Result<()>;
}

macro_rules! parse_dump_struct_inner {
    ($name:ident { $($field:ident: $field_type:ty,)* }) => {
        fn parse(bytes: &'b [u8]) -> Result<(Self, usize)> {
            #[allow(unused_mut)]
            let mut i = if let Some(expected) = MessageType::try_match(stringify!($name)) {
                let raw_msg_type = u8::parse(&bytes)?.0;
                let msg_type = MessageType::try_from(raw_msg_type)?;
                if msg_type != expected {
                    let err_msg = format!(concat!("Expected ", stringify!($name), " message but got {:?}"), msg_type);
                    return Err(Error::new(ErrorKind::InvalidData, err_msg));
                }

                U8
            } else {
                0
            };

            $(
                let ($field, inc) = <$field_type>::parse(&bytes[i..])?;
                i += inc;
            )*
            Ok((Self {
                $(
                    $field,
                )*
            }, i))
        }

        fn dump<W: Write>(&self, sink: &mut W) -> Result<()> {
            if let Some(msg_type) = MessageType::try_match(stringify!($name)) {
                (msg_type as u8).dump(sink)?;
            }

            $(self.$field.dump(sink)?;)*
            Ok(())
        }
    }
}

macro_rules! parse_dump_struct {
    ($name:ident<$lifetime:lifetime> { $($field:ident: $field_type:ty,)* }) => {
        #[derive(Debug)]
        pub struct $name<$lifetime> {
            $(
                pub $field: $field_type,
            )*
        }

        impl<$lifetime, 'b: $lifetime> ParseDump<'b> for $name<$lifetime> {
            parse_dump_struct_inner!($name { $($field: $field_type,)* });
        }
    };
    ($name:ident { $($field:ident: $field_type:ty,)* }) => {
        #[derive(Debug)]
        pub struct $name {
            $(
                pub $field: $field_type,
            )*
        }

        impl<'b> ParseDump<'b> for $name {
            parse_dump_struct_inner!($name { $($field: $field_type,)* });
        }
    };
}

#[derive(Debug)]
pub enum Message<'a> {
    Disconnect,
    Ignore,
    Unimplemented(Unimplemented),
    Debug,
    ServiceRequest,
    ServiceAccept,
    Kexinit(Kexinit<'a>),
    Newkeys,
    KexdhInit(KexdhInit<'a>),
    KexdhReply(KexdhReply<'a>),
    UserauthRequest,
    UserauthFailure,
    UserauthSuccess,
    UserauthPkOk,
    GlobalRequest,
    RequestSuccess,
    RequestFailure,
    ChannelOpen,
    ChannelOpenConfirmation,
    ChannelOpenFailure,
    ChannelWindowAdjust,
    ChannelData,
    ChannelExtendedData,
    ChannelEof,
    ChannelClose,
    ChannelRequest,
    ChannelSuccess,
    ChannelFailure,
}

parse_dump_struct!(Unimplemented {
    packet_number: u32,
});

parse_dump_struct!(Kexinit<'a> {
    cookie: [u8; 16],
    kex_algorithms: &'a str,
    server_host_key_algorithms: &'a str,
    encryption_algorithms_client_to_server: &'a str,
    encryption_algorithms_server_to_client: &'a str,
    mac_algorithms_client_to_server: &'a str,
    mac_algorithms_server_to_client: &'a str,
    compression_algorithms_client_to_server: &'a str,
    compression_algorithms_server_to_client: &'a str,
    languages_client_to_server: &'a str,
    languages_server_to_client: &'a str,
    first_kex_packet_follows: bool,
    nop: u32,
});

parse_dump_struct!(KexdhInit<'a> {
    client_ephemeral_pubkey: &'a [u8],
});

parse_dump_struct!(KexdhReply<'a> {
    server_public_host_key: &'a [u8],
    server_ephemeral_pubkey: &'a [u8],
    exchange_hash_signature: &'a [u8],
});

parse_dump_struct!(Newkeys {});

parse_dump_struct!(ServiceRequest<'a> {
    service_name: &'a str,
});

parse_dump_struct!(ServiceAccept<'a> {
    service_name: &'a str,
});

parse_dump_struct!(Disconnect<'a> {
    reason_code: DisconnectReasonCode,
    description: &'a str,
    language_tag: &'a str,
});

parse_dump_struct!(ExchangeHash<'a> {
    client_header: &'a [u8],
    server_header: &'a [u8],
    client_kexinit_payload: &'a [u8],
    server_kexinit_payload: &'a [u8],
    server_public_host_key: &'a [u8],
    client_ephemeral_pubkey: &'a [u8],
    server_ephemeral_pubkey: &'a [u8],
    shared_secret: UnsignedMpInt<'a>,
});

parse_dump_struct!(Unknown1<'a> {
    _unknown: &'a [u8],
    content: &'a [u8],
});

parse_dump_struct!(BaseKeyMaterial<'a> {
    shared_secret: UnsignedMpInt<'a>,
    exchange_hash: &'a [u8],
    magic_byte: u8,
    session_id: &'a [u8],
});

parse_dump_struct!(ExtKeyMaterial<'a> {
    shared_secret: UnsignedMpInt<'a>,
    exchange_hash: &'a [u8],
    entire_key_so_far: &'a [u8],
});

macro_rules! forward_and_wrap {
    ($variant:ident, $rem:ident) => ( $variant::parse($rem).map(|(inner, p)| (Self::$variant(inner), p)) )
}

impl<'a, 'b: 'a> ParseDump<'b> for Message<'a> {
    fn parse(bytes: &'b [u8]) -> Result<(Self, usize)> {
        let typ = *bytes.get(0).ok_or_else(|| too_short())?;
        match MessageType::try_from(typ)? {
            MessageType::Kexinit => forward_and_wrap!(Kexinit, bytes),
            MessageType::Unimplemented => forward_and_wrap!(Unimplemented, bytes),
            typ => Err(Error::new(ErrorKind::InvalidData, format!("Unimplemented Message Type: {:?}", typ))),
        }
    }

    fn dump<W: Write>(&self, sink: &mut W) -> Result<()> {
        (self.typ() as u8).dump(sink)?;
        match self {
            Self::Kexinit(inner) => inner.dump(sink),
            Self::Unimplemented(inner) => inner.dump(sink),
            typ => Err(Error::new(ErrorKind::InvalidData, format!("Unimplemented Message Type: {:?}", typ))),
        }
    }
}

impl<'a> Message<'a> {
    pub fn typ(&self) -> MessageType {
        match self {
            Self::Disconnect => MessageType::Disconnect,
            Self::Ignore => MessageType::Ignore,
            Self::Unimplemented(_) => MessageType::Unimplemented,
            Self::Debug => MessageType::Debug,
            Self::ServiceRequest => MessageType::ServiceRequest,
            Self::ServiceAccept => MessageType::ServiceAccept,
            Self::Kexinit(_) => MessageType::Kexinit,
            Self::Newkeys => MessageType::Newkeys,
            Self::KexdhInit(_) => MessageType::KexdhInit,
            Self::KexdhReply(_) => MessageType::KexdhReply,
            Self::UserauthRequest => MessageType::UserauthRequest,
            Self::UserauthFailure => MessageType::UserauthFailure,
            Self::UserauthSuccess => MessageType::UserauthSuccess,
            Self::UserauthPkOk => MessageType::UserauthPkOk,
            Self::GlobalRequest => MessageType::GlobalRequest,
            Self::RequestSuccess => MessageType::RequestSuccess,
            Self::RequestFailure => MessageType::RequestFailure,
            Self::ChannelOpen => MessageType::ChannelOpen,
            Self::ChannelOpenConfirmation => MessageType::ChannelOpenConfirmation,
            Self::ChannelOpenFailure => MessageType::ChannelOpenFailure,
            Self::ChannelWindowAdjust => MessageType::ChannelWindowAdjust,
            Self::ChannelData => MessageType::ChannelData,
            Self::ChannelExtendedData => MessageType::ChannelExtendedData,
            Self::ChannelEof => MessageType::ChannelEof,
            Self::ChannelClose => MessageType::ChannelClose,
            Self::ChannelRequest => MessageType::ChannelRequest,
            Self::ChannelSuccess => MessageType::ChannelSuccess,
            Self::ChannelFailure => MessageType::ChannelFailure,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Disconnect = 1,
    Ignore = 2,
    Unimplemented = 3,
    Debug = 4,
    ServiceRequest = 5,
    ServiceAccept = 6,
    Kexinit = 20,
    Newkeys = 21,
    KexdhInit = 30,
    KexdhReply = 31,
    UserauthRequest = 50,
    UserauthFailure = 51,
    UserauthSuccess = 52,
    UserauthPkOk = 60,
    GlobalRequest = 80,
    RequestSuccess = 81,
    RequestFailure = 82,
    ChannelOpen = 90,
    ChannelOpenConfirmation = 91,
    ChannelOpenFailure = 92,
    ChannelWindowAdjust = 93,
    ChannelData = 94,
    ChannelExtendedData = 95,
    ChannelEof = 96,
    ChannelClose = 97,
    ChannelRequest = 98,
    ChannelSuccess = 99,
    ChannelFailure = 100,
}

impl MessageType {
    const fn try_match(name: &str) -> Option<Self> {
        match name.as_bytes() {
            b"Disconnect" => Some(Self::Disconnect),
            b"Ignore" => Some(Self::Ignore),
            b"Unimplemented" => Some(Self::Unimplemented),
            b"Debug" => Some(Self::Debug),
            b"ServiceRequest" => Some(Self::ServiceRequest),
            b"ServiceAccept" => Some(Self::ServiceAccept),
            b"Kexinit" => Some(Self::Kexinit),
            b"Newkeys" => Some(Self::Newkeys),
            b"KexdhInit" => Some(Self::KexdhInit),
            b"KexdhReply" => Some(Self::KexdhReply),
            b"UserauthRequest" => Some(Self::UserauthRequest),
            b"UserauthFailure" => Some(Self::UserauthFailure),
            b"UserauthSuccess" => Some(Self::UserauthSuccess),
            b"UserauthPkOk" => Some(Self::UserauthPkOk),
            b"GlobalRequest" => Some(Self::GlobalRequest),
            b"RequestSuccess" => Some(Self::RequestSuccess),
            b"RequestFailure" => Some(Self::RequestFailure),
            b"ChannelOpen" => Some(Self::ChannelOpen),
            b"ChannelOpenConfirmation" => Some(Self::ChannelOpenConfirmation),
            b"ChannelOpenFailure" => Some(Self::ChannelOpenFailure),
            b"ChannelWindowAdjust" => Some(Self::ChannelWindowAdjust),
            b"ChannelData" => Some(Self::ChannelData),
            b"ChannelExtendedData" => Some(Self::ChannelExtendedData),
            b"ChannelEof" => Some(Self::ChannelEof),
            b"ChannelClose" => Some(Self::ChannelClose),
            b"ChannelRequest" => Some(Self::ChannelRequest),
            b"ChannelSuccess" => Some(Self::ChannelSuccess),
            b"ChannelFailure" => Some(Self::ChannelFailure),
            _ => None,
        }
    }
}

impl TryFrom<u8> for MessageType {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Disconnect),
            2 => Ok(Self::Ignore),
            3 => Ok(Self::Unimplemented),
            4 => Ok(Self::Debug),
            5 => Ok(Self::ServiceRequest),
            6 => Ok(Self::ServiceAccept),
            20 => Ok(Self::Kexinit),
            21 => Ok(Self::Newkeys),
            30 => Ok(Self::KexdhInit),
            31 => Ok(Self::KexdhReply),
            50 => Ok(Self::UserauthRequest),
            51 => Ok(Self::UserauthFailure),
            52 => Ok(Self::UserauthSuccess),
            60 => Ok(Self::UserauthPkOk),
            80 => Ok(Self::GlobalRequest),
            81 => Ok(Self::RequestSuccess),
            82 => Ok(Self::RequestFailure),
            90 => Ok(Self::ChannelOpen),
            91 => Ok(Self::ChannelOpenConfirmation),
            92 => Ok(Self::ChannelOpenFailure),
            93 => Ok(Self::ChannelWindowAdjust),
            94 => Ok(Self::ChannelData),
            95 => Ok(Self::ChannelExtendedData),
            96 => Ok(Self::ChannelEof),
            97 => Ok(Self::ChannelClose),
            98 => Ok(Self::ChannelRequest),
            99 => Ok(Self::ChannelSuccess),
            100 => Ok(Self::ChannelFailure),
            _ => Err(Error::new(ErrorKind::InvalidData, "Unknown Message Type")),
        }
    }
}

pub struct PacketReader<R: Read> {
    inner: BufReader<R>,
    packet: Vec<u8>,
    packet_number: u32,
    negociated: Option<(Cipher, HMAC)>,
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

    pub fn set_decryptor(&mut self, decryptor: Cipher, hmac: HMAC, block_size: usize, mac_size: usize) {
        self.negociated = Some((decryptor, hmac));
        self.block_size = block_size;
        self.mac_size = mac_size;
    }

    fn pull(&mut self, to_pull: usize) -> Result<Range<usize>> {
        let old_len = self.packet.len();
        let new_len = old_len + to_pull;
        let range = old_len..new_len;

        self.packet.resize(new_len, 0);
        self.inner.read(&mut self.packet[range.clone()])?;

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

        self.pull_and_decrypt(self.block_size)?;

        let packet_length = try_u32(&self.packet).unwrap() as usize;
        if let Some(remaining_length) = packet_length.checked_sub(self.block_size - U32) {
            self.pull_and_decrypt(remaining_length)?;
            if self.mac_size != 0 {
                self.pull(self.mac_size)?;
            }
        } else {
            return Err(Error::new(ErrorKind::UnexpectedEof, "Invalid packet_length (1)"));
        }

        let padding_length = self.packet[U32] as usize;
        if let Some(payload_length) = packet_length.checked_sub(padding_length).and_then(|v| v.checked_sub(U8)) {
            let payload_offset = U32 + U8;

            if let Some((_decryptor, hmac)) = &self.negociated {
                let mut hmac = hmac.clone();
                hmac.update(self.packet_number.to_be_bytes().as_slice());

                let (packet, packet_hmac) = self.packet.split_at(packet_length + U32);
                hmac.update(packet);

                if packet_hmac != hmac.sign().as_ref() {
                    return Err(Error::new(ErrorKind::InvalidData, "Incorrect Packet Mac"));
                }
            }

            self.packet_number = self.packet_number.wrapping_add(1);

            let some_ignore_msg = Some(&(MessageType::Ignore as u8));
            if self.packet.get(payload_offset) != some_ignore_msg {
                Ok(&self.packet[payload_offset..][..payload_length])
            } else {
                // skip, receive next packet
                self.recv_raw()
            }
        } else {
            Err(Error::new(ErrorKind::UnexpectedEof, "Invalid packet_length (2)"))
        }
    }

    pub fn recv<'a, 'b: 'a, M: ParseDump<'a>>(&'b mut self) -> Result<M> {
        M::parse(self.recv_raw()?).map(|(m, _)| m)
    }
}

pub struct PacketWriter<W: Write> {
    inner: BufWriter<W>,
    packet: Vec<u8>,
    packet_number: u32,
    negociated: Option<(Cipher, HMAC)>,
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

    pub fn set_encryptor(&mut self, encryptor: Cipher, hmac: HMAC, block_size: usize) {
        self.negociated = Some((encryptor, hmac));
        self.block_size = block_size;
    }

    pub fn send<'a, M: ParseDump<'a>>(&mut self, message: &M) -> Result<()> {
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
            self.packet.extend_from_slice(hmac.sign().as_ref());
        }

        self.packet_number = self.packet_number.wrapping_add(1);

        self.inner.write(&self.packet)?;
        self.inner.flush()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct UnsignedMpInt<'a>(pub &'a [u8]);

impl<'a, 'b: 'a> ParseDump<'b> for UnsignedMpInt<'a> {
    fn parse(bytes: &'b [u8]) -> Result<(Self, usize)> {
        let total = U32 + (try_u32(bytes)? as usize);
        Ok((Self(bytes.get(U32..total).ok_or_else(|| too_short())?), total))
    }

    fn dump<W: Write>(&self, sink: &mut W) -> Result<()> {
        let has_non_zero = self.0.iter().position(|b| *b != 0);
        if has_non_zero.is_some() {
            let prevent_sign = (self.0[0] & 0x80) != 0;
            let len = self.0.len() + (prevent_sign as usize);

            sink.write(&(len as u32).to_be_bytes())?;
            if prevent_sign {
                sink.write(&[0])?;
            }
            sink.write(self.0).map(|_| ())
        } else {
            0u32.dump(sink)
        }
    }
}

impl<'b> ParseDump<'b> for bool {
    fn parse(bytes: &'b [u8]) -> Result<(Self, usize)> {
        Ok((*bytes.get(0).ok_or_else(|| too_short())? != 0, U8))
    }

    fn dump<W: Write>(&self, sink: &mut W) -> Result<()> {
        sink.write(&[*self as u8]).map(|_| ())
    }
}

impl<'b> ParseDump<'b> for u8 {
    fn parse(bytes: &'b [u8]) -> Result<(Self, usize)> {
        Ok((*bytes.get(0).ok_or_else(|| too_short())?, U8))
    }

    fn dump<W: Write>(&self, sink: &mut W) -> Result<()> {
        sink.write(&[*self]).map(|_| ())
    }
}

impl<'b> ParseDump<'b> for u32 {
    fn parse(bytes: &'b [u8]) -> Result<(Self, usize)> {
        Ok((try_u32(bytes)?, U32))
    }

    fn dump<W: Write>(&self, sink: &mut W) -> Result<()> {
        sink.write(&self.to_be_bytes()).map(|_| ())
    }
}

impl<'b> ParseDump<'b> for [u8; 16] {
    fn parse(bytes: &'b [u8]) -> Result<(Self, usize)> {
        Ok((try_get(bytes)?, 16))
    }

    fn dump<W: Write>(&self, sink: &mut W) -> Result<()> {
        sink.write(&*self).map(|_| ())
    }
}

impl<'a, 'b: 'a> ParseDump<'b> for &'a [u8] {
    fn parse(bytes: &'b [u8]) -> Result<(Self, usize)> {
        let total = U32 + (try_u32(bytes)? as usize);
        Ok((bytes.get(U32..total).ok_or_else(|| too_short())?, total))
    }

    fn dump<W: Write>(&self, sink: &mut W) -> Result<()> {
        sink.write(&(self.len() as u32).to_be_bytes())?;
        sink.write(self).map(|_| ())
    }
}

impl<'a, 'b: 'a> ParseDump<'b> for &'a str {
    fn parse(bytes: &'b [u8]) -> Result<(Self, usize)> {
        let (slice, progress) = <&'a [u8]>::parse(bytes)?;
        Ok((from_utf8(slice).map_err(|e| {
            Error::new(ErrorKind::InvalidData, e)
        })?, progress))
    }

    fn dump<W: Write>(&self, sink: &mut W) -> Result<()> {
        self.as_bytes().dump(sink)
    }
}

impl<'a, 'b: 'a> ParseDump<'b> for &'a [&'a [u8]] {
    fn parse(_bytes: &'b [u8]) -> Result<(Self, usize)> {
        panic!("This is only intended for sha256!");
    }

    fn dump<W: Write>(&self, sink: &mut W) -> Result<()> {
        for slice in self.iter() {
            sink.write(slice).map(|_| ())?;
        }
        Ok(())
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum DisconnectReasonCode {
    HostNotAllowedToConnect = 1,
    ProtocolError = 2,
    KeyExchangeFailed = 3,
    Reserved = 4,
    MacError = 5,
    CompressionError = 6,
    ServiceNotAvailable = 7,
    ProtocolVersionNotSupported = 8,
    HostKeyNotVerifiable = 9,
    ConnectionLost = 10,
    ByApplication = 11,
    TooManyConnections = 12,
    AuthCancelledByUser = 13,
    NoMoreAuthMethodsAvailable = 14,
    IllegalUserName = 15,
}

impl<'b> ParseDump<'b> for DisconnectReasonCode {
    fn parse(bytes: &'b [u8]) -> Result<(Self, usize)> {
        let (byte, progress) = u8::parse(bytes)?;
        let reason = match byte {
            1 => Ok(Self::HostNotAllowedToConnect),
            2 => Ok(Self::ProtocolError),
            3 => Ok(Self::KeyExchangeFailed),
            4 => Ok(Self::Reserved),
            5 => Ok(Self::MacError),
            6 => Ok(Self::CompressionError),
            7 => Ok(Self::ServiceNotAvailable),
            8 => Ok(Self::ProtocolVersionNotSupported),
            9 => Ok(Self::HostKeyNotVerifiable),
            10 => Ok(Self::ConnectionLost),
            11 => Ok(Self::ByApplication),
            12 => Ok(Self::TooManyConnections),
            13 => Ok(Self::AuthCancelledByUser),
            14 => Ok(Self::NoMoreAuthMethodsAvailable),
            15 => Ok(Self::IllegalUserName),
            c => Err(Error::new(ErrorKind::InvalidData, format!("Invalid disconnect reason code: {}", c)))
        }?;
        Ok((reason, progress))
    }

    fn dump<W: Write>(&self, sink: &mut W) -> Result<()> {
        (*self as u8).dump(sink)
    }
}

fn try_get<const N: usize>(src: &[u8]) -> Result<[u8; N]> {
    let mut dst = [0; N];
    dst.copy_from_slice(src.get(..N).ok_or_else(|| too_short())?);
    Ok(dst)
}

fn try_u32(src: &[u8]) -> Result<u32> {
    try_get(src).map(|array| u32::from_be_bytes(array))
}
