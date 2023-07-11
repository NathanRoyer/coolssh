use super::{Result, Error, ErrorKind, Write, U8, U32};
use super::parse_dump_struct;
use super::parsedump::{ParseDump, too_short, try_u32};

#[doc(hidden)]
#[macro_export]
macro_rules! check_msg_type {
    ($name:ident, $expected:expr, $bytes:ident) => {
        let raw_msg_type = u8::parse(&$bytes)?.0;
        let msg_type = MessageType::try_from(raw_msg_type)?;
        if msg_type != $expected {
            let err_msg = format!(concat!("Expected ", stringify!($name), " message but got {:?}"), msg_type);
            return Err(Error::new(ErrorKind::InvalidData, err_msg));
        }
    }
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
    UserauthBanner = 53,
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
    const fn from_struct_name(name: &str) -> Option<Self> {
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
            b"UserauthBanner" => Some(Self::UserauthBanner),
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
            53 => Ok(Self::UserauthBanner),
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

impl<'a> Kexinit<'a> {
    pub fn check_compat(&self, client: &Self) -> Result<()> {
        fn find(haystack: &str, needle: &str) -> Result<()> {
            let errmsg = "Couldn't agree with peer on an algorithm set";
            match haystack.split(",").position(|alg| alg == needle) {
                None => Err(Error::new(ErrorKind::Unsupported, errmsg)),
                Some(_) => Ok(()),
            }
        }

        find(self.kex_algorithms, client.kex_algorithms)?;
        find(self.server_host_key_algorithms, client.server_host_key_algorithms)?;
        find(self.encryption_algorithms_client_to_server, client.encryption_algorithms_client_to_server)?;
        find(self.encryption_algorithms_server_to_client, client.encryption_algorithms_server_to_client)?;
        find(self.mac_algorithms_client_to_server, client.mac_algorithms_client_to_server)?;
        find(self.mac_algorithms_server_to_client, client.mac_algorithms_server_to_client)?;
        find(self.compression_algorithms_client_to_server, client.compression_algorithms_client_to_server)?;
        find(self.compression_algorithms_server_to_client, client.compression_algorithms_server_to_client)
    }
}
