use super::{Result, Error, Write, U8, U32};
use super::parse_dump_struct;
use super::parsedump::{ParseDump, too_short, try_u32};
pub use super::userauth::UserauthRequest;
pub use super::channelrequest::ChannelRequest;

// Use with caution: copy-pasting
// and leaving the wrong variant name
// can lead to stack overflow
#[doc(hidden)]
#[macro_export]
macro_rules! check_msg_type {
    ($name:ident, $expected:expr, $bytes:ident) => {
        let raw_msg_type = u8::parse($bytes)?.0;
        let msg_type = MessageType::try_from(raw_msg_type)?;
        if msg_type != $expected {
            let (msg, _) = $crate::messages::Message::parse($bytes)?;
            log::error!(concat!("Expected ", stringify!($name), " message but got {:#?}"), msg);
            return Err(Error::UnexpectedMessageType(msg_type));
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum Message<'a> {
    Disconnect(Disconnect<'a>),
    Ignore,
    Unimplemented(Unimplemented),
    Debug,
    ServiceRequest(ServiceRequest<'a>),
    ServiceAccept(ServiceAccept<'a>),
    Kexinit(Kexinit<'a>),
    Newkeys(Newkeys),
    KexdhInit(KexdhInit<'a>),
    KexdhReply(KexdhReply<'a>),
    UserauthRequest(UserauthRequest<'a>),
    UserauthFailure(UserauthFailure<'a>),
    UserauthSuccess(UserauthSuccess),
    UserauthPkOk(UserauthPkOk<'a>),
    GlobalRequest(GlobalRequest<'a>),
    RequestSuccess,
    RequestFailure,
    ChannelOpen(ChannelOpen<'a>),
    ChannelOpenConfirmation(ChannelOpenConfirmation),
    ChannelOpenFailure(ChannelOpenFailure<'a>),
    ChannelWindowAdjust(ChannelWindowAdjust),
    ChannelData(ChannelData<'a>),
    ChannelExtendedData(ChannelExtendedData<'a>),
    ChannelEof(ChannelEof),
    ChannelClose(ChannelClose),
    ChannelRequest(ChannelRequest<'a>),
    ChannelSuccess(ChannelSuccess),
    ChannelFailure(ChannelFailure),
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
    server_public_host_key: Blob<'a>,
    server_ephemeral_pubkey: &'a [u8],
    exchange_hash_signature: Blob<'a>,
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

parse_dump_struct!(UserauthSuccess {});

parse_dump_struct!(UserauthPkOk<'a> {
    algorithm: &'a str,
    blob: Blob<'a>,
});

parse_dump_struct!(UserauthFailure<'a> {
    allowed_auth: &'a str,
    partial_success: bool,
});

parse_dump_struct!(ChannelOpen<'a> {
    channel_type: &'a str,
    client_channel: u32,
    client_initial_window_size: u32,
    client_max_packet_size: u32,
});

parse_dump_struct!(ChannelOpenConfirmation {
    client_channel: u32,
    server_channel: u32,
    server_initial_window_size: u32,
    server_max_packet_size: u32,
});

parse_dump_struct!(ChannelOpenFailure<'a> {
    client_channel: u32,
    reason_code: u32,
    description: &'a str,
    language_tag: &'a str,
});

parse_dump_struct!(ChannelData<'a> {
    recipient_channel: u32,
    data: &'a [u8],
});

parse_dump_struct!(ChannelExtendedData<'a> {
    recipient_channel: u32,
    data_type: u32,
    data: &'a [u8],
});

parse_dump_struct!(ChannelEof {
    recipient_channel: u32,
});

parse_dump_struct!(ChannelClose {
    recipient_channel: u32,
});

parse_dump_struct!(ChannelSuccess {
    recipient_channel: u32,
});

parse_dump_struct!(ChannelFailure {
    recipient_channel: u32,
});

parse_dump_struct!(GlobalRequest<'a> {
    request_name: &'a str,
    want_reply: bool,
});

parse_dump_struct!(ChannelWindowAdjust {
    recipient_channel: u32,
    bytes_to_add: u32,
});

// utils, not messages:

parse_dump_struct!(ExchangeHash<'a> {
    client_header: &'a [u8],
    server_header: &'a [u8],
    client_kexinit_payload: &'a [u8],
    server_kexinit_payload: &'a [u8],
    server_public_host_key: Blob<'a>,
    client_ephemeral_pubkey: &'a [u8],
    server_ephemeral_pubkey: &'a [u8],
    shared_secret: UnsignedMpInt<'a>,
});

parse_dump_struct!(Blob<'a> {
    blob_len: u32,
    header: &'a str,
    content: &'a [u8],
});

macro_rules! forward_and_wrap {
    ($variant:ident, $rem:ident) => ( $variant::parse($rem).map(|(inner, p)| (Self::$variant(inner), p)) )
}

impl<'a, 'b: 'a> ParseDump<'b> for Message<'a> {
    fn parse(bytes: &'b [u8]) -> Result<(Self, usize)> {
        let typ = *bytes.get(0).ok_or_else(|| too_short())?;
        match MessageType::try_from(typ)? {

            MessageType::Disconnect => forward_and_wrap!(Disconnect, bytes),
            MessageType::Unimplemented => forward_and_wrap!(Unimplemented, bytes),
            MessageType::ServiceRequest => forward_and_wrap!(ServiceRequest, bytes),
            MessageType::ServiceAccept => forward_and_wrap!(ServiceAccept, bytes),
            MessageType::Kexinit => forward_and_wrap!(Kexinit, bytes),
            MessageType::Newkeys => forward_and_wrap!(Newkeys, bytes),
            MessageType::KexdhInit => forward_and_wrap!(KexdhInit, bytes),
            MessageType::KexdhReply => forward_and_wrap!(KexdhReply, bytes),
            MessageType::UserauthRequest => forward_and_wrap!(UserauthRequest, bytes),
            MessageType::UserauthFailure => forward_and_wrap!(UserauthFailure, bytes),
            MessageType::UserauthSuccess => forward_and_wrap!(UserauthSuccess, bytes),
            MessageType::UserauthPkOk => forward_and_wrap!(UserauthPkOk, bytes),
            MessageType::ChannelOpen => forward_and_wrap!(ChannelOpen, bytes),
            MessageType::ChannelOpenConfirmation => forward_and_wrap!(ChannelOpenConfirmation, bytes),
            MessageType::ChannelOpenFailure => forward_and_wrap!(ChannelOpenFailure, bytes),
            MessageType::ChannelData => forward_and_wrap!(ChannelData, bytes),
            MessageType::ChannelExtendedData => forward_and_wrap!(ChannelExtendedData, bytes),
            MessageType::ChannelEof => forward_and_wrap!(ChannelEof, bytes),
            MessageType::ChannelWindowAdjust => forward_and_wrap!(ChannelWindowAdjust, bytes),
            MessageType::ChannelClose => forward_and_wrap!(ChannelClose, bytes),
            MessageType::ChannelSuccess => forward_and_wrap!(ChannelSuccess, bytes),
            MessageType::ChannelFailure => forward_and_wrap!(ChannelFailure, bytes),
            MessageType::ChannelRequest => forward_and_wrap!(ChannelRequest, bytes),
            MessageType::GlobalRequest => forward_and_wrap!(GlobalRequest, bytes),

            typ => {
                log::error!("Unimplemented: Message::parse() for {:?}", typ);
                Err(Error::Unimplemented)
            },
        }
    }

    fn dump<W: Write>(&self, sink: &mut W) -> Result<()> {
        (self.typ() as u8).dump(sink)?;
        match self {
            Self::Disconnect(inner) => inner.dump(sink),
            Self::Unimplemented(inner) => inner.dump(sink),
            Self::ServiceRequest(inner) => inner.dump(sink),
            Self::ServiceAccept(inner) => inner.dump(sink),
            Self::Kexinit(inner) => inner.dump(sink),
            Self::Newkeys(inner) => inner.dump(sink),
            Self::KexdhInit(inner) => inner.dump(sink),
            Self::KexdhReply(inner) => inner.dump(sink),
            Self::UserauthRequest(inner) => inner.dump(sink),
            Self::UserauthFailure(inner) => inner.dump(sink),
            Self::UserauthSuccess(inner) => inner.dump(sink),
            Self::UserauthPkOk(inner) => inner.dump(sink),
            Self::ChannelOpen(inner) => inner.dump(sink),
            Self::ChannelOpenConfirmation(inner) => inner.dump(sink),
            Self::ChannelOpenFailure(inner) => inner.dump(sink),
            Self::ChannelData(inner) => inner.dump(sink),
            Self::ChannelExtendedData(inner) => inner.dump(sink),
            Self::ChannelEof(inner) => inner.dump(sink),
            Self::ChannelWindowAdjust(inner) => inner.dump(sink),
            Self::ChannelClose(inner) => inner.dump(sink),
            Self::ChannelSuccess(inner) => inner.dump(sink),
            Self::ChannelFailure(inner) => inner.dump(sink),
            Self::ChannelRequest(inner) => inner.dump(sink),
            Self::GlobalRequest(inner) => inner.dump(sink),

            typ => {
                log::error!("Unimplemented: Message::dump() for {:?}", typ);
                Err(Error::Unimplemented)
            },
        }
    }
}

impl<'a> Message<'a> {
    pub fn typ(&self) -> MessageType {
        match self {
            Self::Disconnect(_) => MessageType::Disconnect,
            Self::Ignore => MessageType::Ignore,
            Self::Unimplemented(_) => MessageType::Unimplemented,
            Self::Debug => MessageType::Debug,
            Self::ServiceRequest(_) => MessageType::ServiceRequest,
            Self::ServiceAccept(_) => MessageType::ServiceAccept,
            Self::Kexinit(_) => MessageType::Kexinit,
            Self::Newkeys(_) => MessageType::Newkeys,
            Self::KexdhInit(_) => MessageType::KexdhInit,
            Self::KexdhReply(_) => MessageType::KexdhReply,
            Self::UserauthRequest(_) => MessageType::UserauthRequest,
            Self::UserauthFailure(_) => MessageType::UserauthFailure,
            Self::UserauthSuccess(_) => MessageType::UserauthSuccess,
            Self::UserauthPkOk(_) => MessageType::UserauthPkOk,
            Self::GlobalRequest(_) => MessageType::GlobalRequest,
            Self::RequestSuccess => MessageType::RequestSuccess,
            Self::RequestFailure => MessageType::RequestFailure,
            Self::ChannelOpen(_) => MessageType::ChannelOpen,
            Self::ChannelOpenConfirmation(_) => MessageType::ChannelOpenConfirmation,
            Self::ChannelOpenFailure(_) => MessageType::ChannelOpenFailure,
            Self::ChannelWindowAdjust(_) => MessageType::ChannelWindowAdjust,
            Self::ChannelData(_) => MessageType::ChannelData,
            Self::ChannelExtendedData(_) => MessageType::ChannelExtendedData,
            Self::ChannelEof(_) => MessageType::ChannelEof,
            Self::ChannelClose(_) => MessageType::ChannelClose,
            Self::ChannelRequest(_) => MessageType::ChannelRequest,
            Self::ChannelSuccess(_) => MessageType::ChannelSuccess,
            Self::ChannelFailure(_) => MessageType::ChannelFailure,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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

            // hack: this allows ChannelRequestExec to dump the correct message type
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
            value => Err(Error::UnknownMessageType(value)),
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

            sink.write(self.0)?;
            Ok(())
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
            c => {
                log::error!("Invalid disconnect reason code: {}", c);
                Err(Error::InvalidData)
            },
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
            match haystack.split(",").position(|alg| alg == needle) {
                None => {
                    log::error!("Couldn't agree with peer on an algorithm set");
                    Err(Error::Unimplemented)
                },
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
