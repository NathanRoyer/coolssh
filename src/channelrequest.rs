use super::{Result, Error, ErrorKind, U8, Write};
use super::parsedump::ParseDump;
use super::messages::MessageType;
use super::check_msg_type;

#[derive(Copy, Clone, Debug)]
pub enum ChannelRequest<'a> {
    Exec {
        recipient_channel: u32,
        want_reply: bool,
        command: &'a str,
    },
    ExitStatus {
        recipient_channel: u32,
        exit_status: u32,
    },
    Other {
        recipient_channel: u32,
        request_type: &'a str,
        want_reply: bool,
    },
}

impl<'a, 'b: 'a> ParseDump<'b> for ChannelRequest<'a> {
    fn parse(bytes: &'b[u8]) -> Result<(Self, usize)> {
        check_msg_type!(ChannelRequest, MessageType::ChannelRequest, bytes);
        let mut i = U8;

        let (recipient_channel, inc) = u32::parse(&bytes[i..])?;
        i += inc;
        let (request_type, inc) = <&'a str>::parse(&bytes[i..])?;
        i += inc;
        let (want_reply, inc) = <bool>::parse(&bytes[i..])?;
        i += inc;

        match request_type {
            "exec" => {
                let (command, inc) = <&'a str>::parse(&bytes[i..])?;
                i += inc;

                Ok((Self::Exec {
                    recipient_channel,
                    want_reply,
                    command,
                }, i))
            },
            "exit-status" => {
                if want_reply {
                    let errmsg = "\"exit-status\" Channel Request with want_reply=true";
                    return Err(Error::new(ErrorKind::InvalidData, errmsg));
                }

                let (exit_status, inc) = u32::parse(&bytes[i..])?;
                i += inc;

                Ok((Self::ExitStatus {
                    recipient_channel,
                    exit_status,
                }, i))
            },
            _ => Ok((Self::Other {
                recipient_channel,
                request_type,
                want_reply,
            }, i)),
        }
    }

    fn dump<W: Write>(&self, sink: &mut W) -> Result<()> {
        (MessageType::ChannelRequest as u8).dump(sink)?;

        match self {
            Self::Exec {
                recipient_channel,
                want_reply,
                command,
            } => {
                recipient_channel.dump(sink)?;
                "exec".dump(sink)?;
                want_reply.dump(sink)?;
                command.dump(sink)?;
            },
            Self::ExitStatus {
                recipient_channel,
                exit_status,
            } => {
                recipient_channel.dump(sink)?;
                "exit-status".dump(sink)?;
                false.dump(sink)?;
                exit_status.dump(sink)?;
            },
            Self::Other { .. } => {
                let errmsg = "ChannelRequest::Other has no binary representation";
                return Err(Error::new(ErrorKind::Unsupported, errmsg));
            },
        }

        Ok(())
    }
}