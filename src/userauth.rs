use super::{Result, Error, ErrorKind, U8, U32, Write};
use super::parsedump::ParseDump;
use super::messages::MessageType;
use super::check_msg_type;

#[derive(Debug)]
pub enum UserauthRequest<'a> {
    PublicKey {
        username: &'a str,
        service_name: &'a str,
        algorithm: &'a str,
        blob: &'a [u8],
        signature: Option<&'a [u8]>,
    },
    Password {
        username: &'a str,
        service_name: &'a str,
        password: &'a str,
        new_password: Option<&'a str>
    }
}

impl<'a, 'b: 'a> ParseDump<'b> for UserauthRequest<'a> {
    fn parse(bytes: &'b[u8]) -> Result<(Self, usize)> {
        check_msg_type!(UserauthRequest, MessageType::UserauthRequest, bytes);
        let mut i = U8;

        let (username, inc) = <&'a str>::parse(&bytes[i..])?;
        i += inc;
        let (service_name, inc) = <&'a str>::parse(&bytes[i..])?;
        i += inc;
        let (method_name, inc) = <&'a str>::parse(&bytes[i..])?;
        i += inc;
        let (has_option, inc) = <bool>::parse(&bytes[i..])?;
        i += inc;

        match method_name {
            "publickey" => {
                let (algorithm, inc) = <&'a str>::parse(&bytes[i..])?;
                i += inc;
                let (blob, inc) = <&'a [u8]>::parse(&bytes[i..])?;
                i += inc;

                let (signature, inc) = match has_option {
                    true => <&'a [u8]>::parse(&bytes[i..])?,
                    false => (b"".as_slice(), 0),
                };
                i += inc;

                Ok((Self::PublicKey {
                    username,
                    service_name,
                    algorithm,
                    blob,
                    signature: inc.checked_sub(U32).map(|_| signature),
                }, i))
            },
            "password" => {
                let (password, inc) = <&'a str>::parse(&bytes[i..])?;
                i += inc;

                let (new_password, inc) = match has_option {
                    true => <&'a str>::parse(&bytes[i..])?,
                    false => ("", 0),
                };
                i += inc;

                Ok((Self::Password {
                    username,
                    service_name,
                    password,
                    new_password: inc.checked_sub(U32).map(|_| new_password),
                }, i))
            },
            _ => {
                let errmsg = format!("Unsupported UserauthRequest Variant ({})", method_name);
                Err(Error::new(ErrorKind::Unsupported, errmsg))
            },
        }
    }

    fn dump<W: Write>(&self, sink: &mut W) -> Result<()> {
        (MessageType::UserauthRequest as u8).dump(sink)?;

        match self {
            Self::PublicKey {
                username,
                service_name,
                algorithm,
                blob,
                signature,
            } => {
                username.dump(sink)?;
                service_name.dump(sink)?;
                "publickey".dump(sink)?;
                signature.is_some().dump(sink)?;
                algorithm.dump(sink)?;
                blob.dump(sink)?;

                if let Some(signature) = signature {
                    signature.dump(sink)?;
                }
            },
            Self::Password {
                username,
                service_name,
                password,
                new_password,
            } => {
                username.dump(sink)?;
                service_name.dump(sink)?;
                "password".dump(sink)?;
                new_password.is_some().dump(sink)?;
                password.dump(sink)?;

                if let Some(new_password) = new_password {
                    new_password.dump(sink)?;
                }
            },
        }

        Ok(())
    }
}
