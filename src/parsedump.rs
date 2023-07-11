use core::str::from_utf8;
use super::{Result, Error, ErrorKind, U8, U32, Write};

pub (crate) fn too_short() -> Error {
    Error::new(ErrorKind::UnexpectedEof, "Missing Bytes / Input Too Short")
}

pub trait ParseDump<'b>: Sized {
    fn parse(bytes: &'b[u8]) -> Result<(Self, usize)>;
    fn dump<W: Write>(&self, sink: &mut W) -> Result<()>;
}

#[doc(hidden)]
#[macro_export]
macro_rules! parse_dump_struct_inner {
    ($name:ident { $($field:ident: $field_type:ty,)* }) => {
        fn parse(bytes: &'b [u8]) -> Result<(Self, usize)> {
            #[allow(unused_mut)]
            let mut i = if let Some(expected) = MessageType::from_struct_name(stringify!($name)) {
                $crate::check_msg_type!($name, expected, bytes);
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
            if let Some(msg_type) = MessageType::from_struct_name(stringify!($name)) {
                (msg_type as u8).dump(sink)?;
            }

            $(self.$field.dump(sink)?;)*
            Ok(())
        }
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! parse_dump_struct {
    ($name:ident<$lifetime:lifetime> { $($field:ident: $field_type:ty,)* }) => {
        #[derive(Debug)]
        pub struct $name<$lifetime> {
            $(
                pub $field: $field_type,
            )*
        }

        impl<$lifetime, 'b: $lifetime> $crate::parsedump::ParseDump<'b> for $name<$lifetime> {
            $crate::parse_dump_struct_inner!($name { $($field: $field_type,)* });
        }
    };
    ($name:ident { $($field:ident: $field_type:ty,)* }) => {
        #[derive(Debug)]
        pub struct $name {
            $(
                pub $field: $field_type,
            )*
        }

        impl<'b> $crate::parsedump::ParseDump<'b> for $name {
            $crate::parse_dump_struct_inner!($name { $($field: $field_type,)* });
        }
    };
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

pub fn try_get<const N: usize>(src: &[u8]) -> Result<[u8; N]> {
    let mut dst = [0; N];
    dst.copy_from_slice(src.get(..N).ok_or_else(|| too_short())?);
    Ok(dst)
}

pub fn try_u32(src: &[u8]) -> Result<u32> {
    try_get(src).map(|array| u32::from_be_bytes(array))
}
