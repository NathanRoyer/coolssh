use super::{Connection, Result, Error};
use super::messages::{
    ChannelOpen, ChannelOpenConfirmation, ChannelRequest, ChannelClose,
    ChannelData, Message, ChannelExtendedData, ChannelWindowAdjust,
};

pub type ExitStatus = u32;

const CLIENT_INITIAL_WINDOW_SIZE: u32 = u32::MAX;
const CLIENT_WIN_TELL_TRIGGER: u32 = CLIENT_INITIAL_WINDOW_SIZE / 4;
const CLIENT_MAX_PACKET_SIZE: u32 = 64 * 0x1000;

#[derive(Debug)]
pub enum RunResult<T: core::fmt::Debug> {
    Refused,
    Accepted(T),
}

impl Connection {
    pub fn run(&mut self, command: &str, env: &[(&str, &str)]) -> Result<RunResult<Run>> {
        let client_channel = self.next_client_channel;
        self.next_client_channel += 1;

        self.writer.send(&ChannelOpen {
            channel_type: "session",
            client_channel,
            client_initial_window_size: CLIENT_INITIAL_WINDOW_SIZE,
            client_max_packet_size: CLIENT_MAX_PACKET_SIZE,
        })?;

        let ChannelOpenConfirmation {
            client_channel: _,
            server_channel,
            server_initial_window_size,
            server_max_packet_size,
        } = self.reader.recv()?;

        for (name, value) in env {
            self.writer.send(&ChannelRequest::EnvironmentVariable {
                recipient_channel: server_channel,
                want_reply: false,
                name,
                value,
            })?;
        }

        self.writer.send(&ChannelRequest::Exec {
            recipient_channel: server_channel,
            want_reply: true,
            command,
        })?;

        match self.reader.recv()? {
            Message::ChannelSuccess(_) => Ok(RunResult::Accepted(Run {
                conn: self,
                server_channel,
                client_channel,
                exit_status: None,
                closed: false,

                client_window: CLIENT_INITIAL_WINDOW_SIZE as _,
                server_window: server_initial_window_size as _,
                server_max_packet_size: server_max_packet_size as _,
            })),
            Message::ChannelFailure(_) => Ok(RunResult::Refused),
            msg => {
                log::error!("Unexpected message: {:#?}", msg);
                return Err(Error::UnexpectedMessageType(msg.typ()));
            },
        }
    }

    fn quick_run_internal(&mut self, command: &str, get_output: bool) -> Result<RunResult<(Option<Vec<u8>>, Option<ExitStatus>)>> {
        match self.run(command, &[])? {
            RunResult::Refused => Ok(RunResult::Refused),
            RunResult::Accepted(mut run) => {
                let mut output = match get_output {
                    true => Some(Vec::new()),
                    false => None,
                };

                loop {
                    match run.poll()? {
                        RunEvent::None => std::thread::sleep(std::time::Duration::from_millis(10)),
                        RunEvent::Data(data) => { output.as_mut().map(|o| o.extend_from_slice(data)); },
                        RunEvent::ExtDataStderr(data) => { output.as_mut().map(|o| o.extend_from_slice(data)); },
                        RunEvent::Stopped(exit_status) => return Ok(RunResult::Accepted((output, exit_status))),
                    }
                }
            },
        }
    }

    pub fn quick_run_bytes(&mut self, command: &str) -> Result<RunResult<(Vec<u8>, Option<ExitStatus>)>> {
        Ok(match self.quick_run_internal(command, true)? {
            RunResult::Refused => RunResult::Refused,
            RunResult::Accepted((None, _)) => unreachable!(),
            RunResult::Accepted((Some(vec), status)) => RunResult::Accepted((vec, status)),
        })
    }

    pub fn quick_run(&mut self, command: &str) -> Result<RunResult<(String, Option<ExitStatus>)>> {
        Ok(match self.quick_run_internal(command, true)? {
            RunResult::Refused => RunResult::Refused,
            RunResult::Accepted((None, _)) => unreachable!(),
            RunResult::Accepted((Some(bytes), status)) => {
                RunResult::Accepted((String::from_utf8(bytes).map_err(|_| {
                    log::error!("Non-UTF-8 bytes in command output");
                    Error::InvalidData
                })?, status))
            },
        })
    }

    pub fn quick_run_blind(&mut self, command: &str) -> Result<RunResult<Option<ExitStatus>>> {
        Ok(match self.quick_run_internal(command, false)? {
            RunResult::Refused => RunResult::Refused,
            RunResult::Accepted((None, status)) => RunResult::Accepted(status),
            RunResult::Accepted((Some(_), _)) => unreachable!(),
        })
    }
}

#[derive(Debug)]
pub struct Run<'a> {
    conn: &'a mut Connection,
    exit_status: Option<ExitStatus>,
    closed: bool,
    server_channel: u32,
    server_max_packet_size: usize,
    server_window: usize,
    client_window: usize,

    // todo: check it in incoming messages
    #[allow(dead_code)]
    client_channel: u32,
}

#[derive(Copy, Clone, Debug)]
pub enum RunEvent<'a> {
    None,
    Data(&'a [u8]),
    ExtDataStderr(&'a [u8]),
    Stopped(Option<ExitStatus>),
}

impl<'a> Run<'a> {
    pub fn poll(&mut self) -> Result<RunEvent> {
        let message = match self.conn.reader.recv() {
            Ok(message) => message,
            Err(Error::Timeout) => return Ok(RunEvent::None),
            Err(e) => return Err(e),
        };

        match message {
            Message::ChannelData(ChannelData {
                recipient_channel: _,
                data,
            }) => {
                self.client_window -= data.len();
                let cw = self.client_window as u32;
                if cw < CLIENT_WIN_TELL_TRIGGER {
                    self.conn.writer.send(&ChannelWindowAdjust {
                        recipient_channel: self.server_channel,
                        bytes_to_add: CLIENT_INITIAL_WINDOW_SIZE - cw,
                    })?;

                    self.client_window = CLIENT_INITIAL_WINDOW_SIZE as _;
                }
                Ok(RunEvent::Data(data))
            },
            Message::ChannelWindowAdjust(ChannelWindowAdjust {
                recipient_channel: _,
                bytes_to_add,
            }) => {
                self.server_window += bytes_to_add as usize;
                Ok(RunEvent::None)
            },
            Message::ChannelEof(_) => Ok(RunEvent::None),
            Message::ChannelClose(_) => {
                self.conn.writer.send(&ChannelClose {
                    recipient_channel: self.server_channel,
                })?;

                self.closed = true;

                Ok(RunEvent::Stopped(self.exit_status))
            },
            Message::ChannelRequest(ChannelRequest::ExitStatus {
                recipient_channel: _,
                exit_status,
            }) => {
                self.exit_status = Some(exit_status);
                Ok(RunEvent::None)
            },
            Message::ChannelExtendedData(ChannelExtendedData {
                recipient_channel: _,
                data_type: 1,
                data,
            }) => Ok(RunEvent::ExtDataStderr(data)),
            msg => {
                log::error!("Unexpected message: {:#?}", msg);
                return Err(Error::UnexpectedMessageType(msg.typ()));
            },
        }
    }

    /// Tries to send `data` over the run channel and calls `event_callback`
    /// if an event occurs during the transmission.
    ///
    /// Use this if the protocol you're using is full-duplex.
    pub fn write_poll<WPE: From<Error>, F: FnMut(RunEvent) -> core::result::Result<(), WPE>>(
        &mut self,
        mut data: &[u8],
        mut event_callback: F,
    ) -> core::result::Result<(), WPE> {
        if self.closed {
            return Err(Error::ProcessHasExited.into());
        }

        loop {
            let step = self.server_max_packet_size.min(self.server_window);
            if step >= data.len() {
                self.conn.writer.send(&ChannelData {
                    recipient_channel: self.server_channel,
                    data,
                })?;

                self.server_window -= data.len();

                break Ok(())
            } else if step > 0 {
                let (sendable, next) = data.split_at(step);

                self.conn.writer.send(&ChannelData {
                    recipient_channel: self.server_channel,
                    data: sendable,
                })?;

                self.server_window -= step;
                data = next;
            }

            match self.poll()? {
                RunEvent::None => (),
                e => event_callback(e)?,
            }
        }
    }

    /// Tries to send `data` over the run channel and returns the `on_event` error
    /// if an event occurs during the transmission.
    ///
    /// Use this if the protocol you're using is half-duplex.
    pub fn write<WPE: From<Error>>(&mut self, data: &[u8], on_event: WPE) -> core::result::Result<(), WPE> {
        let mut on_event = Some(on_event);
        self.write_poll(data, |data| {
            log::error!("Unexpected RunEvent in Run::write(): {:?}", data);
            Err(on_event.take().unwrap())
        })
    }
}

impl<'a> Drop for Run<'a> {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.conn.writer.send(&ChannelClose {
                recipient_channel: self.server_channel,
            });
        }
    }
}
