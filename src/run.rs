use super::{Connection, ErrorKind, Result, Error};
use super::messages::{
    ChannelOpen, ChannelOpenConfirmation, ChannelRequest, ChannelClose,
    ChannelData, Message, ChannelExtendedData,
};

pub type ExitStatus = u32;

#[derive(Debug)]
pub enum RunResult<T: core::fmt::Debug> {
    Refused,
    Accepted(T),
}

impl Connection {
    pub fn run(&mut self, command: &str) -> Result<RunResult<Run>> {
        let client_channel = self.next_client_channel;
        self.next_client_channel += 1;

        self.writer.send(&ChannelOpen {
            channel_type: "session",
            client_channel,
            client_initial_window_size: u32::MAX,
            client_max_packet_size: 64 * 0x1000,
        })?;

        let ChannelOpenConfirmation {
            client_channel: _,
            server_channel,
            server_initial_window_size: _,
            server_max_packet_size: _,
        } = self.reader.recv()?;

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
            })),
            Message::ChannelFailure(_) => Ok(RunResult::Refused),
            msg => {
                let err_msg = format!("Unexpected message: {:#?}", msg);
                return Err(Error::new(ErrorKind::InvalidData, err_msg));
            },
        }
    }

    fn quick_run_internal(&mut self, command: &str, get_output: bool) -> Result<RunResult<(Option<Vec<u8>>, Option<ExitStatus>)>> {
        match self.run(command)? {
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
                        RunEvent::ExtDataStdout(data) => { output.as_mut().map(|o| o.extend_from_slice(data)); },
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
                    let errmsg = "Non-UTF-8 bytes in command output";
                    Error::new(ErrorKind::InvalidData, errmsg)
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
    server_channel: u32,
    client_channel: u32,
    exit_status: Option<ExitStatus>,
    closed: bool,
}

#[derive(Copy, Clone, Debug)]
pub enum RunEvent<'a> {
    None,
    Data(&'a [u8]),
    ExtDataStdout(&'a [u8]),
    Stopped(Option<ExitStatus>),
}

impl<'a> Run<'a> {
    pub fn poll(&mut self) -> Result<RunEvent> {
        let message = match self.conn.reader.recv() {
            Ok(message) => message,
            Err(e) => return match e.kind() {
                ErrorKind::WouldBlock | ErrorKind::TimedOut => Ok(RunEvent::None),
                _ => Err(e),
            },
        };

        match message {
            Message::ChannelData(ChannelData {
                recipient_channel: _,
                data,
            }) => Ok(RunEvent::Data(data)),
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
            }) => Ok(RunEvent::ExtDataStdout(data)),
            msg => {
                let err_msg = format!("Unexpected message: {:#?}", msg);
                return Err(Error::new(ErrorKind::InvalidData, err_msg));
            },
        }
    }

    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        match self.closed {
            false => self.conn.writer.send(&ChannelData {
                recipient_channel: self.server_channel,
                data,
            }),
            true => Err(Error::new(ErrorKind::BrokenPipe, "Process has already exited")),
        }
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
