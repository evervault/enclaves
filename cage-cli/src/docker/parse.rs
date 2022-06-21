use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::Decoder;
use std::convert::{From,TryFrom};
use std::fmt::Formatter;

#[derive(Debug)]
pub enum Mode {
    Exec,
    Shell
}

impl From<u8> for Mode {
    fn from(byte: u8) -> Self {
        if byte == b'[' {
            Self::Exec
        } else {
            Self::Shell
        }
    }
}

pub enum Directive {
    Comment,
    Entrypoint,
    Cmd,
    Expose,
    // we only need to care about entrypoint, cmd and expose for cages
    Other(String)
}

impl Directive {
    pub fn is_cmd(&self) -> bool {
        matches!(self, Self::Cmd)
    }

    pub fn is_entrypoint(&self) -> bool {
        matches!(self, Self::Entrypoint)
    }
}

impl std::fmt::Display for Directive {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Comment => write!(f, "#"),
            Self::Entrypoint => write!(f, "ENTRYPOINT"),
            Self::Cmd => write!(f, "CMD"),
            Self::Expose => write!(f, "EXPOSE"),
            Self::Other(directive) => write!(f, "{}", directive)
        }
    }
}

impl TryFrom<&[u8]> for Directive {
    type Error = DecodeError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let directive_str = std::str::from_utf8(value)
            .map_err(|err| DecodeError::NonUtf8Directive(err))?;

        if directive_str.starts_with("#") {
            return Ok(Self::Comment);
        }

        let directive = match directive_str.to_ascii_uppercase().as_str() {
            "ENTRYPOINT" => Self::Entrypoint,
            "CMD" => Self::Cmd,
            "EXPOSE" => Self::Expose,
            _ => Self::Other(directive_str.to_string())
        };

        Ok(directive)
    }
}

pub struct Instruction {
    directive: Directive,
    content: Bytes,
    mode: Option<Mode>
}

impl std::fmt::Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let content_str = std::str::from_utf8(self.content.as_ref()).expect("Non utf8 content");
        match self.directive {
            Directive::Expose | Directive::Cmd if self.mode.is_some() => {
                write!(f, "{} {} # {:?}", self.directive, content_str, self.mode.as_ref().unwrap())
            },
            _ => write!(f, "{} {}", self.directive, content_str)
        }
    }
}

enum NewLineBehaviour {
    Escaped,
    IgnoreLine, // handle embedded comments
    Observe,
}

impl NewLineBehaviour {
    pub fn is_escaped(&self) -> bool {
        matches!(self, Self::Escaped)
    }

    pub fn is_observe(&self) -> bool {
        matches!(self, Self::Observe)
    }

    pub fn is_ignore_line(&self) -> bool {
        matches!(self, Self::IgnoreLine)
    }
}

enum DecoderState {
    ReadingDirective(BytesMut),
    ReadingDirectiveArguments {
        directive: Directive,
        arguments: Option<BytesMut>,
        new_line_behaviour: NewLineBehaviour,
        directive_mode: Option<Mode>
    },
    ReadingComment(BytesMut),
    ReadingWhitespace
}

impl DecoderState {
    fn is_reading_whitespace(&self) -> bool {
        matches!(self, Self::ReadingWhitespace)
    }
}

#[derive(Debug)]
pub enum DecodeError {
    IoError(tokio::io::Error),
    UnexpectedToken,
    NonUtf8Directive(std::str::Utf8Error)
}

impl From<std::io::Error> for DecodeError {
    fn from(io_err: std::io::Error) -> Self {
        DecodeError::IoError(io_err)
    }
}

impl std::convert::TryFrom<u8> for DecoderState {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value.is_ascii_whitespace() {
            Ok(Self::ReadingWhitespace)
        } else if value.is_ascii_alphabetic() {
            let mut bytes = BytesMut::with_capacity(1);
            bytes.put_u8(value);
            Ok(Self::ReadingDirective(bytes))
        } else if value == b'#' {
            Ok(Self::ReadingComment(BytesMut::new()))
        } else {
            Err(DecodeError::UnexpectedToken)
        }
    }
}

pub struct DockerfileDecoder {
    current_state: Option<DecoderState>,
}

impl DockerfileDecoder {
    pub fn new() -> Self {
        Self {
            current_state: None
        }
    }

    fn read_u8(&mut self, src: &mut BytesMut) -> Option<u8> {
        if src.has_remaining() {
            Some(src.get_u8())
        } else {
            None
        }
    }

    fn derive_new_line_state(&mut self, first_byte: u8) -> Result<Option<DecoderState>, DecodeError> {
        let initial_state = if first_byte.is_ascii_whitespace() {
            DecoderState::ReadingWhitespace
        } else if first_byte.is_ascii_alphabetic() {
            let mut bytes = BytesMut::with_capacity(1);
            bytes.put_u8(first_byte);
            DecoderState::ReadingDirective(bytes)
        } else if first_byte == b'#' {
            DecoderState::ReadingComment(BytesMut::with_capacity(1))
        } else {
            return Err(DecodeError::UnexpectedToken);
        };

        Ok(Some(initial_state))
    }
}

impl Decoder for DockerfileDecoder {
    type Item = Instruction;
    type Error = DecodeError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {

        let mut decode_state = if self.current_state.is_none() {
            let first_byte = match self.read_u8(src) {
                Some(byte) => byte,
                None => return Ok(None)
            };
            match self.derive_new_line_state(first_byte)? {
                Some(initial_state) => initial_state,
                None => return Ok(None)
            }
        } else {
          self.current_state.take().unwrap()
        };

        if decode_state.is_reading_whitespace() {
            // Read until end of whitespace
            let new_char = loop {
                match self.read_u8(src) {
                    Some(byte) if byte.is_ascii_whitespace() => continue,
                    Some(byte) => break byte,
                    None => return Ok(None)
                }
            };

            match self.derive_new_line_state(new_char)? {
                Some(new_line_state) => {
                    decode_state = new_line_state;
                },
                None => return Ok(None)
            }
        };

        match decode_state {
            DecoderState::ReadingDirective(mut directive) => {
                loop {
                    match self.read_u8(src) {
                        Some(byte) => {
                            if byte == b' ' {
                                self.current_state = Some(DecoderState::ReadingDirectiveArguments {
                                    directive: Directive::try_from(directive.as_ref())?,
                                    directive_mode: None,
                                    arguments: None,
                                    new_line_behaviour: NewLineBehaviour::Observe,
                                });
                                return Ok(None);
                            } else if byte.is_ascii() {
                                directive.put_u8(byte);
                                continue;
                            } else {
                                return Err(DecodeError::UnexpectedToken);
                            }
                        },
                        None => {
                            self.current_state = Some(DecoderState::ReadingDirective(directive));
                            return Ok(None);
                        }
                    }
                }
                // Read until space
            },
            DecoderState::ReadingDirectiveArguments {
                mut arguments,
                mut new_line_behaviour,
                directive,
                mut directive_mode
            } => {
                // read until new line, not preceded by '\'
                loop {
                    match self.read_u8(src) {
                        Some(next_byte) if (next_byte == b'\n' || next_byte == b'\\') && arguments.is_none() => {
                            return Err(DecodeError::UnexpectedToken)
                        },
                        Some(next_byte) => {
                            // ignore backslash in the middle of arguments
                            if arguments.is_none() {
                                if next_byte == b' ' {
                                    continue;
                                }
                            }
                            match next_byte {
                                b'\\' => {
                                    if new_line_behaviour.is_escaped() {
                                        new_line_behaviour = NewLineBehaviour::Observe;
                                    } else if new_line_behaviour.is_observe() {
                                        new_line_behaviour = NewLineBehaviour::Escaped;
                                    }
                                    arguments.as_mut().unwrap().put_u8(next_byte);
                                    continue;
                                },
                                b'\n' if new_line_behaviour.is_escaped() || new_line_behaviour.is_ignore_line() => {
                                    if arguments.is_none() {
                                        arguments = Some(BytesMut::new());
                                    }
                                    let argument_mut = arguments.as_mut().unwrap();
                                    argument_mut.put_u8(next_byte);
                                    continue;
                                },
                                b'\n' => {
                                    self.current_state = None;
                                    return Ok(Some(Instruction {
                                        directive,
                                        content: Bytes::from(arguments.unwrap()),
                                        mode: directive_mode
                                    }));
                                },
                                b'#' => {
                                    // comment embedded in a directive
                                    // TODO: account for comments embedded in strings
                                    new_line_behaviour = NewLineBehaviour::IgnoreLine;
                                    if arguments.is_none() {
                                        arguments = Some(BytesMut::new());
                                    }
                                    let argument_mut = arguments.as_mut().unwrap();
                                    argument_mut.put_u8(next_byte);
                                    println!("Comment in directive");
                                },
                                char => {
                                    if arguments.is_none() {
                                        // first char
                                        if directive.is_cmd() || directive.is_entrypoint() {
                                            directive_mode = Some(Mode::from(char));
                                        }
                                        arguments = Some(BytesMut::new());
                                    }
                                    let argument_mut = arguments.as_mut().unwrap();
                                    new_line_behaviour = NewLineBehaviour::Observe;
                                    argument_mut.put_u8(char);
                                    continue;
                                }
                            }
                        }
                        None => {
                            self.current_state = Some(DecoderState::ReadingDirectiveArguments {
                                arguments,
                                new_line_behaviour,
                                directive,
                                directive_mode
                            });
                            return Ok(None);
                        }
                    }
                }
            },
            DecoderState::ReadingComment(mut comment_bytes) => {
                // read until new line
                loop {
                    match self.read_u8(src) {
                        Some(next_byte) if next_byte == b'\n' => {
                            self.current_state = None;
                            return Ok(Some(Instruction {
                                directive: Directive::Comment,
                                content: Bytes::from(comment_bytes),
                                mode: None
                            }));
                        },
                        Some(next_byte) => {
                            comment_bytes.put_u8(next_byte);
                        },
                        None => return Ok(None)
                    };
                }
            },
            _ => Ok(None)
        }
    }
}
