use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::Decoder;
use std::convert::{From,TryFrom,TryInto};
use std::fmt::Formatter;

#[derive(Clone,Debug)]
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

#[derive(Clone, Debug)]
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

    pub fn is_expose(&self) -> bool {
        matches!(self, Self::Expose)
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

#[derive(Clone)]
pub struct Instruction {
    directive: Directive,
    content: Bytes,
    mode: Option<Mode>
}

impl std::fmt::Debug for Instruction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Ok(content) = std::str::from_utf8(self.content.as_ref()) {
            write!(f, "*Begin Instruction*\nDirective: {}\nContent: {}\nMode: {:?}\n*End Instruction*", self.directive, content, self.mode)
        } else {
            write!(f, "*Begin Instruction*\nDirective: {}\nContent: [invalid utf8 in content]\nMode: {:?}\n*End Instruction*", self.directive, self.mode)
        }
    }
}

impl Instruction {
    pub fn is_entrypoint(&self) -> bool {
        self.directive.is_entrypoint()
    }

    pub fn is_cmd(&self) -> bool {
        self.directive.is_cmd()
    }

    pub fn is_expose(&self) -> bool {
        self.directive.is_expose()
    }
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

#[derive(Debug, PartialEq)]
enum StringToken {
    SingleQuote,
    DoubleQuote
}

impl TryFrom<u8> for StringToken {
    type Error = DecodeError;

    fn try_from(token: u8) -> Result<Self, Self::Error> {
        let matched_token = match token {
            b'\'' => StringToken::SingleQuote,
            b'"' => StringToken::DoubleQuote,
            _ => return Err(DecodeError::UnexpectedToken)
        };
        Ok(matched_token)
    }
}

struct StringStack {
    inner: Vec<StringToken>
}

impl StringStack {
    fn new() -> Self {
        Self {
            inner: Vec::new()
        }
    }

    fn is_empty(&self) -> bool {
        self.inner.len() == 0
    }

    fn peek_top(&self) -> Option<&StringToken> {
        self.inner.iter().last()
    }

    fn pop(&mut self) -> Option<StringToken> {
        self.inner.pop()
    }

    fn push(&mut self, token: StringToken) {
        self.inner.push(token);
    }
}

impl std::fmt::Display for StringStack {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.inner)
    }
}

enum DecoderState {
    ReadingDirective(BytesMut),
    ReadingDirectiveArguments {
        directive: Directive,
        arguments: Option<BytesMut>,
        new_line_behaviour: NewLineBehaviour,
        directive_mode: Option<Mode>,
        string_stack: StringStack,
    },
    ReadingComment {
        content: BytesMut,
    },
    ReadingWhitespace
}

impl std::convert::TryInto<Option<Instruction>> for DecoderState {
    type Error = DecodeError;

    fn try_into(self) -> Result<Option<Instruction>, Self::Error> {
        match self {
            Self::ReadingComment { content } => Ok(Some(Instruction {
                directive: Directive::Comment,
                content: Bytes::from(content),
                mode: None
            })),
            Self::ReadingDirectiveArguments {
                directive,
                directive_mode,
                arguments,
                ..
            } => {
                let arguments = arguments.ok_or(DecodeError::IncompleteInstruction)?;
                Ok(Some(Instruction {
                    directive,
                    content: Bytes::from(arguments),
                    mode: directive_mode,
                }))
            },
            _ => Ok(None)
        }
    }
}

#[derive(Debug)]
pub enum DecodeError {
    IoError(tokio::io::Error),
    UnexpectedToken,
    NonUtf8Directive(std::str::Utf8Error),
    IncompleteInstruction
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
            Ok(Self::ReadingComment {
                content: BytesMut::new(),
            })
        } else {
            Err(DecodeError::UnexpectedToken)
        }
    }
}

pub struct DockerfileDecoder {
    current_state: Option<DecoderState>,
    eof_reached: bool
}

impl DockerfileDecoder {
    pub fn new() -> Self {
        Self {
            current_state: None,
            eof_reached: false
        }
    }

    pub fn set_eof(&mut self, eof: bool) {
        self.eof_reached = eof;
    }

    pub fn eof(&self) -> bool {
        self.eof_reached
    }

    pub fn flush(self) -> Option<Instruction> {
        self.current_state?.try_into().unwrap_or(None)
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
            DecoderState::ReadingComment {
                content: BytesMut::with_capacity(1),
            }
        } else {
            return Err(DecodeError::UnexpectedToken);
        };

        Ok(Some(initial_state))
    }

    fn decode_whitespace(&mut self, src: &mut BytesMut) -> Result<Option<DecoderState>, DecodeError> {
        // Read until end of whitespace
        let new_char = loop {
            match self.read_u8(src) {
                Some(byte) if byte.is_ascii_whitespace() => continue,
                Some(byte) => break byte,
                None => return Ok(None)
            }
        };

        self.derive_new_line_state(new_char)
    }

    fn decode_comment(&mut self, src: &mut BytesMut, content: &mut BytesMut) -> Result<Option<Instruction>, DecodeError> {
        loop {
            match self.read_u8(src) {
                Some(next_byte) if next_byte == b'\n' => {
                    return Ok(Some(Instruction {
                        directive: Directive::Comment,
                        content: Bytes::from(content.to_vec()),
                        mode: None
                    }));
                },
                Some(next_byte) => {
                    content.put_u8(next_byte);
                },
                None => {
                    return Ok(None);
                }
            };
        }
    }

    fn decode_directive(&mut self, src: &mut BytesMut, directive: &mut BytesMut) -> Result<Option<DecoderState>, DecodeError> {
        loop {
            match self.read_u8(src) {
                Some(byte) if byte == b' ' => {
                    return Ok(Some(DecoderState::ReadingDirectiveArguments {
                        directive: Directive::try_from(directive.as_ref())?,
                        directive_mode: None,
                        arguments: None,
                        new_line_behaviour: NewLineBehaviour::Observe,
                        string_stack: StringStack::new(),
                    }));
                }
                Some(byte) if byte.is_ascii() => {
                    directive.put_u8(byte);
                    continue;
                },
                Some(_) => return Err(DecodeError::UnexpectedToken),
                None => return Ok(None)
            }
        }
    }

    fn decode_directive_arguments(
        &mut self,
        src: &mut BytesMut,
        directive: &Directive,
        arguments: &mut Option<BytesMut>,
        new_line_behaviour: &mut NewLineBehaviour,
        directive_mode: &mut Option<Mode>,
        string_stack: &mut StringStack
    ) -> Result<Option<Instruction>, DecodeError> {
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
                                *new_line_behaviour = NewLineBehaviour::Observe;
                            } else if new_line_behaviour.is_observe() {
                                *new_line_behaviour = NewLineBehaviour::Escaped;
                            }
                            arguments.as_mut().unwrap().put_u8(next_byte);
                            continue;
                        },
                        b'\n' if new_line_behaviour.is_escaped() || new_line_behaviour.is_ignore_line() => {
                            if arguments.is_none() {
                                *arguments = Some(BytesMut::new());
                            }
                            let argument_mut = arguments.as_mut().unwrap();
                            argument_mut.put_u8(next_byte);
                            continue;
                        },
                        b'\n' => {
                            self.current_state = None;
                            let content = arguments.as_ref().unwrap().to_vec(); // TODO: potential panic
                            return Ok(Some(Instruction {
                                directive: directive.clone(),
                                content: Bytes::from(content),
                                mode: directive_mode.clone()
                            }));
                        },
                        b'#' => {
                            // if comment is not part of a string
                            if string_stack.is_empty() {
                                let is_newline_comment = arguments.as_ref()
                                    .map(|bytes| bytes.ends_with(b"\\\n"))
                                    .unwrap_or(false);
                                if is_newline_comment {
                                    *new_line_behaviour = NewLineBehaviour::IgnoreLine;
                                } else {
                                    *new_line_behaviour = NewLineBehaviour::Observe;
                                }
                            }
                            if arguments.is_none() {
                                *arguments = Some(BytesMut::new());
                            }
                            let argument_mut = arguments.as_mut().unwrap();
                            argument_mut.put_u8(next_byte);
                        },
                        char => {
                            if arguments.is_none() {
                                // first char determines shell vs exec
                                if directive.is_cmd() || directive.is_entrypoint() {
                                    *directive_mode = Some(Mode::from(char));
                                }
                                *arguments = Some(BytesMut::new());
                            }
                            let argument_mut = arguments.as_mut().unwrap();
                            argument_mut.put_u8(char);

                            if new_line_behaviour.is_escaped() {
                                *new_line_behaviour = NewLineBehaviour::Observe;
                            }

                            if char == b'\'' || char == b'"' {
                                let token = StringToken::try_from(char).unwrap();
                                if string_stack.peek_top() == Some(&token) {
                                    string_stack.pop();
                                } else {
                                    string_stack.push(token);
                                }
                            }
                            continue;
                        }
                    }
                }
                None => return Ok(None)
            }
        }
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

        loop {
            let next_state = match decode_state {
                DecoderState::ReadingWhitespace => self.decode_whitespace(src)?,
                DecoderState::ReadingComment {
                    mut content
                } => {
                    return match self.decode_comment(src, &mut content)? {
                        Some(instruction) => Ok(Some(instruction)),
                        None => {
                            self.current_state = Some(DecoderState::ReadingComment {
                                content
                            });
                            Ok(None)
                        }
                    };
                },
                DecoderState::ReadingDirective(mut directive) => {
                    let next_state = self.decode_directive(src, &mut directive)?;
                    if next_state.is_none() {
                        self.current_state = Some(DecoderState::ReadingDirective(directive));
                    }
                    next_state
                },
                DecoderState::ReadingDirectiveArguments {
                    directive,
                    mut arguments,
                    mut new_line_behaviour,
                    mut directive_mode,
                    mut string_stack
                } => {
                    return match self.decode_directive_arguments(
                        src,
                        &directive,
                        &mut arguments,
                        &mut new_line_behaviour,
                        &mut directive_mode,
                        &mut string_stack
                    )? {
                        Some(instruction) => Ok(Some(instruction)),
                        None => {
                            self.current_state = Some(DecoderState::ReadingDirectiveArguments {
                                directive,
                                arguments,
                                new_line_behaviour,
                                directive_mode,
                                string_stack
                            });
                            Ok(None)
                        }
                    };
                },
            };

            match next_state {
                Some(next_state) => {
                    decode_state = next_state;
                },
                None => return Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decoding_of_directive_with_comments() {
        let mut decoder = DockerfileDecoder::new();
        let test_directive = "ENTRYPOINT echo 'Test' # emits Test";
        let directive_with_new_line = format!("{}\n", test_directive);
        let mut dockerfile_content = BytesMut::from(directive_with_new_line.as_str());
        let mut instructions = Vec::new();
        loop {
            let emitted_instruction = decoder.decode(&mut dockerfile_content);
            assert_eq!(emitted_instruction.is_ok(), true); // expect no errors
            match emitted_instruction.unwrap() {
                Some(instruction) => instructions.push(instruction),
                None => break
            }
        }
        assert_eq!(instructions.len(), 1);
        let instruction = instructions.pop().unwrap();
        assert_eq!(instruction.is_entrypoint(), true);
        assert_eq!(instruction.to_string(), String::from(test_directive));
    }
}
