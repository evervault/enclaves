use itertools::{join};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::Decoder;
use std::convert::{From,TryFrom,TryInto};
use std::fmt::Formatter;

#[derive(Clone,Debug,PartialEq)]
pub enum Mode {
    Exec,
    Shell
}

impl Mode {
    pub fn is_shell(&self) -> bool {
        matches!(self, Self::Shell)
    }

    pub fn is_exec(&self) -> bool {
        matches!(self, Self::Exec)
    }
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
    Comment(Bytes),
    Entrypoint {
        mode: Option<Mode>,
        tokens: Vec<String>
    },
    Cmd {
        mode: Option<Mode>,
        tokens: Vec<String>
    },
    Expose(Bytes),
    Run(Bytes),
    // we only need to care about entrypoint, cmd, expose and run for cages
    Other {
        directive: String,
        arguments: Bytes
    }
}

impl Directive {
    pub fn is_cmd(&self) -> bool {
        matches!(self, Self::Cmd{ .. })
    }

    pub fn is_entrypoint(&self) -> bool {
        matches!(self, Self::Entrypoint{ .. })
    }

    pub fn is_expose(&self) -> bool {
        matches!(self, Self::Expose(_))
    }

    pub fn is_run(&self) -> bool {
        matches!(self, Self::Run(_))
    }

    pub fn set_mode(&mut self, new_mode: Mode) {
        match self {
            Self::Entrypoint { mode, .. } | Self::Cmd { mode, .. } => {
                *mode = Some(new_mode);
            },
            _ => panic!("Attempt to set mode on directive which is not Entrypoint or Cmd")
        }
    }

    pub fn mode(&self) -> Option<&Mode> {
        match self {
            Self::Entrypoint { mode, .. } | Self::Cmd { mode, .. } => mode.as_ref(),
            _ => None
        }
    }

    pub fn set_arguments(&mut self, given_arguments: Vec<u8>) {
        match self {
            Self::Entrypoint { mode, tokens } | Self::Cmd { mode, tokens } => {
                let mode = mode.as_ref().unwrap();
                if mode.is_exec() {
                    // docker exec commands are given in the form of: ["exec_cmd", "arg1", "arg2"]
                    // so to isolate the individual tokens we need to:
                    // - remove the first and last characters ('[', ']')
                    // - split on "," to get individual terms
                    // - trim each term and remove first and last ('"', '"')
                    let terms = &given_arguments[1..given_arguments.len()-1]; // remove square brackets
                    let parsed_tokens: Vec<String> = terms.split(|byte| &[*byte] == b",")
                        .filter_map(|token_slice| std::str::from_utf8(token_slice).ok())
                        .map(|token| {
                            let trimmed_token = token.trim();
                            let token_without_leading_quote = trimmed_token.strip_prefix("\"").unwrap_or(trimmed_token);
                            token_without_leading_quote.strip_suffix("\"").unwrap_or(token_without_leading_quote).to_string()
                        })
                        .collect();
                    *tokens = parsed_tokens;
                } else {
                    // docker shell commands are given in the form of: exec_cmd arg1 arg2
                    // so we need to split on space and convert to strings
                    *tokens = given_arguments.as_slice()
                        .split(|byte| &[*byte] == b" ")
                        .filter_map(|token_slice| std::str::from_utf8(token_slice).ok())
                        .map(|token_str| token_str.to_string())
                        .collect();
                }
            },
            Self::Expose(arguments) | Self::Other { arguments, .. } | Self::Comment(arguments) | Self::Run(arguments) => {
                *arguments = Bytes::from(given_arguments)
            }
        }
    }

    fn arguments(&self) -> String {
        match self {
            Self::Comment(bytes) | Self::Expose(bytes) | Self::Run(bytes) | Self::Other{ arguments: bytes, .. }=> {
                std::str::from_utf8(bytes.as_ref()).unwrap_or("[Invalid utf8 arguments]").to_string()
            },
            Self::Entrypoint { mode, tokens } | Self::Cmd { mode, tokens } => {
                if mode.as_ref().map(|mode| mode.is_exec()).unwrap_or(false) {
                    // Recreate an exec mode command — wrap tokens in quotes, and join with ", "
                    let exec_args = tokens.iter().map(|token| format!("\"{}\"", token));
                    format!("[{}]", join(exec_args, ", "))
                } else {
                    join(tokens.as_slice(), " ")
                }
            }
        }
    }

    pub fn tokens(&self) -> Option<&[String]> {
        match self {
            Self::Entrypoint { tokens, .. } | Self::Cmd { tokens, .. } => Some(tokens.as_slice()),
            _ => None
        }
    }

    pub fn new_entrypoint<T: Into<Vec<String>>>(mode: Mode, tokens: T) -> Self {
        Self::Entrypoint {
            mode: Some(mode),
            tokens: tokens.into()
        }
    }

    #[allow(dead_code)]
    pub fn new_cmd<T: Into<Vec<String>>>(mode: Mode, tokens: T) -> Self {
        Self::Cmd {
            mode: Some(mode),
            tokens: tokens.into()
        }
    }

    #[allow(dead_code)]
    pub fn new_run<B: Into<Bytes>>(arguments: B) -> Self {
        Self::Run(arguments.into())
    }
}

impl std::fmt::Display for Directive {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let prefix = match self {
            Self::Comment(_) => "#",
            Self::Entrypoint { .. } => "ENTRYPOINT",
            Self::Cmd { .. } => "CMD",
            Self::Expose(_) => "EXPOSE",
            Self::Run(_) => "RUN",
            Self::Other { directive, .. } => directive.as_str()
        };
        write!(f, "{} {}", prefix, self.arguments())
    }
}

impl TryFrom<&[u8]> for Directive {
    type Error = DecodeError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let directive_str = std::str::from_utf8(value)
            .map_err(|err| DecodeError::NonUtf8Directive(err))?;

        if directive_str.starts_with("#") {
            return Ok(Self::Comment(Bytes::new()));
        }

        let directive = match directive_str.to_ascii_uppercase().as_str() {
            "ENTRYPOINT" => Self::Entrypoint {
                mode: None,
                tokens: Vec::new()
            },
            "CMD" => Self::Cmd {
                mode: None,
                tokens: Vec::new()
            },
            "EXPOSE" => Self::Expose(Bytes::new()),
            "RUN" => Self::Run(Bytes::new()),
            _ => Self::Other { directive: directive_str.to_string(), arguments: Bytes::new() }
        };

        Ok(directive)
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

// tiny stack which is used to track if we are inside/outside of a string
// which helps with incorrectly treating # in strings as a comment
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

// States for the Dockerfile decoder's internal state management
enum DecoderState {
    ReadingDirective(BytesMut),
    ReadingDirectiveArguments {
        directive: Directive,
        arguments: Option<BytesMut>,
        new_line_behaviour: NewLineBehaviour,
        string_stack: StringStack,
    },
    ReadingComment(BytesMut),
    ReadingWhitespace
}

// Helper function to clear out any lingering state in the Decoder on eof
// Mainly used to prevent failed parsing when the final directive in a fail doesn't have a newline
impl std::convert::TryInto<Option<Directive>> for DecoderState {
    type Error = DecodeError;

    fn try_into(self) -> Result<Option<Directive>, Self::Error> {
        match self {
            Self::ReadingComment(content) => Ok(Some(Directive::Comment(Bytes::from(content)))),
            Self::ReadingDirectiveArguments {
                mut directive,
                arguments,
                ..
            } => {
                let arguments = arguments.ok_or(DecodeError::IncompleteInstruction)?;
                directive.set_arguments(arguments.to_vec());
                Ok(Some(directive))
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
            current_state: None,
        }
    }

    pub fn flush(self) -> Result<Option<Directive>,DecodeError> {
        if self.current_state.is_none() {
            Ok(None)
        } else {
            self.current_state.unwrap().try_into()
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

    fn decode_comment(&mut self, src: &mut BytesMut, content: &mut BytesMut) -> Result<Option<Directive>, DecodeError> {
        loop {
            match self.read_u8(src) {
                Some(next_byte) if next_byte == b'\n' => {
                    let comment_bytes = Bytes::from(content.to_vec());
                    return Ok(Some(Directive::Comment(comment_bytes)));
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
        directive: &mut Directive,
        arguments: &mut Option<BytesMut>,
        new_line_behaviour: &mut NewLineBehaviour,
        string_stack: &mut StringStack
    ) -> Result<Option<Directive>, DecodeError> {
        // read until new line, not preceded by '\'
        loop {
            match self.read_u8(src) {
                // if we see a newline character or backslash as the first character for a directives argument
                // return an error
                Some(next_byte) if (next_byte == b'\n' || next_byte == b'\\') && arguments.is_none() => {
                    return Err(DecodeError::UnexpectedToken)
                },
                // newline is either escaped or we are reading an embedded comment
                Some(next_byte) if next_byte == b'\n' && !new_line_behaviour.is_observe() => {
                    if arguments.is_none() {
                        *arguments = Some(BytesMut::new());
                    }
                    let argument_mut = arguments.as_mut().unwrap();
                    argument_mut.put_u8(next_byte);
                },
                // new line signifies end of directive if unescaped
                Some(next_byte) if next_byte == b'\n' => {
                    // safety: first arm will be matched if next_byte is a newline and arguments is None
                    let content = arguments.as_ref().unwrap().to_vec();
                    directive.set_arguments(content.clone());
                    return Ok(Some(directive.clone()));
                },
                // if a newline character is next, escape it, if already escaped then observe (\\)
                Some(next_byte) if next_byte == b'\\' => {
                    if new_line_behaviour.is_escaped() {
                        *new_line_behaviour = NewLineBehaviour::Observe;
                    } else if new_line_behaviour.is_observe() {
                        *new_line_behaviour = NewLineBehaviour::Escaped;
                    }
                    arguments.as_mut().unwrap().put_u8(next_byte);
                },
                // ignore leading space on directive arguments
                Some(next_byte) if next_byte == b' ' && arguments.is_none() => continue,
                Some(next_byte) if next_byte == b'#' => {
                    // check if # signifies a comment or is embedded within an instruction
                    if string_stack.is_empty() {
                        let is_newline_comment = arguments.as_ref()
                            .map(|bytes| bytes.ends_with(b"\\\n"))
                            .unwrap_or(false);
                        if is_newline_comment {
                            // ignore next newline — will terminate comment, not directive args
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
                // nothing special about this byte, so add to arguments buffer
                Some(next_byte) => {
                    if arguments.is_none() {
                        // first char for CMD & EXEC determines the mode (shell vs exec)
                        if directive.is_cmd() || directive.is_entrypoint() {
                            directive.set_mode(Mode::from(next_byte));
                        }
                        *arguments = Some(BytesMut::new());
                    }
                    let argument_mut = arguments.as_mut().unwrap();
                    argument_mut.put_u8(next_byte);

                    // only update new line behaviour when escaped (i.e. cancel \ if followed by non-newline char)
                    // if new line behaviour is set to ignore line, then we are in an embedded comment, new line remains escaped
                    if new_line_behaviour.is_escaped() {
                        *new_line_behaviour = NewLineBehaviour::Observe;
                    }

                    // if this byte is a string character, check if stack can be popped, else push
                    if next_byte == b'\'' || next_byte == b'"' {
                        let token = StringToken::try_from(next_byte).unwrap();
                        if string_stack.peek_top() == Some(&token) {
                            string_stack.pop();
                        } else {
                            string_stack.push(token);
                        }
                    }
                }
                None => return Ok(None)
            }
        }
    }
}

impl Decoder for DockerfileDecoder {
    type Item = Directive;
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
                DecoderState::ReadingComment(mut content) => {
                    return match self.decode_comment(src, &mut content)? {
                        Some(directive) => Ok(Some(directive)),
                        None => {
                            self.current_state = Some(DecoderState::ReadingComment(content));
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
                    mut directive,
                    mut arguments,
                    mut new_line_behaviour,
                    mut string_stack
                } => {
                    return match self.decode_directive_arguments(
                        src,
                        &mut directive,
                        &mut arguments,
                        &mut new_line_behaviour,
                        &mut string_stack
                    )? {
                        Some(instruction) => Ok(Some(instruction)),
                        None => {
                            self.current_state = Some(DecoderState::ReadingDirectiveArguments {
                                directive,
                                arguments,
                                new_line_behaviour,
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

    fn assert_directive_has_been_parsed(parsed_directive: Result<Option<Directive>, DecodeError>) -> Directive {
        assert_eq!(parsed_directive.is_ok(), true);
        let directive = parsed_directive.unwrap();
        assert_eq!(directive.is_some(), true);
        directive.unwrap()
    }

    fn assert_directive_has_not_been_parsed(parsed_directive: Result<Option<Directive>, DecodeError>) {
        assert_eq!(parsed_directive.is_ok(), true);
        let directive = parsed_directive.unwrap();
        assert_eq!(directive.is_none(), true);
    }

    #[test]
    fn test_decoding_of_directive_with_comments() {
        let mut decoder = DockerfileDecoder::new();
        let test_directive = "ENTRYPOINT echo 'Test' # emits Test";
        let directive_with_new_line = format!("{}\n", test_directive);
        let mut dockerfile_content = BytesMut::from(directive_with_new_line.as_str());
        let emitted_directive = decoder.decode(&mut dockerfile_content);
        let directive = assert_directive_has_been_parsed(emitted_directive);
        assert_eq!(directive.is_entrypoint(), true);
        assert_eq!(directive.to_string(), String::from(test_directive));
    }

    #[test]
    fn test_flush_on_file_without_final_newline() {
        let mut decoder = DockerfileDecoder::new();
        let test_directive = "ENTRYPOINT echo 'Test' # emits Test";
        let mut dockerfile_content = BytesMut::from(test_directive);
        let emitted_directive = decoder.decode(&mut dockerfile_content);
        assert_directive_has_not_been_parsed(emitted_directive);
        let flushed_directive = decoder.flush();
        let directive = assert_directive_has_been_parsed(flushed_directive);
        assert_eq!(directive.is_entrypoint(), true);
        assert_eq!(directive.to_string(), String::from(test_directive));
    }

    #[test]
    fn test_flush_on_incomplete_state() {
        let mut decoder = DockerfileDecoder::new();
        let test_directive = "ENTRYPOINT ";
        let mut dockerfile_content = BytesMut::from(test_directive);
        let emitted_directive = decoder.decode(&mut dockerfile_content);
        assert_directive_has_not_been_parsed(emitted_directive);
        let flushed_state = decoder.flush();
        assert_eq!(flushed_state.is_err(), true);
    }

    #[test]
    fn test_multiline_directive_with_embedded_comments() {
        let mut decoder = DockerfileDecoder::new();
        // using entrypoint for apk updates doesn't really make sense, purely for testing
        let test_dockerfile = r#"
FROM node:16-alpine3.14
ENTRYPOINT apk update && apk add python3 glib make g++ gcc libc-dev &&\
# clean apk cache
    rm -rf /var/cache/apk/* # testing"#;
        let mut dockerfile_content = BytesMut::from(test_dockerfile);
        let from_directive = decoder.decode(&mut dockerfile_content);
        assert_directive_has_been_parsed(from_directive);
        let emitted_directive = decoder.decode(&mut dockerfile_content);
        assert_directive_has_not_been_parsed(emitted_directive);
        let flushed_state = decoder.flush();
        let directive = assert_directive_has_been_parsed(flushed_state);
        assert_eq!(directive.is_entrypoint(), true);
        assert_eq!(directive.to_string(), String::from(r#"ENTRYPOINT apk update && apk add python3 glib make g++ gcc libc-dev &&\
# clean apk cache
    rm -rf /var/cache/apk/* # testing"#));
    }

    #[test]
    fn test_parsing_of_command_with_hashbang() {
        let mut decoder = DockerfileDecoder::new();
        let test_dockerfile = r#"RUN /bin/sh -c "echo -e '"'#!/bin/sh\necho "Hello, World!"'"' > /etc/service/hello_world/run""#;
        let dockerfile_contents = format!("{}\n", test_dockerfile);
        let mut buffer = BytesMut::from(dockerfile_contents.as_str());
        let run_directive = decoder.decode(&mut buffer);
        let directive = assert_directive_has_been_parsed(run_directive);
        assert_eq!(directive.to_string(),test_dockerfile.to_string());
    }

    #[test]
    fn test_parsing_of_command_with_uneven_apostrophes() {
        let mut decoder = DockerfileDecoder::new();
        let test_dockerfile = r#"RUN /bin/sh -c "echo -e '"'#!/bin/sh\necho "'"\n'"' > /etc/service/apostrophe/run""#;
        let dockerfile_contents = format!("{}\n", test_dockerfile);
        let mut buffer = BytesMut::from(dockerfile_contents.as_str());
        let run_directive = decoder.decode(&mut buffer);
        let directive = assert_directive_has_been_parsed(run_directive);
        assert_eq!(directive.to_string(),test_dockerfile.to_string());
    }

    #[test]
    fn test_parsing_of_entrypoint_exec_mode() {
        let mut decoder = DockerfileDecoder::new();
        let test_dockerfile = r#"ENTRYPOINT ["node", "server.js"]"#;
        let dockerfile_contents = format!("{}\n", test_dockerfile);
        let mut buffer = BytesMut::from(dockerfile_contents.as_str());
        let run_directive = decoder.decode(&mut buffer);
        let directive = assert_directive_has_been_parsed(run_directive);
        assert_eq!(directive.to_string(),test_dockerfile.to_string());
        assert_eq!(directive.is_entrypoint(),true);
        assert_eq!(directive.mode().unwrap(),&Mode::Exec);
    }

    #[test]
    fn test_parsing_of_entrypoint_shell_mode() {
        let mut decoder = DockerfileDecoder::new();
        let test_dockerfile = r#"ENTRYPOINT node server.js"#;
        let dockerfile_contents = format!("{}\n", test_dockerfile);
        let mut buffer = BytesMut::from(dockerfile_contents.as_str());
        let run_directive = decoder.decode(&mut buffer);
        let directive = assert_directive_has_been_parsed(run_directive);
        assert_eq!(directive.to_string(),test_dockerfile.to_string());
        assert_eq!(directive.is_entrypoint(),true);
        assert_eq!(directive.mode().unwrap(),&Mode::Shell);
    }

    #[test]
    fn test_parsing_of_cmd_exec_mode() {
        let mut decoder = DockerfileDecoder::new();
        let test_dockerfile = r#"CMD ["node", "server.js"]"#;
        let dockerfile_contents = format!("{}\n", test_dockerfile);
        let mut buffer = BytesMut::from(dockerfile_contents.as_str());
        let run_directive = decoder.decode(&mut buffer);
        let directive = assert_directive_has_been_parsed(run_directive);
        assert_eq!(directive.to_string(),test_dockerfile.to_string());
        assert_eq!(directive.is_cmd(),true);
        assert_eq!(directive.mode().unwrap(),&Mode::Exec);
    }

    #[test]
    fn test_parsing_of_cmd_shell_mode() {
        let mut decoder = DockerfileDecoder::new();
        let test_dockerfile = r#"CMD node server.js"#;
        let dockerfile_contents = format!("{}\n", test_dockerfile);
        let mut buffer = BytesMut::from(dockerfile_contents.as_str());
        let run_directive = decoder.decode(&mut buffer);
        let directive = assert_directive_has_been_parsed(run_directive);
        assert_eq!(directive.to_string(),test_dockerfile.to_string());
        assert_eq!(directive.is_cmd(),true);
        assert_eq!(directive.mode().unwrap(),&Mode::Shell);
    }

    #[test]
    fn test_constructor_for_run_commands() {
        let run_directive = Directive::new_run("echo 'Test'".to_string());
        assert_eq!(run_directive.is_run(), true);
        assert_eq!(run_directive.to_string(), String::from("RUN echo 'Test'"))
    }

    #[test]
    fn test_constructor_for_entrypoint_commands() {
        let entrypoint_directive = Directive::new_entrypoint(Mode::Shell, vec!["echo 'Test'".to_string()]);
        assert_eq!(entrypoint_directive.is_entrypoint(), true);
        assert_eq!(entrypoint_directive.mode().unwrap(), &Mode::Shell);
        assert_eq!(entrypoint_directive.to_string(), String::from("ENTRYPOINT echo 'Test'"))
    }

    #[test]
    fn test_constructor_for_cmd_commands() {
        let entrypoint_directive = Directive::new_cmd(Mode::Shell, vec!["echo 'Test'".to_string()]);
        assert_eq!(entrypoint_directive.is_cmd(), true);
        assert_eq!(entrypoint_directive.mode().unwrap(), &Mode::Shell);
        assert_eq!(entrypoint_directive.to_string(), String::from("CMD echo 'Test'"))
    }
}
