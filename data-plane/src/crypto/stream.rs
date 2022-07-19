use super::parser;
use crate::crypto::parser::Ciphertext;
use bytes::{Buf, BytesMut};
use thiserror::Error;
use tokio_util::codec::Decoder;

pub enum IncomingFrame {
    Plaintext(Vec<u8>),
    Ciphertext(Ciphertext),
}

#[derive(Debug, Error)]
pub enum IncomingStreamError {
    #[error("Error occurred while parsing")]
    NomError,
    #[error("Failure occurred while parsing")]
    NomFailure,
    #[error("An IO error occurred")]
    IoError(#[from] std::io::Error),
}

pub struct IncomingStreamDecoder;

// first slice is the possible ciphertext, second byte is the data on the socket preceding it
pub type CiphertextCandidate<'a> = (&'a [u8], &'a [u8]);

impl IncomingStreamDecoder {
    fn find_next_ciphertext_candidate(
        src: &[u8],
    ) -> Result<Option<CiphertextCandidate>, IncomingStreamError> {
        match parser::find_ciphertext_prefix(src) {
            Err(nom::Err::Incomplete(_)) => Ok(None),
            Err(nom::Err::Error(_)) => Err(IncomingStreamError::NomError),
            Err(nom::Err::Failure(_)) => Err(IncomingStreamError::NomFailure),
            Ok(detected) => Ok(Some(detected)),
        }
    }
}

impl Decoder for IncomingStreamDecoder {
    type Item = IncomingFrame;
    type Error = IncomingStreamError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let next_candidate = Self::find_next_ciphertext_candidate(src.as_ref())?;
        if next_candidate.is_none() {
            // no ciphertext candidate
            let result = src.copy_to_bytes(src.len());
            return Ok(Some(IncomingFrame::Plaintext(result.to_vec())));
        }

        let (potential_ciphertext, prefix) = next_candidate.unwrap();
        let prefix_len = prefix.len();
        if prefix_len > 0 {
            let result = src.copy_to_bytes(prefix_len);
            return Ok(Some(IncomingFrame::Plaintext(result.to_vec())));
        }

        return match parser::parse_ciphertexts(potential_ciphertext) {
            Ok((_, Some(ciphertext))) => {
                src.advance(ciphertext.len());
                Ok(Some(IncomingFrame::Ciphertext(ciphertext)))
            }
            Ok((input, None)) => {
                let next_candidate = Self::find_next_ciphertext_candidate(&input[3..])?;
                if let Some((_, prefix)) = next_candidate {
                    let prefix_len = prefix.len();
                    let plaintext_data = src.copy_to_bytes(prefix_len + 3);
                    Ok(Some(IncomingFrame::Plaintext(plaintext_data.to_vec())))
                } else {
                    let entire_buffer = src.copy_to_bytes(src.len());
                    Ok(Some(IncomingFrame::Plaintext(entire_buffer.to_vec())))
                }
            }
            Err(nom::Err::Incomplete(_)) => Ok(None),
            Err(nom::Err::Error(_)) => Err(IncomingStreamError::NomError),
            Err(nom::Err::Failure(_)) => Err(IncomingStreamError::NomFailure),
        };
    }

    fn decode_eof(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.decode(buf) {
            Ok(Some(frame)) => Ok(Some(frame)),
            // We've hit EOF, can assume any remainder is plaintext
            Ok(None) => {
                let remainder = buf.copy_to_bytes(buf.remaining());
                Ok(Some(IncomingFrame::Plaintext(remainder.to_vec())))
            }
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use tokio_test::io::Builder;
    use tokio_util::codec::FramedRead;

    #[tokio::test]
    async fn test_stream_decoder() {
        // Create payload to read which has ciphertexts mixed with plaintext
        let sections: Vec<&str> = vec![
            "Lorem ipsum dolor sit amet, ",
            "ev:Tk9D:number:YGJVktHhdj3ds3wC:A6rkaTU8lez7NSBT8nTqbhBIu3tX4/lyH3aJVBUcGmLh:8hI5qEp32kWcVK367yaC09bDRbk:$",
            ". Praesent sit amet ultrices nibh, a egestas odio. ",
            "ev:RFVC:number:YGJVktHhdj3ds3wC:A6rkaTU8lez7NSBT8nTqbhBIu3tX4/lyH3aJVBUcGmLh:8hI5qEp32kWcVK367yaC09bDRbk:$",
            " taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Nunc pharetra massa odio, sed tempor nunc varius vel. Fusce vitae luctus quam. Nulla sed aliquet risus, eu porta sem. Etiam purus quam, imperdiet eu mollis at, semper ac justo. Aliquam id ultricies ante. Maecenas non elementum felis, in vehicula tortor. Integer posuere ullamcorper varius. Mauris aliquet mi sit amet pellentesque bibendum. Donec luctus efficitur mauris, eget sodales tortor consequat varius. Quisque eu feugiat lorem. Vivamus in tortor aliquam magna laoreet porta vel et ligula. Etiam in auctor eros. Mauris sodales lorem dui, eu commodo elit tincidunt vitae. Mauris ornare ac lorem quis vehicula. Nunc ornare lobortis ",
            "ev:YGJVktHhdj3ds3wC:A6rkaTU8lez7NSBT8nTqbhBIu3tX4/lyH3aJVBUcGmLh:8hI5qEp32kWcVK367yaC09bDRbk:$",
            ". Etiam a sapien sem. Quisque molestie suscipit tellus. Etiam gravida massa vitae lorem tristique suscipit. Donec euismod, ipsum nec hendrerit gravida, sapien mi vulputate nibh, eu mattis odio ",
            "ev:Tk9D:boolean:YGJVktHhdj3ds3wC:A6rkaTU8lez7NSBT8nTqbhBIu3tX4/lyH3aJVBUcGmLh:8hI5qEp32kWcVK367yaC09bDRbk:$",
            " mollis nulla. In finibus risus non lacus laoreet rutrum. Maecenas at libero nec enim pharetra vulputate eu sed nisi. Duis imperdiet suscipit tristique. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Praesent sit amet est at velit mollis maximus. Pellentesque consectetur mi at sapien vehicula condimentum."
        ];
        let content = sections.join("");
        let content_bytes = content.as_bytes();
        let mut mock_builder = Builder::new();
        mock_builder.read(content_bytes);
        let mock = mock_builder.build();

        let mut reader = FramedRead::new(mock, IncomingStreamDecoder);
        let frame1 = reader.next().await.transpose().unwrap(); // don't expect errors
        assert!(matches!(frame1, Some(IncomingFrame::Plaintext(_))));
        let frame2 = reader.next().await.transpose().unwrap(); // don't expect errors
        assert!(matches!(frame2, Some(IncomingFrame::Ciphertext(_))));
        let frame3 = reader.next().await.transpose().unwrap(); // don't expect errors
        assert!(matches!(frame3, Some(IncomingFrame::Plaintext(_))));
        let frame4 = reader.next().await.transpose().unwrap(); // don't expect errors
        assert!(matches!(frame4, Some(IncomingFrame::Ciphertext(_))));
        let frame5 = reader.next().await.transpose().unwrap(); // don't expect errors
        assert!(matches!(frame5, Some(IncomingFrame::Plaintext(_))));
        let frame6 = reader.next().await.transpose().unwrap(); // don't expect errors
        assert!(matches!(frame6, Some(IncomingFrame::Ciphertext(_))));
        let frame7 = reader.next().await.transpose().unwrap(); // don't expect errors
        assert!(matches!(frame7, Some(IncomingFrame::Plaintext(_))));
        let frame8 = reader.next().await.transpose().unwrap(); // don't expect errors
        assert!(matches!(frame8, Some(IncomingFrame::Ciphertext(_))));
        let frame9 = reader.next().await.transpose().unwrap(); // don't expect errors
        assert!(matches!(frame9, Some(IncomingFrame::Plaintext(_))));
    }

    #[tokio::test]
    async fn test_stream_decoder_with_incomplete_ciphertext() {
        let plaintext = "Lorem ipsum dolor sit amet, ";
        let sections: Vec<&str> = vec![
            plaintext,
            "ev:Tk9D:number:YGJVktHhdj3ds3wC:A6rkaTU8lez7NSBT8nTqbhBIu3tX4",
        ];
        let content = sections.join("");
        let content_bytes = content.as_bytes();
        let mut mock_builder = Builder::new();
        mock_builder.read(content_bytes);
        let mock = mock_builder.build();

        let mut reader = FramedRead::new(mock, IncomingStreamDecoder);
        let frame1 = reader.next().await.transpose().unwrap(); // don't expect errors
        let plaintext_bytes = plaintext.as_bytes();
        let _expected_frame = IncomingFrame::Plaintext(plaintext_bytes.to_vec());
        assert!(matches!(frame1, Some(_expected_frame)));
        let frame2 = reader.next().await.transpose().unwrap(); // don't expect errors
        assert!(matches!(frame2, Some(IncomingFrame::Plaintext(_))));
    }

    #[tokio::test]
    async fn test_stream_decoder_with_invalid_ciphertext() {
        let plaintext = "Lorem ipsum dolor sit amet, ";
        let sections: Vec<&str> = vec![
            plaintext,
            "ev:Tk9D:number:YGJVktHhdj3ds3wC:A6rkaTU8lez7NSBT8nTqbhBIu3tX4/lyH3aJVBUcGmLh:8@!£hI5qEp32kWcVK367yaC09bDRbk:$",
            ". Praesent sit amet ultrices nibh, a egestas odio. "
        ];
        let content = sections.join("");
        let content_bytes = content.as_bytes();
        let mut mock_builder = Builder::new();
        mock_builder.read(content_bytes);
        let mock = mock_builder.build();

        let mut reader = FramedRead::new(mock, IncomingStreamDecoder);
        let frame1 = reader.next().await.transpose().unwrap(); // don't expect errors
        let plaintext_bytes = plaintext.as_bytes();
        let _expected_frame = IncomingFrame::Plaintext(plaintext_bytes.to_vec());
        assert!(matches!(frame1, Some(_expected_frame)));
        let frame2 = reader.next().await.transpose().unwrap(); // don't expect errors
        assert!(matches!(frame2, Some(IncomingFrame::Plaintext(_))));
        let frame3 = reader.next().await.transpose().unwrap(); // don't expect errors
        assert!(matches!(frame3, Some(IncomingFrame::Plaintext(_))));
    }

    #[tokio::test]
    async fn test_stream_decoder_with_invalid_and_valid_ciphertexts() {
        let plaintext = "Lorem ipsum dolor sit amet, ";
        let sections: Vec<&str> = vec![
            plaintext,
            // invalid ciphertext
            "ev:Tk9D:number:YGJVktHhdj3ds3wC:A6rkaTU8lez7NSBT8nTqbhBIu3tX4/lyH3aJVBUcGmLh:8@!£hI5qEp32kWcVK367yaC09bDRbk:$",
            // valid ciphertext - test that stream will still recognize this
            "ev:Tk9D:boolean:YGJVktHhdj3ds3wC:A6rkaTU8lez7NSBT8nTqbhBIu3tX4/lyH3aJVBUcGmLh:8hI5qEp32kWcVK367yaC09bDRbk:$",
            ". Praesent sit amet ultrices nibh, a egestas odio. ",
            "ev:Tk9D:boolean:YGJVktHhdj3ds3wC:A6rkaTU8lez7NSBT8nTqbhBIu3tX4/lyH3aJVBUcGmLh:8hI5qEp32kWcVK367yaC09bDRbk:$",
        ];
        let content = sections.join("");
        let content_bytes = content.as_bytes();
        let mut mock_builder = Builder::new();
        mock_builder.read(content_bytes);
        let mock = mock_builder.build();

        let mut reader = FramedRead::new(mock, IncomingStreamDecoder);
        let frame1 = reader.next().await.transpose().unwrap(); // don't expect errors
        let plaintext_bytes = plaintext.as_bytes();
        let _expected_frame = IncomingFrame::Plaintext(plaintext_bytes.to_vec());
        assert!(matches!(frame1, Some(_expected_frame)));
        let frame2 = reader.next().await.transpose().unwrap(); // don't expect errors
        assert!(matches!(frame2, Some(IncomingFrame::Plaintext(_))));
        let frame3 = reader.next().await.transpose().unwrap(); // don't expect errors
        assert!(matches!(frame3, Some(IncomingFrame::Ciphertext(_))));
        let frame4 = reader.next().await.transpose().unwrap(); // don't expect errors
        assert!(matches!(frame4, Some(IncomingFrame::Plaintext(_))));
    }
}
