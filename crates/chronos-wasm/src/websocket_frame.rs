//! Bounded parser for unmasked binary WebSocket frames used by local tests.
//!
//! This is a frame parser only. It does not establish a network connection,
//! provide traffic camouflage, or implement a browser transport.

#[derive(Debug, PartialEq, Eq)]
pub enum WebSocketFrameError {
    MalformedHeader,
    MaskedFrameUnsupported,
    PayloadTooLarge,
    TruncatedData,
    LengthOverflow,
}

pub struct WebSocketBinaryFrameParser {
    max_frame_size: usize,
}

impl WebSocketBinaryFrameParser {
    pub fn new(max_frame_size: usize) -> Self {
        Self { max_frame_size }
    }

    /// Parses one complete, unmasked FIN binary frame and returns its payload.
    pub fn parse_binary_frame<'a>(&self, data: &'a [u8]) -> Result<&'a [u8], WebSocketFrameError> {
        if data.len() < 2 {
            return Err(WebSocketFrameError::TruncatedData);
        }
        if data[0] != 0x82 {
            return Err(WebSocketFrameError::MalformedHeader);
        }
        if data[1] & 0x80 != 0 {
            return Err(WebSocketFrameError::MaskedFrameUnsupported);
        }
        let length_marker = data[1] & 0x7f;
        let (payload_len, header_len): (usize, usize) = match length_marker {
            0..=125 => (usize::from(length_marker), 2),
            126 => {
                if data.len() < 4 {
                    return Err(WebSocketFrameError::TruncatedData);
                }
                (usize::from(u16::from_be_bytes([data[2], data[3]])), 4)
            }
            127 => {
                if data.len() < 10 {
                    return Err(WebSocketFrameError::TruncatedData);
                }
                let declared = u64::from_be_bytes(data[2..10].try_into().expect("fixed slice"));
                let length =
                    usize::try_from(declared).map_err(|_| WebSocketFrameError::LengthOverflow)?;
                (length, 10)
            }
            _ => return Err(WebSocketFrameError::MalformedHeader),
        };
        if payload_len > self.max_frame_size {
            return Err(WebSocketFrameError::PayloadTooLarge);
        }
        let end = header_len
            .checked_add(payload_len)
            .ok_or(WebSocketFrameError::LengthOverflow)?;
        if data.len() < end {
            return Err(WebSocketFrameError::TruncatedData);
        }
        Ok(&data[header_len..end])
    }
}

impl Default for WebSocketBinaryFrameParser {
    fn default() -> Self {
        Self::new(16_384)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bounded_unmasked_binary_payload() {
        let parser = WebSocketBinaryFrameParser::default();
        assert_eq!(
            parser.parse_binary_frame(&[0x82, 3, 1, 2, 3]),
            Ok(&[1, 2, 3][..])
        );
    }

    #[test]
    fn rejects_masked_and_truncated_frames() {
        let parser = WebSocketBinaryFrameParser::default();
        assert_eq!(
            parser.parse_binary_frame(&[0x82, 0x80]),
            Err(WebSocketFrameError::MaskedFrameUnsupported)
        );
        assert_eq!(
            parser.parse_binary_frame(&[0x82, 126, 0]),
            Err(WebSocketFrameError::TruncatedData)
        );
    }
}
