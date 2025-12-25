#[derive(Debug)]
pub enum ParseError {
    UnexpectedEOF,
}

pub fn take_next_bytes<const N: usize>(data: &mut &[u8]) -> Result<[u8; N], ParseError> {
    let (part, rest) = data.split_at_checked(N).ok_or(ParseError::UnexpectedEOF)?;
    *data = rest;

    part.try_into().map_err(|_| ParseError::UnexpectedEOF)
}
