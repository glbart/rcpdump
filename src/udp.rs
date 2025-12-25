use crate::shared::ParseError;
use crate::shared::take_next_bytes;

pub struct UdpPacket<'a> {
    source_port: u16,
    destination_port: u16,
    length: u16,
    checksum: u16,
    payload: &'a [u8],
}

impl UdpPacket<'_> {
    const MIN_SIZE: usize = 8;
    pub fn try_parse<'a>(data: &'a [u8]) -> Result<UdpPacket<'a>, ParseError> {
        if data.len() < Self::MIN_SIZE {
            return Err(ParseError::UnexpectedEOF);
        }

        let mut cursor = data;

        // first 2 bytes is source_port
        let source_port = u16::from_be_bytes(take_next_bytes::<2>(&mut cursor)?);

        // next 2 bytes is destination_port
        let destination_port = u16::from_be_bytes(take_next_bytes::<2>(&mut cursor)?);

        // next 2 bytes is length
        let length = u16::from_be_bytes(take_next_bytes::<2>(&mut cursor)?);

        // next 2 bytes is checksum
        let checksum = u16::from_be_bytes(take_next_bytes::<2>(&mut cursor)?);

        let payload = &data[Self::MIN_SIZE..];

        Ok(UdpPacket {
            source_port,
            destination_port,
            length,
            checksum,
            payload,
        })
    }

    pub fn format_output(&self) {
        println!("User Datagram Protocol");
        println!("\tSource port: {}", self.source_port);
        println!("\tDestination port: {}", self.destination_port);
        println!("\tLength: {}", self.length);
        println!("\tChecksum: 0x{:04x}", self.checksum);
        println!(
            "\tData length: {} bytes",
            self.length - Self::MIN_SIZE as u16
        );
    }
}
