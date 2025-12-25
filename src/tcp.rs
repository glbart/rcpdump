use crate::shared::{ParseError, take_next_bytes};

#[derive(Debug)]
pub struct TcpPacket<'a> {
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    ack_number: u32,
    data_offset: u8,
    reserved: u8,
    URG: bool,
    ACK: bool,
    PSH: bool,
    RST: bool,
    SYN: bool,
    FIN: bool,
    window: u16,
    checksum: u16,
    urgent_pointer: u16,
    payload: &'a [u8],
}

impl TcpPacket<'_> {
    const MIN_SIZE: usize = 20;

    pub fn try_parse<'a>(data: &'a [u8]) -> Result<TcpPacket<'a>, ParseError> {
        if data.len() < Self::MIN_SIZE {
            return Err(ParseError::UnexpectedEOF);
        }

        let mut cursor = data;

        // first 2 bytes is source_port
        let source_port = u16::from_be_bytes(take_next_bytes::<2>(&mut cursor)?);

        // next 2 bytes is destination_port
        let destination_port = u16::from_be_bytes(take_next_bytes::<2>(&mut cursor)?);

        // next 4 bytes is sequence_number
        let sequence_number = u32::from_be_bytes(take_next_bytes::<4>(&mut cursor)?);

        // next 4 bytes is ack_number
        let ack_number = u32::from_be_bytes(take_next_bytes::<4>(&mut cursor)?);

        // next 2 bytes = data_offset (4 bit) + reserved (6 bit) + URG (1 bit) + ACK (1 bit) + PSH (1 bit) + RST (1 bit)  + SYN (1 bit) + FIN (1 bit)
        let bytes = u16::from_be_bytes(take_next_bytes::<2>(&mut cursor)?);

        let data_offset = (bytes >> 12) as u8;
        let reserved = ((bytes >> 6) & 0x3F) as u8;

        let flags = (bytes & 0x3F) as u8;

        let URG = flags & 0b0010000 != 0;
        let ACK = flags & 0b0001000 != 0;
        let PSH = flags & 0b0001000 != 0;
        let RST = flags & 0b0000100 != 0;
        let SYN = flags & 0b0000010 != 0;
        let FIN = flags & 0b0000001 != 0;

        // next 2 bytes is window
        let window = u16::from_be_bytes(take_next_bytes::<2>(&mut cursor)?);

        // next 2 bytes is checksum
        let checksum = u16::from_be_bytes(take_next_bytes::<2>(&mut cursor)?);

        // next 2 bytes is urgent_pointer
        let urgent_pointer = u16::from_be_bytes(take_next_bytes::<2>(&mut cursor)?);

        // temporary skip options + padding
        let payload = &data[(data_offset * 4) as usize..];

        Ok(TcpPacket {
            source_port,
            destination_port,
            sequence_number,
            ack_number,
            data_offset,
            reserved,
            URG,
            ACK,
            PSH,
            RST,
            SYN,
            FIN,
            window,
            checksum,
            urgent_pointer,
            payload,
        })
    }

    pub fn format_output(&self) {
        println!("Transmission Control Protocol");
        println!("\tSource port: {}", self.source_port);
        println!("\tDestination port: {}", self.destination_port);
        println!("\tSequence number: {}", self.sequence_number);
        println!("\tAcknowledgment number: {}", self.ack_number);
        println!("\tHeader length: {}", self.data_offset * 4);
        println!("\tFlags:");
        println!("\t\tUrgent: {}", self.URG);
        println!("\t\tAcknowledgment: {}", self.ACK);
        println!("\t\tPush: {}", self.PSH);
        println!("\t\tReset: {}", self.RST);
        println!("\t\tSyn: {}", self.SYN);
        println!("\t\tFin: {}", self.FIN);
        println!("\tWindow size value: {}", self.window);
        println!("\tChecksum: 0x{:04x}", self.checksum);
    }
}
