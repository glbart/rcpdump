use crate::shared::{ParseError, take_next_bytes};
use std::fmt;

#[derive(Debug)]
pub enum FrameType {
    IPv4,
    IPv6,
    ARP,
    FARP,
    PPP,
    Unknown,
}

impl TryFrom<u16> for FrameType {
    type Error = ParseError;

    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            0x0800 => Ok(FrameType::IPv4),
            0x0806 => Ok(FrameType::ARP),
            0x0808 => Ok(FrameType::FARP),
            0x86DD => Ok(FrameType::IPv6),
            0x880B => Ok(FrameType::PPP),
            _ => Ok(FrameType::Unknown),
        }
    }
}

#[derive(Debug)]
pub struct EthernetFrame<'a> {
    mac_dest: MacAddress,
    mac_source: MacAddress,
    pub frame_type: FrameType,
    raw_type: u16,
    pub payload: &'a [u8],
}

impl EthernetFrame<'_> {
    const MIN_SIZE: usize = 64;

    pub fn try_parse(data: &[u8]) -> Result<EthernetFrame<'_>, ParseError> {
        if data.len() < Self::MIN_SIZE {
            return Err(ParseError::UnexpectedEOF);
        }

        let mut cursor = data;

        // first 6 bytes is mac_dest
        let mac_dest = MacAddress::from_bytes(take_next_bytes::<6>(&mut cursor)?);
        // next 6 bytes is mac_source
        let mac_source = MacAddress::from_bytes(take_next_bytes::<6>(&mut cursor)?);

        // next 2 bytes is frame type
        let raw_type = u16::from_be_bytes(take_next_bytes::<2>(&mut cursor)?);
        let frame_type = FrameType::try_from(raw_type)?;

        Ok(EthernetFrame {
            mac_dest,
            mac_source,
            frame_type,
            raw_type,
            payload: &data[14..],
        })
    }

    pub fn format_output(&self) {
        println!("Ethernet Frame");
        println!("\tDestination: {}", self.mac_dest);
        println!("\tSoruce: {}", self.mac_source);
        println!("\tType: {:?} (0x{:04X})", self.frame_type, self.raw_type);
    }
}

#[derive(Debug)]
struct MacAddress {
    address: [u8; 6],
}

impl MacAddress {
    fn from_bytes(bytes: [u8; 6]) -> Self {
        Self { address: bytes }
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            self.address[0],
            self.address[1],
            self.address[2],
            self.address[3],
            self.address[4],
            self.address[5]
        )
    }
}
