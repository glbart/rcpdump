use crate::shared::{ParseError, take_next_bytes};
use std::fmt;

#[derive(Debug)]
pub struct IPv4Packet<'a> {
    version: u8,
    header_length: u8,
    type_of_service: u8,
    total_length: u16,
    identification: u16,
    flags: u8,
    fragment_offset: u16,
    ttl: u8,
    pub protocol: InternetProtocol,
    raw_protocol: u8,
    header_checksum: u16,
    source_address: IPv4Addr,
    destination_address: IPv4Addr,
    pub payload: &'a [u8],
}

#[derive(Debug)]
pub enum InternetProtocol {
    ICMP = 1,
    IGMP = 2,
    GGP = 3,
    IPinIP = 4,
    TCP = 6,
    UDP = 17,
    Unknown,
}

#[derive(Debug)]
struct IPv4Addr {
    address: [u8; 4],
}

impl IPv4Addr {
    fn from_bytes(bytes: [u8; 4]) -> Self {
        Self { address: bytes }
    }
}

impl IPv4Packet<'_> {
    const MIN_SIZE: usize = 20;

    pub fn try_parse(data: &[u8]) -> Result<IPv4Packet<'_>, ParseError> {
        if data.len() < Self::MIN_SIZE {
            return Err(ParseError::UnexpectedEOF);
        }

        let mut cursor = data;

        // first byte = 4 + 4 bits : version + hdr_length
        let first = u8::from_be_bytes(take_next_bytes::<1>(&mut cursor)?);
        let version = u8::from_be(first >> 4);
        let header_length = u8::from_be(first & 0x0F);

        // next byte type of service
        let type_of_service = u8::from_be_bytes(take_next_bytes::<1>(&mut cursor)?);

        // next 2 bytes total length
        let total_length = u16::from_be_bytes(take_next_bytes::<2>(&mut cursor)?);

        // next 2 bytes identification
        let identification = u16::from_be_bytes(take_next_bytes::<2>(&mut cursor)?);

        // next 2 bytes = 3 bit flags + 13 bit fragment offset
        let bytes = u16::from_be_bytes(take_next_bytes::<2>(&mut cursor)?);
        let flags = (bytes >> 13) as u8;
        let fragment_offset = bytes & 0x1FFF;

        // next byte ttl
        let ttl = u8::from_be_bytes(take_next_bytes::<1>(&mut cursor)?);

        // next byte protocol
        let raw_protocol = u8::from_be_bytes(take_next_bytes::<1>(&mut cursor)?);
        let protocol = InternetProtocol::try_from(raw_protocol)?;

        // next 2 bytes header_checksum
        let header_checksum = u16::from_be_bytes(take_next_bytes::<2>(&mut cursor)?);

        // next 4 bytes source address
        let source_address = IPv4Addr::from_bytes(take_next_bytes::<4>(&mut cursor)?);

        // next 4 bytes destination address
        let destination_address = IPv4Addr::from_bytes(take_next_bytes::<4>(&mut cursor)?);

        // temporary skip options fileld an padding
        let payload = &data[(header_length * 4) as usize..];

        Ok(IPv4Packet {
            version,
            header_length,
            type_of_service,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            raw_protocol,
            protocol,
            header_checksum,
            source_address,
            destination_address,
            payload,
        })
    }

    pub fn format_output(&self) {
        println!("Internet Protocol Version 4");
        println!("\tVersion: {}", self.version);
        println!("\tHeader length: {}", self.header_length);
        println!("\tTotal length: {}", self.total_length);
        println!("\tIdentification: 0x{:04x}", self.identification);
        println!("\tFlags: {}", self.flags);
        println!("\tFragment offset: {}", self.fragment_offset);
        println!("\tTTL: {}", self.ttl);
        println!("\tProtocol: {:?} ({})", self.protocol, self.raw_protocol);
        println!("\tHeader checkshum: 0x{:04x}", self.header_checksum);
        println!("\tSoruce: {}", self.source_address);
        println!("\tDestination: {}", self.destination_address);
    }
}

impl fmt::Display for IPv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.address[0], self.address[1], self.address[2], self.address[3]
        )
    }
}

impl TryFrom<u8> for InternetProtocol {
    type Error = ParseError;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            1 => Ok(InternetProtocol::ICMP),
            2 => Ok(InternetProtocol::IGMP),
            3 => Ok(InternetProtocol::GGP),
            4 => Ok(InternetProtocol::IPinIP),
            6 => Ok(InternetProtocol::TCP),
            17 => Ok(InternetProtocol::UDP),
            _ => Ok(InternetProtocol::Unknown),
        }
    }
}
