use std::{
    ffi::CString,
    fmt::{self},
    mem,
    os::fd::RawFd,
};

use anyhow::Result;
use clap::Parser;
use libc::{BIOCGBLEN, BIOCIMMEDIATE, BIOCSETIF, O_RDONLY, bpf_hdr, ifreq, ioctl, open, read};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    list_interfaces: bool,

    #[arg(short, long)]
    interface_name: String,
    //#[arg(short, long)]
    //count: usize,
}

fn main() {
    let args = Args::parse();

    if args.list_interfaces {
        print_network_interfaces();
        return;
    }

    let mut fd: RawFd = -1;

    for i in 0..255 {
        let bpf = format!("/dev/bpf{}", i);
        let bpf_c_str = CString::new(bpf).unwrap();
        fd = unsafe { open(bpf_c_str.as_ptr(), O_RDONLY) };

        if fd >= 0 {
            println!("open /dev/bpf{i}");
            break;
        }
    }

    if fd < 0 {
        println!("Не удалось открыть /dev/bpf (требуется root доступ)");
        return;
    }

    let mut ifr: ifreq = unsafe { mem::zeroed() };
    let if_name = args.interface_name;
    let bytes = if_name.as_bytes();
    for (i, &byte) in bytes.iter().enumerate().take(15) {
        ifr.ifr_name[i] = byte as libc::c_char;
    }

    let ioc = unsafe { ioctl(fd, BIOCSETIF, &mut ifr) };
    if ioc < 0 {
        return;
    }

    let enable = 1;
    // acivate immediate mode
    unsafe { ioctl(fd, BIOCIMMEDIATE, &enable) };

    let mut bufsize: usize = 0;

    // request buffer length
    unsafe { ioctl(fd, BIOCGBLEN, &mut bufsize) };

    // println!("buffer size: {}", bufsize);

    let mut buffer = vec![0u8; bufsize];

    loop {
        let bytes_read = unsafe { read(fd, buffer.as_mut_ptr() as *mut libc::c_void, bufsize) };

        if bytes_read <= 0 {
            continue;
        }

        // println!("read {} bytes", bytes_read);

        let mut offset = 0;

        while offset + mem::size_of::<bpf_hdr>() <= bytes_read as usize {
            let hdr_ptr = unsafe { buffer.as_ptr().add(offset) as *const bpf_hdr };
            let hdr = unsafe { &*hdr_ptr };

            let packet_data_prt = unsafe { buffer.as_ptr().add(offset + hdr.bh_hdrlen as usize) };
            let _packer_data =
                unsafe { std::slice::from_raw_parts(packet_data_prt, hdr.bh_caplen as usize) };

            // println!("Captured packet: {} bytes", hdr.bh_caplen);

            let frame = parse_frame(_packer_data);
            println!();
            println!("Ethernet Frame");
            println!("\tDestination: {}", frame.mac_dest);
            println!("\tSoruce: {}", frame.mac_source);
            println!("\tType: {:?} (0x{:04X}", frame.frame_type, frame.type_raw);

            match frame.frame_type {
                FrameType::IPv4 => {
                    let ip_packet = parse_IPv4(frame.payload);
                    println!("Internet Protocol Version 4");
                    println!("\tVersion: {}", ip_packet.version);
                    println!("\tHeader length: {}", ip_packet.header_length);
                    println!("\tTotal length: {}", ip_packet.total_length);
                    println!("\tIdentification: 0x{:04x}", ip_packet.identification);
                    println!("\tFlags: {}", ip_packet.flags);
                    println!("\tFragment offset: {}", ip_packet.fragment_offset);
                    println!("\tTTL: {}", ip_packet.ttl);
                    println!(
                        "\tProtocol: {:?} ({})",
                        ip_packet.protocol, ip_packet.raw_protocol
                    );
                    println!("\tHeader checkshum: 0x{:04x}", ip_packet.header_checksum);
                    println!("\tSoruce: {}", ip_packet.source_address);
                    println!("\tDestination: {}", ip_packet.destination_address);
                    println!();
                }
                _ => println!("Unknown payload"),
            }

            let allign = mem::size_of::<usize>() - 1;
            offset += (hdr.bh_hdrlen as usize + hdr.bh_caplen as usize + allign) & !allign;
        }
    }
}

fn print_network_interfaces() {
    let list = get_network_interfaces().unwrap();
    for (i, interface) in list.iter().enumerate() {
        println!("{}. {}", i, interface);
    }
}

fn get_network_interfaces() -> Result<Vec<String>> {
    let mut initerfaces_names: Vec<String> = Vec::new();
    let network_interfaces = NetworkInterface::show()?;
    for itf in network_interfaces.iter() {
        initerfaces_names.push(itf.name.to_string());
    }

    Ok(initerfaces_names)
}

#[derive(Debug)]
struct EthernetFrame<'a> {
    mac_dest: MacAddress,
    mac_source: MacAddress,
    frame_type: FrameType,
    type_raw: u16,
    payload: &'a [u8],
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

fn parse_frame<'a>(bytes: &'a [u8]) -> EthernetFrame<'a> {
    let mac_dest: [u8; 6] = bytes[..6].try_into().unwrap();
    let mac_source: [u8; 6] = bytes[6..12].try_into().unwrap();

    let protocol_bytes = u16::from_be_bytes(bytes[12..14].try_into().unwrap());
    let protocol_type = FrameType::try_from(protocol_bytes).unwrap();
    EthernetFrame {
        mac_dest: MacAddress::from_bytes(mac_dest),
        mac_source: MacAddress::from_bytes(mac_source),
        frame_type: protocol_type,
        type_raw: protocol_bytes,
        payload: &bytes[14..],
    }
}

#[derive(Debug)]
struct IPv4Packet {
    version: u8,
    header_length: u8,
    type_of_service: u8,
    total_length: u16,
    identification: u16,
    flags: u8,
    fragment_offset: u16,
    ttl: u8,
    protocol: InternetProtocol,
    raw_protocol: u8,
    header_checksum: u16,
    source_address: IPv4Addr,
    destination_address: IPv4Addr,
}

impl IPv4Packet {
    fn new() -> Self {
        Self {
            version: 0,
            header_length: 0,
            type_of_service: 0,
            total_length: 0,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            ttl: 0,
            protocol: InternetProtocol::Unknown,
            raw_protocol: 0,
            header_checksum: 0,
            source_address: IPv4Addr::empty(),
            destination_address: IPv4Addr::empty(),
        }
    }
}

#[derive(Debug)]
enum InternetProtocol {
    Reserved = 0,
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

    fn empty() -> Self {
        Self {
            address: [0, 0, 0, 0],
        }
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
    type Error = ();

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

fn parse_IPv4<'a>(bytes: &'a [u8]) -> IPv4Packet {
    let mut ip_packet = IPv4Packet::new();

    let mut cursor = bytes;

    // 4 + 4 bits : version + hdr_length
    if let Some((first, rest)) = cursor.split_first() {
        ip_packet.version = u8::from_be(*first >> 4);
        ip_packet.header_length = u8::from_be(*first & 0x0F);
        cursor = rest;
    }

    // next byte type of service
    if let Some((byte, rest)) = cursor.split_first() {
        ip_packet.type_of_service = u8::from_be(*byte);
        cursor = rest;
    }

    // next 2 bytes total length
    if let Some((byte, rest)) = cursor.split_at_checked(2) {
        ip_packet.total_length = u16::from_be_bytes(byte.try_into().unwrap());
        cursor = rest;
    }

    // next 2 bytes identification
    if let Some((byte, rest)) = cursor.split_at_checked(2) {
        ip_packet.identification = u16::from_be_bytes(byte.try_into().unwrap());
        cursor = rest;
    }

    // next 2 bytes = 3 bit flags + 13 bit fragment offset
    if let Some((byte, rest)) = cursor.split_at_checked(2) {
        ip_packet.flags = u8::from_be(byte[1] >> 5);
        let full_value = u16::from_be_bytes(byte.try_into().unwrap());
        ip_packet.fragment_offset = full_value & 0x1FFF;
        cursor = rest;
    }

    // next byte ttl
    if let Some((byte, rest)) = cursor.split_first() {
        ip_packet.ttl = u8::from_be(*byte);
        cursor = rest;
    }

    // next byte protocol
    if let Some((byte, rest)) = cursor.split_first() {
        ip_packet.protocol = InternetProtocol::try_from(*byte).unwrap();
        ip_packet.raw_protocol = u8::from_be(*byte);
        cursor = rest;
    }

    // next 2 bytes header_checksum
    if let Some((byte, rest)) = cursor.split_at_checked(2) {
        ip_packet.header_checksum = u16::from_be_bytes(byte.try_into().unwrap());
        cursor = rest;
    }

    // next 4 bytes source address
    if let Some((byte, rest)) = cursor.split_at_checked(4) {
        ip_packet.source_address = IPv4Addr::from_bytes(byte.try_into().unwrap());
        cursor = rest;
    }

    // next 4 bytes destination address
    if let Some((byte, rest)) = cursor.split_at_checked(4) {
        ip_packet.destination_address = IPv4Addr::from_bytes(byte.try_into().unwrap());
    }

    ip_packet
}

#[derive(Debug)]
enum FrameType {
    IPv4,
    IPv6,
    ARP,
    FARP,
    PPP,
    Unknown,
}

impl TryFrom<u16> for FrameType {
    type Error = ();

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
