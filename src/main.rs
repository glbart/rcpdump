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

    println!("buffer size: {}", bufsize);

    let mut buffer = vec![0u8; bufsize];

    loop {
        let bytes_read = unsafe { read(fd, buffer.as_mut_ptr() as *mut libc::c_void, bufsize) };

        if bytes_read <= 0 {
            continue;
        }

        println!("read {} bytes", bytes_read);

        let mut offset = 0;

        while offset + mem::size_of::<bpf_hdr>() <= bytes_read as usize {
            let hdr_ptr = unsafe { buffer.as_ptr().add(offset) as *const bpf_hdr };
            let hdr = unsafe { &*hdr_ptr };

            let packet_data_prt = unsafe { buffer.as_ptr().add(offset + hdr.bh_hdrlen as usize) };
            let _packer_data =
                unsafe { std::slice::from_raw_parts(packet_data_prt, hdr.bh_caplen as usize) };

            println!("Captured packet: {} bytes", hdr.bh_caplen);

            let frame = parse_frame(_packer_data);
            println!(
                "\nCaptured frame:\nDestination: {}\nSource: {}\nType: {:?} (0x{:04X})\n",
                frame.mac_dest, frame.mac_source, frame.frame_type, frame.type_raw
            );

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
struct EthernetFrame {
    mac_dest: MacAddress,
    mac_source: MacAddress,
    frame_type: FrameType,
    type_raw: u16,
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

fn parse_frame(bytes: &[u8]) -> EthernetFrame {
    let bytes = bytes.to_vec();
    let mac_dest: [u8; 6] = bytes[..6].try_into().unwrap();
    let mac_source: [u8; 6] = bytes[6..12].try_into().unwrap();

    let protocol_bytes: u16 = ((bytes[12] as u16) << 8) | bytes[13] as u16;
    let protocol_type = FrameType::try_from(protocol_bytes).unwrap();
    EthernetFrame {
        mac_dest: MacAddress::from_bytes(mac_dest),
        mac_source: MacAddress::from_bytes(mac_source),
        frame_type: protocol_type,
        type_raw: protocol_bytes,
    }
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
