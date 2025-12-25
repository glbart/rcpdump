#![allow(non_snake_case)]
use std::{ffi::CString, mem, os::fd::RawFd};

use anyhow::Result;
use clap::Parser;
use libc::{BIOCGBLEN, BIOCIMMEDIATE, BIOCSETIF, O_RDONLY, bpf_hdr, ifreq, ioctl, open, read};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};

mod eth;
mod ipv4;
mod shared;
mod tcp;

use eth::{EthernetFrame, FrameType};
use ipv4::{IPv4Packet, InternetProtocol};
use tcp::TcpPacket;

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
            let _packet_data =
                unsafe { std::slice::from_raw_parts(packet_data_prt, hdr.bh_caplen as usize) };

            // println!("Captured packet: {} bytes", hdr.bh_caplen);

            match EthernetFrame::try_parse(_packet_data) {
                Ok(eth_frame) => {
                    println!();
                    eth_frame.format_output();

                    match eth_frame.frame_type {
                        FrameType::IPv4 => match IPv4Packet::try_parse(eth_frame.payload) {
                            Ok(ip_packet) => {
                                ip_packet.format_output();
                                match ip_packet.protocol {
                                    InternetProtocol::TCP => {
                                        match TcpPacket::try_parse(ip_packet.payload) {
                                            Ok(tcp_packet) => {
                                                tcp_packet.format_output();
                                            }
                                            Err(e) => {
                                                eprintln!("Broken tcp packet: {:?}", e);
                                            }
                                        }
                                    }
                                    _ => println!("Not implemented yet"),
                                }
                            }
                            Err(e) => {
                                eprintln!("Broken IPv4 packet: {:?}", e);
                            }
                        },
                        _ => println!("Not implemented yet"),
                    }

                    println!();
                }
                Err(e) => {
                    eprintln!("Broken ethernet frame: {:?}", e);
                }
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
