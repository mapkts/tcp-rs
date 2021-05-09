use std::collections::HashMap;
use std::io;
use std::io::Read;
use std::net::Ipv4Addr;

mod tcp;

type Port = u16;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Quad {
	src_ip: (Ipv4Addr, Port),
	dst_ip: (Ipv4Addr, Port),
}

fn main() -> io::Result<()> {
	// TCP connnections.
	let mut connections: HashMap<Quad, tcp::State> = Default::default();

	// Set up tun inteface.
	let mut config = tun::Configuration::default();
	config
		.address((10, 0, 0, 1))
		.netmask((255, 255, 255, 0))
		.up();

	#[cfg(target_os = "linux")]
	config.platform(|config| {
		config.packet_information(true);
	});
	let mut dev = tun::create(&config).unwrap();

	// 2B flag + 2B proto + 1500B mtu
	let mut buf = [0u8; 1054];
	loop {
		let nbytes = dev.read(&mut buf)?;
		let _tun_flags = u16::from_be_bytes([buf[0], buf[1]]);
		let tun_proto = u16::from_be_bytes([buf[2], buf[3]]);

		if tun_proto != 0x0800 {
			// Only ipv4 packets.
			continue;
		}

		let ip_hdr_offset = 4;
		match etherparse::Ipv4HeaderSlice::from_slice(&buf[ip_hdr_offset..nbytes]) {
			Ok(ip_h) => {
				let src = ip_h.source_addr();
				let dst = ip_h.destination_addr();
				let proto = ip_h.protocol();
				if proto != 6 {
					// Only tcp packets.
					continue;
				}

				let tcp_hdr_offset = ip_hdr_offset + ip_h.slice().len();
				match etherparse::TcpHeaderSlice::from_slice(&buf[tcp_hdr_offset..nbytes]) {
					Ok(tcp_h) => {
						let data_offset = tcp_hdr_offset + tcp_h.slice().len();
						connections
							.entry(Quad {
								src_ip: (src, tcp_h.source_port()),
								dst_ip: (dst, tcp_h.destination_port()),
							})
							.or_default()
							.on_packet(ip_h, tcp_h, &buf[data_offset..nbytes]);
					}
					Err(e) => {
						eprintln!("ignored weird packet: {:?}", e);
					}
				}
			}
			Err(e) => {
				eprintln!("ignored weird packet: {:?}", e);
			}
		}
	}
}
