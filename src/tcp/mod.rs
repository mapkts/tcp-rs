use std::io;
use std::io::prelude::*;

/// The TCP state machine.
///
/// RFC 793 S3.2
pub enum State {
    Closed,
    Listen,
    SynReceived,
    // Established,
}

/// An end to end TCP connection.
pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
}

/// State of the Send Sequence Space (RFC 793 S3.2 Fig4)
///
/// ```text
/// 1         2          3          4
/// ----------|----------|----------|----------
///        SND.UNA    SND.NXT    SND.UNA
///                             +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
/// ```
struct SendSequenceSpace {
    /// send unacknowledged
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer,
    up: bool,
    /// segment sequence number used for last window update
    wl1: usize,
    /// segment acknowledgment number used for last window update
    wl2: usize,
    /// initial send sequence number
    iss: u32,
}

/// State of the Receive Sequence Space (RFC 793 S3.2 Fig5)
///
/// ```text
/// 1          2          3
/// ----------|----------|----------
///        RCV.NXT    RCV.NXT
///                  +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
/// ```
struct RecvSequenceSpace {
    /// receive next
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

impl Connection {
    pub fn accept<'a>(
        nic: &mut tun::platform::Device,
        ip_h: etherparse::Ipv4HeaderSlice,
        tcp_h: etherparse::TcpHeaderSlice,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];
        // match self.state {
        //     State::Closed => {
        //         // refuse any packets
        //         return Ok(None);
        //     }
        if !tcp_h.syn() {
            // only expected SYN packets
            return Ok(None);
        }

        let iss = 0;
        let mut conn = Connection {
            state: State::SynReceived,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss + 1,
                wnd: 10,
                up: false,
                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                irs: tcp_h.sequence_number(),
                wnd: tcp_h.window_size(),
                nxt: tcp_h.sequence_number() + 1,
                up: false,
            },
        };

        // need to start establishing a connection
        let mut syn_ack =
            etherparse::TcpHeader::new(tcp_h.destination_port(), tcp_h.source_port(), 0, 10);
        syn_ack.acknowledgment_number = conn.recv.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;

        let mut ip = etherparse::Ipv4Header::new(
            syn_ack.header_len(),
            64,
            etherparse::IpTrafficClass::Tcp,
            ip_h.destination_addr().octets(),
            ip_h.source_addr().octets(),
        );

        // write out the headers
        let unwritten = {
            let mut unwritten = &mut buf[..];
            ip.write(&mut unwritten).unwrap();
            syn_ack.write(&mut unwritten).unwrap();
            unwritten.len()
        };
        nic.write(&buf[..unwritten])?;
        // eprintln!(
        //     "{}:{} -> {}:{}  {}B transfered over TCP",
        //     ip_h.source_addr(),
        //     tcp_h.source_port(),
        //     ip_h.destination_addr(),
        //     tcp_h.destination_port(),
        //     data.len(),
        // );
        Ok(Some(conn))
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun::platform::Device,
        ip_h: etherparse::Ipv4HeaderSlice,
        tcp_h: etherparse::TcpHeaderSlice,
        data: &'a [u8],
    ) -> io::Result<()> {
        Ok(())
    }
}
