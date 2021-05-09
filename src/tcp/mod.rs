/// TCP state.
#[derive(Clone, Debug)]
pub struct State {}

impl Default for State {
    fn default() -> Self {
        State {}
    }
}

impl State {
    pub fn on_packet<'a>(
        &mut self,
        iph: etherparse::Ipv4HeaderSlice,
        tcp_h: etherparse::TcpHeaderSlice,
        data: &'a [u8],
    ) {
        eprintln!(
            "{}:{} -> {}:{}  {}B transfered over TCP",
            iph.source_addr(),
            tcp_h.source_port(),
            iph.destination_addr(),
            tcp_h.destination_port(),
            data.len(),
        );
    }
}
