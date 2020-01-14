use crate::{Error, Response};

use std::{io, net::Ipv4Addr};

use bytes::Bytes;
use futures01::sink::Sink as Sink01;
use futures01::stream::Stream as Stream01;
use futures_core::Stream;
use futures_util::compat::Future01CompatExt;
use futures_util::compat::Stream01CompatExt;
use net2;
use tokio_codec::BytesCodec;
use tokio_reactor::Handle;
use tokio_udp::{UdpFramed, UdpSocket};

#[cfg(not(target_os = "windows"))]
use net2::unix::UnixUdpBuilderExt;
use std::net::SocketAddr;

/// The IP address for the mDNS multicast socket.
const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MULTICAST_PORT: u16 = 5353;

pub fn mdns_interface(
    service_name: String,
    interface_addr: Ipv4Addr,
) -> Result<(mDNSListener, mDNSSender), Error> {
    let socket = create_socket()?;
    let socket = UdpSocket::from_std(socket, &Handle::default())?;

    socket.set_multicast_loop_v4(false)?;
    socket.join_multicast_v4(&MULTICAST_ADDR, &interface_addr)?;

    let framer = UdpFramed::new(socket, BytesCodec::new());

    let (send, recv) = framer.split();

    Ok((
        mDNSListener { recv },
        mDNSSender {
            service_name,
            send: Some(send),
        },
    ))
}

const ADDR_ANY: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

#[cfg(not(target_os = "windows"))]
fn create_socket() -> io::Result<std::net::UdpSocket> {
    net2::UdpBuilder::new_v4()?
        .reuse_address(true)?
        .reuse_port(true)?
        .bind((ADDR_ANY, 46383))
}

#[cfg(target_os = "windows")]
fn create_socket() -> io::Result<std::net::UdpSocket> {
    net2::UdpBuilder::new_v4()?
        .reuse_address(true)?
        .bind((ADDR_ANY, 46383))
}

/// An mDNS sender on a specific interface.
#[allow(non_camel_case_types)]
pub struct mDNSSender {
    service_name: String,
    send: Option<futures01::stream::SplitSink<UdpFramed<BytesCodec>>>,
}

impl mDNSSender {
    /// Send multicasted DNS queries.
    pub async fn send_request(&mut self) -> Result<(), Error> {
        let mut builder = dns_parser::Builder::new_query(0, false);
        let prefer_unicast = false;
        builder.add_question(
            &self.service_name,
            prefer_unicast,
            dns_parser::QueryType::PTR,
            dns_parser::QueryClass::IN,
        );
        let packet_data = Bytes::from(builder.build().unwrap());

        let addr = SocketAddr::new(MULTICAST_ADDR.into(), MULTICAST_PORT);

        // self.send.send(&packet_data, &addr).compat().await?;
        // let send = self.send.clone();
        let send = self.send.take().unwrap();
        self.send
            .replace(send.send((packet_data, addr)).compat().await?);

        Ok(())
    }
}

/// An mDNS listener on a specific interface.
#[allow(non_camel_case_types)]
pub struct mDNSListener {
    recv: futures01::stream::SplitStream<UdpFramed<BytesCodec>>,
}

impl mDNSListener {
    pub fn listen(self) -> impl Stream<Item = Result<Response, Error>> {
        self.recv
            .filter_map(|(buff, _)| match dns_parser::Packet::parse(&buff) {
                Ok(raw_packet) => Some(Response::from_packet(&raw_packet)),
                Err(_) => None,
            })
            .map_err(|err| Error::from(err))
            .compat()
    }
}
