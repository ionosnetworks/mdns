use crate::{Error, Response};

use std::{io, net::Ipv4Addr};

use bytes::Bytes;
use futures::prelude::*;
use net2;
use tokio::net::UdpSocket;
use tokio_util::codec::BytesCodec;
use tokio_util::udp::UdpFramed;

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
    let socket = create_socket(interface_addr.clone())?;
    let socket = UdpSocket::from_std(socket)?;

    socket.set_multicast_loop_v4(false)?;
    socket.join_multicast_v4(MULTICAST_ADDR, interface_addr)?;

    let framer = UdpFramed::new(socket, BytesCodec::new());

    let (send, recv) = framer.split();

    Ok((
        mDNSListener { recv },
        mDNSSender {
            service_name,
            send: send,
        },
    ))
}

#[cfg(not(target_os = "windows"))]
fn create_socket(bind_addr: Ipv4Addr) -> io::Result<std::net::UdpSocket> {
    net2::UdpBuilder::new_v4()?
        .reuse_address(true)?
        .reuse_port(true)?
        .bind((bind_addr, 46383))
}

#[cfg(target_os = "windows")]
fn create_socket(bind_addr: Ipv4Addr) -> io::Result<std::net::UdpSocket> {
    net2::UdpBuilder::new_v4()?
        .reuse_address(true)?
        .bind((bind_addr, 46383))
}

/// An mDNS sender on a specific interface.
#[allow(non_camel_case_types)]
pub struct mDNSSender {
    service_name: String,
    send: futures::stream::SplitSink<UdpFramed<BytesCodec>, (Bytes, std::net::SocketAddr)>,
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

        self.send.send((packet_data, addr)).await?;

        Ok(())
    }
}

/// An mDNS listener on a specific interface.
#[allow(non_camel_case_types)]
pub struct mDNSListener {
    recv: futures::stream::SplitStream<UdpFramed<BytesCodec>>,
}

impl mDNSListener {
    pub fn listen(self) -> impl Stream<Item = Result<Response, Error>> {
        self.recv
            .try_filter_map(|(buff, _)| async move {
                match dns_parser::Packet::parse(&buff) {
                    Ok(raw_packet) => Ok(Some(Response::from_packet(&raw_packet))),
                    Err(_) => Ok(None),
                }
            })
            .map_err(|err| Error::from(err))
    }
}
