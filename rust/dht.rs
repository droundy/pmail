extern crate time;

use std::net::SocketAddr;
use onionsalt::ROUTING_LENGTH;
use onionsalt::crypto;
use std::io::Error;

use super::udp;

use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Addr {
    V6 {addr: [u16; 8],
        port: u16,
    },
    V4 {
        addr: [u8; 4],
        port: u16
    },
}

impl<'a> From<&'a SocketAddr> for Addr {
    fn from(sa: &SocketAddr) -> Addr {
        match *sa {
            SocketAddr::V4(sav4) =>
                Addr::V4{ addr: sav4.ip().octets(),
                          port: sav4.port() },
            SocketAddr::V6(sav6) =>
                Addr::V6{ addr: sav6.ip().segments(),
                          port: sav6.port() },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RoutingInfo {
    /// The IP addressing information, 18 bytes, enough for an ipv6
    /// address and a 16 bit port.
    ip: Addr,
    /// The time in seconds (after some specified epoch) by which we
    /// want the message to arrive.  4 bytes/
    eta: u32,
    /// The payload is for us!  Wheee!
    is_for_me: bool,
}

/// When we ask for addresses, we only get `NUM_IN_RESPONSE`, since
/// that is all that will fit in the payload, along with their public
/// key and the authentication overhead.
pub const NUM_IN_RESPONSE: usize = 10;


/// The `USER_MESSAGE_LENGTH` is the size of actual content that can
/// be encrypted and authenticated to send to some receiver.
pub const USER_MESSAGE_LENGTH: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RoutingGift {
    pub addr: Addr,
    pub key: crypto::PublicKey,
}

pub enum MessageType {
    Greetings([RoutingGift; NUM_IN_RESPONSE]),
    Response([RoutingGift; NUM_IN_RESPONSE]),
    ForwardToMe {
        destination: crypto::PublicKey,
        gift: [RoutingGift; NUM_IN_RESPONSE],
    },
    ForwardPlease {
        destination: crypto::PublicKey,
        message: [u8; USER_MESSAGE_LENGTH],
    },
}

pub struct Message {
    pub from: crypto::PublicKey, // 32 bytes, but not part of the ROUTING_LENGTH
    pub contents: MessageType, // 6 bytes
}

///
const EPOCH: time::Timespec = time::Timespec { sec: 1420092000, nsec: 0 };

pub fn now() -> u32 {
    (time::get_time().sec - EPOCH.sec) as u32
}

impl RoutingInfo {
    pub fn new(saddr: SocketAddr, delay_time: u32) -> RoutingInfo {
        let eta = now() + delay_time;
        RoutingInfo {
            ip: Addr::from(&saddr),
            eta: eta,
            is_for_me: false,
        }
    }
    pub fn bytes(&self) -> [u8; ROUTING_LENGTH] {
        let mut out = [0; ROUTING_LENGTH];
        if self.is_for_me {
            out[0] = 1;
        }
        out[1] = self.eta as u8;
        out[2] = (self.eta >> 8) as u8;
        out[3] = (self.eta >> 16) as u8;
        out[4] = (self.eta >> 24) as u8;
        match self.ip {
            Addr::V6{ addr, port } => {
                out[5] = 6;
                out[6] = port as u8;
                out[7] = (port >> 8) as u8;
                for i in 0..8 {
                    out[8 + 2*i] = addr[i] as u8;
                    out[8 + 2*i+1] = (addr[i] >> 8) as u8;
                }
            },
            Addr::V4{ addr, port } => {
                out[5] = 4;
                out[6] = port as u8;
                out[7] = (port >> 8) as u8;
                for i in 0..4 {
                    out[8+i] = addr[i];
                }
            },
        }
        out
    }
    pub fn from_bytes(out: [u8; ROUTING_LENGTH]) -> Option<RoutingInfo> {
        let is_for_me = out[0] == 1;
        let eta = out[1] as u32 + ((out[2] as u32) << 8)
            + ((out[3] as u32) << 16) + ((out[4] as u32) << 24);
        let addr = match out[7] {
            6 => {
                let port = out[6] as u16 + ((out[7] as u16) << 8);
                let mut addr = [0; 8];
                for i in 0..8 {
                    addr[i] = out[8 + 2*i] as u16 + ((out[8 + 2*i+1] as u16) << 8);
                }
                Addr::V6{ addr: addr, port: port }
            },
            4 => {
                let port = out[6] as u16 + ((out[7] as u16) << 8);
                let mut addr = [0;4];
                for i in 0..4 {
                    addr[i] = out[8+i];
                }
                Addr::V4{ addr: addr, port: port }
            },
            _ => {
                return None;
            }
        };
        Some(RoutingInfo {
            is_for_me: is_for_me,
            eta: eta,
            ip: addr,
        })
    }
}

pub fn start() -> Result<(), Error> {
    let mut addresses = HashMap::new();
    let mut pubkeys = HashMap::new();

    let bingley_addr = Addr::V4{ addr: [128,193,96,51], port: udp::PORT };
    let bingley_key = crypto::PublicKey([0;32]);
    addresses.insert(bingley_key, bingley_addr);
    pubkeys.insert(bingley_addr, bingley_key);

    let (_lopriority, _send, _get, _) = try!(udp::listen());

    // lopriority.send();
    Ok(())
}
