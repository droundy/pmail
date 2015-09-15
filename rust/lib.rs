#![deny(warnings)]

#[macro_use]
extern crate arrayref;

#[macro_use]
extern crate log;

extern crate onionsalt;

pub mod udp;
pub mod dht;
pub mod pmail;
pub mod str255;

pub use udp::{PACKET_LENGTH};

#[cfg(test)]
mod tests {
    use super::*;
    use std;

    #[test]
    fn listen_works() {
        use std::net::{SocketAddr};
        use std::str::FromStr;
        let send_period_ms = 1000*1;
        let (send, receive) = udp::listen(send_period_ms).unwrap();
        let lopri_msg = [2; PACKET_LENGTH];
        let msg = [1; PACKET_LENGTH];
        std::thread::spawn(move || {
            send.send(udp::RawEncryptedMessage{ip: SocketAddr::from_str("127.0.0.1:54321").unwrap(),
                                               data: lopri_msg}).unwrap();
            send.send(udp::RawEncryptedMessage{ip: SocketAddr::from_str("127.0.0.1:54321").unwrap(),
                                               data: msg}).unwrap();
        });
        let got = receive.recv().unwrap();
        for i in 0..PACKET_LENGTH {
            assert_eq!(got.data[i], 2);
        }
        let got = receive.recv().unwrap();
        for i in 0..PACKET_LENGTH {
            assert_eq!(got.data[i], 1);
        }
    }
}
