#![deny(warnings)]

extern crate onionsalt;

pub mod udp;
pub mod dht;

pub use udp::{PACKET_LENGTH};

#[cfg(test)]
mod tests {
    use super::*;
    use std;

    #[test]
    fn listen_works() {
        let (lopri_send, send, receive, myself) = udp::listen().unwrap();
        let lopri_msg = [2; PACKET_LENGTH];
        std::thread::spawn(move || {
            lopri_send.send(udp::RawEncryptedMessage{ip: myself, data: lopri_msg}).unwrap();
        });
        let msg = [1; PACKET_LENGTH];
        send.send(udp::RawEncryptedMessage{ip: myself, data: msg}).unwrap();
        let got = receive.recv().unwrap();
        for i in 0..PACKET_LENGTH {
            assert_eq!(got.data[i], 1);
        }
    }
}
