#![deny(warnings)]

extern crate onionsalt;

pub mod udp;

pub use udp::{PACKET_LENGTH};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_works() {
        let (send, receive, myself) = udp::listen().unwrap();
        let msg = [1; PACKET_LENGTH];
        send.send(udp::RawEncryptedMessage{ip: myself, data: msg}).unwrap();
        let got = receive.recv().unwrap();
        for i in 0..PACKET_LENGTH {
            assert_eq!(got.data[i], 1);
        }
    }
}
