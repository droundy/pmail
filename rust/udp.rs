#![deny(warnings)]

extern crate time;
extern crate onionsalt;

use std::fmt::{Formatter, Debug};
use std::fmt;
use std;

use std::net::UdpSocket;
use std::net::{ SocketAddr, SocketAddrV4 };
// use onionsalt::crypto;
// use onionsalt::crypto::{ToPublicKey};
use std::io::Error;
use std::sync::mpsc::{Receiver, channel,
                      SyncSender, sync_channel};
use std::thread;

pub use onionsalt::{PACKET_LENGTH};

pub const PORT: u16 = 54321;

pub const SEND_PERIOD_MS: u64 = 10*1000; // in ms!

#[derive(Copy)]
pub struct RawEncryptedMessage {
    pub ip: SocketAddr,
    pub data: [u8; PACKET_LENGTH],
}

impl Clone for RawEncryptedMessage {
    fn clone(&self) -> RawEncryptedMessage {
        RawEncryptedMessage { ip: normalize(self.ip), data: self.data }
    }
}

impl Debug for RawEncryptedMessage {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        let mut s = format!("{:?} :", self.ip);
        for i in 0 .. PACKET_LENGTH/32 {
            s = s + "\n  ";
            for j in 0 .. 32 {
                s = s + &format!("{:02x}", self.data[i*32 + j]);
            }
        }
        s = s + "\n";
        f.write_str(&s)
    }
}

pub fn listen() -> Result<(SyncSender<RawEncryptedMessage>,
                           Receiver<RawEncryptedMessage>), Error> {
    // Create the socket we will use for all communications.  If we
    // can bind to ipv6, we will only use ipv6 for listening. I'm not
    // sure if this is wise, but it seems best not to listen on both
    // protocols...

    // On ipv6 we only bind to the default port, since we presume that
    // NAT isn't needed on ipv6, and don't want to store yet more
    // routing bytes.
    let socket = match UdpSocket::bind(("::", PORT)) {
        Ok(s) => s,
        _ => {
            println!("Attempting to bind to ipv4...");
            match UdpSocket::bind(("0.0.0.0", PORT)) {
                Ok(s) => s,
                _ => try!(UdpSocket::bind(("0.0.0.0", 0))) // any port in a storm
            }
        }
    };
    let send_socket = try!(socket.try_clone());

    // Create two channels, one for sending messages from the socket,
    // and one for receiving them.

    let (ts, rs) : (SyncSender<RawEncryptedMessage>,
                    Receiver<RawEncryptedMessage>) = sync_channel(0); // for sending messages
    let (tr, rr) = channel(); // for receiving messages

    // We use four (or more) separate threads for our communication.
    // This has three major benefits (in order of importance):
    //
    // 1. Preventing information leaks.  We leverage rust's memory
    //    safety to ensure that "secret" information cannot be leaked
    //    to code that should not know about it.  We may want to
    //    enable further separation one day by changing these to
    //    processes and perhaps dropping privileges with seccomp.
    //    Note: rust could actually acheive this without using OS
    //    threads, but using threads makes it harder to break this
    //    barrier accidentally.
    //
    // 2. Avoiding timing leaks.  Because the threads run as separate
    //    OS threads, it is unlikely that the time spent on one of
    //    these tasks will be observable in the behavior of another
    //    one.  Rust does not give us a strong guarantee here, so we
    //    also need to be careful, e.g. by either pacing the sending
    //    of datagrams, or sending them prior to examination of secret
    //    content.
    //
    // 3. Parallelization. Different tasks can run on different cores.
    //    Note that this is the *least* important reason for us to use
    //    threads.

    // We use two threads for sending and receiving respectively, in
    // an attempt to minimize the opportunity for timing attacks.  On
    // top of this, the sender always sends on a regular schedule,
    // which further decreases the opportunity for timing attacks.
    // Actually, the receiver also sends confirmation datagrams, but
    // prior to decrypting or reading any "secret" output.

    thread::spawn(move|| {
        // This is the sender of messages.
        let ms_period = SEND_PERIOD_MS;
        let mut next_time = (now_ms()/ms_period)*ms_period;
        loop {
            if !sleep_until(next_time) {
                // We are behind, so try to catch up by sleeping extra
                // long this time.
                next_time += ms_period;
            }
            next_time += ms_period;
            let m = rs.recv().unwrap();
            // println!("Sending to {}", m.ip);
            match send_socket.send_to(&m.data, &m.ip) {
                Ok(sent) => {
                    if sent != PACKET_LENGTH {
                        println!("Short message {} sent to {}", sent, m.ip);
                    }
                },
                Err(e) => {
                    println!("Error sending to {}: {:?}", m.ip, e);
                }
            }
        }
    });
    thread::spawn(move|| {
        // This is the receiver of messages.  It listens on the
        // socket, and decrypts messages with the ephemeral session
        // key prior to forwarding the contents on through the
        // channel.
        let mut buf = [0; PACKET_LENGTH];
        loop {
            // We assume that when we fail on a receive, the socket must
            // have gone down, and we should exit this thread.
            let (amt, src) = socket.recv_from(&mut buf).unwrap();
            if amt == PACKET_LENGTH {
                // println!("I got a packet from {}", src);
                if let Err(e) = tr.send(RawEncryptedMessage{ ip: normalize(src), data: buf }) {
                    // When no one is listending for messages, we may
                    // as well shut down our listener.
                    println!("Quitting now because {:?}", e);
                    return;
                }
            } else {
                println!("A packet of a strange size {}", amt);
            }
        }
    });
    Ok((ts, rr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std;
    use udp;

    #[test]
    fn listen_works() {
        let (send, receive) = listen().unwrap();
        std::thread::spawn(move || {
            let lopri_msg = [2; PACKET_LENGTH];
            send.send(udp::RawEncryptedMessage{ip: myself, data: lopri_msg}).unwrap();
        });
        let msg = [1; PACKET_LENGTH];
        send.send(RawEncryptedMessage{ip: myself, data: msg}).unwrap();
        let got = receive.recv().unwrap();
        for i in 0..PACKET_LENGTH {
            assert_eq!(got.data[i], 1);
        }
    }
}

/// The `EPOCH` is when time begins.  We have not facilities for
/// sending messages prior to this time.  However, we also do not
/// promise never to change `EPOCH`.  It may be changed in a future
/// version of the protocol in order to avoid a Y2K-like problem.
/// Therefore, `EPOCH`-difference times should not be stored on disk,
/// and should only be sent over the network.  It is also possible
/// that future changes will needlessly change `EPOCH` (but only while
/// making other network protool changes) simply to flush out
/// buggy use of thereof.
pub const EPOCH: time::Timespec = time::Timespec { sec: 1420092000, nsec: 0 };

pub fn now_ms() -> u64 {
    let now = time::get_time();
    let mut ms = (now.sec - EPOCH.sec) as u64 * 1000;
    ms += (now.nsec/1000000) as u64;
    ms
}

pub fn sleep_until(ms_from_epoch: u64) -> bool {
    let ms = now_ms();
    if ms > ms_from_epoch {
        println!("I am behind by {} seconds", (ms - ms_from_epoch) as f64 / 1000.0);
        return false;
    }
    std::thread::sleep_ms((ms_from_epoch - ms) as u32);
    true
}

fn normalize(sa: SocketAddr) -> SocketAddr {
    // is it an IPv4-mapped IPv6 address?
    match sa {
        SocketAddr::V6(sa6) =>
            match sa6.ip().to_ipv4() {
                None => sa,
                Some(ipv4) => SocketAddr::V4(SocketAddrV4::new(ipv4, sa6.port())),
            },
        _ => sa,
    }
}
