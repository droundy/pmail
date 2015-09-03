#![deny(warnings)]

extern crate onionsalt;

use std::fmt::{Formatter, Debug};
use std::fmt;
use std;

use std::net::UdpSocket;
use std::net::SocketAddr;
// use onionsalt::crypto;
// use onionsalt::crypto::{ToPublicKey};
use std::io::Error;
use std::sync::mpsc::{Sender, Receiver, channel,
                      SyncSender, sync_channel};
use std::thread;

pub use onionsalt::{PACKET_LENGTH};

pub const PORT: u16 = 54321;

#[derive(Copy)]
pub struct RawEncryptedMessage {
    pub ip: SocketAddr,
    pub data: [u8; PACKET_LENGTH],
}

impl Clone for RawEncryptedMessage {
    fn clone(&self) -> RawEncryptedMessage {
        RawEncryptedMessage { ip: self.ip, data: self.data }
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
                           Sender<RawEncryptedMessage>,
                           Receiver<RawEncryptedMessage>,
                           SocketAddr), Error> {
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
    let myaddr = try!(socket.local_addr());

    // Create two channels, one for sending messages from the socket,
    // and one for receiving them.

    let (ts, rs) : (Sender<RawEncryptedMessage>,
                    Receiver<RawEncryptedMessage>) = channel(); // for sending messages
    let (low_priority_ts, low_priority_rs)
        : (SyncSender<RawEncryptedMessage>,
           Receiver<RawEncryptedMessage>) = sync_channel(0); // for sending low-priority messages
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
        // This is the sender of messages.  I assume that 100 ms is
        // sufficient time to receive a message from a Receiver, so
        // that observers cannot tell whether the message was a high-
        // or low-priority message from watching us.  I also assume
        // that there will always be a low-priority message available.
        // That is a responsibility of the dht module.
        let (send_now, send_warning) = double_timer(10000, 100);
        for _ in send_warning.iter() {
            let m: RawEncryptedMessage = if let Ok(message) = rs.try_recv() {
                message
            } else {
                match low_priority_rs.recv() {
                    Ok(mess) => mess,
                    _ => unreachable!(),
                }
            };
            send_now.recv().unwrap();
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
                if let Err(e) = tr.send(RawEncryptedMessage{ ip: src, data: buf }) {
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
    Ok((low_priority_ts, ts, rr, myaddr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std;
    use udp;

    #[test]
    fn listen_works() {
        let (lopri_send, send, receive, myself) = listen().unwrap();
        std::thread::spawn(move || {
            let lopri_msg = [2; PACKET_LENGTH];
            lopri_send.send(udp::RawEncryptedMessage{ip: myself, data: lopri_msg}).unwrap();
        });
        let msg = [1; PACKET_LENGTH];
        send.send(RawEncryptedMessage{ip: myself, data: msg}).unwrap();
        let got = receive.recv().unwrap();
        for i in 0..PACKET_LENGTH {
            assert_eq!(got.data[i], 1);
        }
    }
}

fn double_timer(ms: u32, ms_warning: u32) -> (Receiver<()>, Receiver<()>) {
    assert!(ms > ms_warning);
    let (tx, rx) = std::sync::mpsc::sync_channel(0);
    let (tx_warning, rx_warning) = std::sync::mpsc::sync_channel(0);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep_ms(ms - ms_warning);
            if tx_warning.send(()).is_err() {
                break;
            }
            // FIXME this sleep really ought to keep track of the
            // target time, and sleep the correct amount of time, such
            // that we don't give away the time spent doing the
            // previous check, which could be affected by CPU
            // contention.
            std::thread::sleep_ms(ms_warning);
            if tx.send(()).is_err() {
                break;
            }
        }
    });
    (rx, rx_warning)
}
