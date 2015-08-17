#![deny(warnings)]

extern crate onionsalt;

use std::fmt::{Formatter, Debug};
use std::fmt;

use std::net::UdpSocket;
use std::net::SocketAddr;
// use onionsalt::crypto;
// use onionsalt::crypto::{ToPublicKey};
use std::io::Error;
use std::sync::mpsc::{Sender, Receiver, channel};
use std::thread;

pub use onionsalt::{PACKET_LENGTH};

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

pub fn listen() -> Result<(Sender<RawEncryptedMessage>,
                           Receiver<RawEncryptedMessage>,
                           SocketAddr), Error> {
    let port: u16 = 54321;
    // Create the socket we will use for all communications.  If we
    // can bind to ipv6, we will only use ipv6 for listening. I'm not
    // sure if this is wise, but it seems best not to listen on both
    // protocols...
    let socket = match UdpSocket::bind(("::", port)) {
        Ok(s) => s,
        _ => {
            println!("Attempting to bind to ipv4 port...");
            match UdpSocket::bind(("0.0.0.0", port)) {
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
        for m in rs.iter() {
            println!("I should be sending {:?}", m);
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
                println!("I got a packet from {}", src);
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
    Ok((ts, rr, myaddr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_works() {
        let (send, receive, myself) = listen().unwrap();
        let msg = [1; PACKET_LENGTH];
        send.send(RawEncryptedMessage{ip: myself, data: msg}).unwrap();
        let got = receive.recv().unwrap();
        for i in 0..PACKET_LENGTH {
            assert_eq!(got.data[i], 1);
        }
    }
}
