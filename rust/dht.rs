extern crate time;

use std::net::{SocketAddr, SocketAddrV6, SocketAddrV4,
               Ipv6Addr, Ipv4Addr};
use onionsalt;
use onionsalt::{ROUTING_LENGTH,
                PAYLOAD_LENGTH};
use onionsalt::{crypto,
                onionbox,
                onionbox_open};
use std::io::Error;
use std;
use super::udp;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::mpsc::{Receiver, SyncSender};

trait MyBytes<T> {
    fn bytes(&self, &mut T);
    fn from_bytes(&T) -> Self;
}

impl MyBytes<[u8; 18]> for SocketAddr {
    fn bytes(&self, out: &mut[u8; 18]) {
        match *self {
            SocketAddr::V6(sa) => {
                let (port, a, b, c, d, e, f, g, h) = mut_array_refs!(out, 2,
                                                                     2,2,2,2,
                                                                     2,2,2,2);
                sa.port().bytes(port);
                let addr = sa.ip().segments();
                addr[0].bytes(a); addr[1].bytes(b); addr[2].bytes(c); addr[3].bytes(d);
                addr[4].bytes(e); addr[5].bytes(f); addr[6].bytes(g); addr[7].bytes(h);
            },
            SocketAddr::V4(sa) => {
                for i in 0..18 {
                    out[i] = 0;
                }
                sa.port().bytes(array_mut_ref![out, 2, 2]);
                *array_mut_ref![out,4,4] = sa.ip().octets();
            },
        }
    }
    fn from_bytes(inp: &[u8; 18]) -> SocketAddr {
        if inp[0] == 0 && inp[1] == 0 {
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(inp[4], inp[5], inp[6], inp[7]),
                inp[2] as u16 + (inp[3] as u16) << 8))
        } else {
            let mut addr = [0; 8];
            for i in 0..8 {
                addr[i] = inp[2 + 2*i] as u16 + ((inp[2 + 2*i+1] as u16) << 8);
            }
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(addr[0],addr[1],addr[2],addr[3],
                              addr[4],addr[5],addr[6],addr[7]),
                inp[0] as u16 + (inp[1] as u16) << 8, 0, 0))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RoutingInfo {
    /// The IP addressing information, 18 bytes, enough for an ipv6
    /// address and a 16 bit port.
    ip: SocketAddr,
    /// The time in seconds (after some specified epoch) by which we
    /// want the message to arrive.  4 bytes/
    eta: u32,
    /// The payload is for us!  Wheee!
    is_for_me: bool,
    /// Just respond to the sender of this packet with his address.
    /// This is needed for a node to find out its port, if it happens
    /// to be passing through a NAT.
    who_am_i: bool,
}

impl MyBytes<[u8; 4]> for u32 {
    fn bytes(&self, out: &mut[u8; 4]) {
        out[0] = *self as u8;
        out[1] = (*self >> 8) as u8;
        out[2] = (*self >> 16) as u8;
        out[3] = (*self >> 24) as u8;
    }
    fn from_bytes(inp: &[u8; 4]) -> u32 {
        inp[0] as u32 + ((inp[1] as u32) << 8) + ((inp[2] as u32) << 16) + ((inp[3] as u32) << 24)
    }
}

impl MyBytes<[u8; 2]> for u16 {
    fn bytes(&self, out: &mut[u8; 2]) {
        out[0] = *self as u8;
        out[1] = (*self >> 8) as u8;
    }
    fn from_bytes(inp: &[u8; 2]) -> u16 {
        inp[0] as u16 + ((inp[1] as u16) << 8)
    }
}

impl MyBytes<[u8; ROUTING_LENGTH]> for RoutingInfo {
    fn bytes(&self, out: &mut[u8; ROUTING_LENGTH]) {
        let (flags,addr,eta,_) = mut_array_refs!(out, 1, 18, 4,1);
        flags[0] = self.is_for_me as u8 + ((self.who_am_i as u8) << 1);
        self.ip.bytes(addr);
        self.eta.bytes(eta);
    }
    fn from_bytes(inp: &[u8; ROUTING_LENGTH]) -> RoutingInfo {
        let (flags,addr,eta,_) = array_refs!(inp, 1, 18, 4,1);
        RoutingInfo {
            ip: SocketAddr::from_bytes(addr),
            eta: u32::from_bytes(eta),
            is_for_me: flags[0] & 1 == 1,
            who_am_i: flags[0] & 2 == 2,
        }
    }
}

/// When we ask for addresses, we only get `NUM_IN_RESPONSE`, since
/// that is all that will fit in the payload, along with their public
/// key and the authentication overhead.
pub const NUM_IN_RESPONSE: usize = 10;


/// The `USER_MESSAGE_LENGTH` is the size of actual content that can
/// be encrypted and authenticated to send to some receiver.
pub const USER_MESSAGE_LENGTH: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RoutingGift {
    pub addr: SocketAddr,
    pub key: crypto::PublicKey,
}

impl MyBytes<[u8; 32]> for crypto::PublicKey {
    fn bytes(&self, out: &mut[u8; 32]) {
        *out = self.0;
    }
    fn from_bytes(inp: &[u8; 32]) -> crypto::PublicKey {
        crypto::PublicKey(*inp)
    }
}

impl MyBytes<[u8; 18+32]> for RoutingGift {
    fn bytes(&self, out: &mut[u8; 18+32]) {
        self.addr.bytes(array_mut_ref![out,0,18]);
        self.key.bytes(array_mut_ref![out,18,32]);
    }
    fn from_bytes(inp: &[u8; 18+32]) -> RoutingGift {
        RoutingGift {
            addr: SocketAddr::from_bytes(array_ref![inp,0,18]),
            key: crypto::PublicKey::from_bytes(array_ref![inp,18,32]),
        }
    }
}

type RoutingGifts = [RoutingGift; NUM_IN_RESPONSE];

impl MyBytes<[u8; (18+32)*NUM_IN_RESPONSE]> for [RoutingGift; NUM_IN_RESPONSE] {
    fn bytes(&self, out: &mut[u8; (18+32)*NUM_IN_RESPONSE]) {
        for i in 0 .. NUM_IN_RESPONSE {
            self[i].bytes(array_mut_ref![out,i*(18+32),18+32]);
        }
    }
    fn from_bytes(inp: &[u8; (18+32)*NUM_IN_RESPONSE]) -> [RoutingGift; NUM_IN_RESPONSE] {
        let (g0,g1,g2,g3,g4,g5,g6,g7,g8,g9) = array_refs!(inp,
                                                          50, 50, 50, 50, 50,
                                                          50, 50, 50, 50, 50);
        [RoutingGift::from_bytes(g0), RoutingGift::from_bytes(g1),
         RoutingGift::from_bytes(g2), RoutingGift::from_bytes(g3),
         RoutingGift::from_bytes(g4), RoutingGift::from_bytes(g5),
         RoutingGift::from_bytes(g6), RoutingGift::from_bytes(g7),
         RoutingGift::from_bytes(g8), RoutingGift::from_bytes(g9)]
    }
}


// impl RoutingGift {
//     fn new() -> RoutingGift {
//         RoutingGift {
//             addr: Addr::V4{ addr: [0;4], port: 0 },
//             key: crypto::PublicKey([0;32]),
//         }
//     }
// }

pub enum Message {
    Greetings([RoutingGift; NUM_IN_RESPONSE]),
    Response([RoutingGift; NUM_IN_RESPONSE]),
    PickUp {
        destination: crypto::PublicKey,
        gifts: [RoutingGift; NUM_IN_RESPONSE],
    },
    ForwardPlease {
        destination: crypto::PublicKey,
        message: [u8; 512], // this is a hokey and lazy
                                 // workaround for lack of derive for
                                 // arrays larger than 32.
    },
}

impl MyBytes<[u8; PAYLOAD_LENGTH]> for Message {
    fn bytes(&self, out: &mut[u8; PAYLOAD_LENGTH]) {
        match *self {
            Message::Greetings(gifts) => {
                out[0] = b'g';
                gifts.bytes(array_mut_ref![out,1,500]);
            },
            Message::Response(gifts) => {
                out[0] = b'r';
                gifts.bytes(array_mut_ref![out,1,500]);
            },
            Message::PickUp { destination, gifts } => {
                out[0] = b'p';
                destination.bytes(array_mut_ref![out,1,32]);
                gifts.bytes(array_mut_ref![out,33,500]);
            },
            Message::ForwardPlease { destination, message } => {
                out[0] = b'f';
                destination.bytes(array_mut_ref![out,1,32]);
                *array_mut_ref![out,33,512] = message;
            },
        }
    }
    fn from_bytes(inp: &[u8; PAYLOAD_LENGTH]) -> Message {
        match inp[0] {
            b'g' => Message::Greetings(RoutingGifts::from_bytes(array_ref![inp,1,500])),
            b'r' => Message::Response(RoutingGifts::from_bytes(array_ref![inp,1,500])),
            b'p' => unimplemented!(),
            b'f' => unimplemented!(),
            _ => unimplemented!(),
        }
    }
}


// impl Message {
//     fn encrypted_bytes(&self,
//                        n: crypto::Nonce,
//                        to: crypto::PublicKey,
//                        from: crypto::KeyPair) -> [u8; PAYLOAD_LENGTH] {
//         let mut plain = [0; PAYLOAD_LENGTH - 16];
//         // FIXME fill up plain here with the actual content to send.
//         let mut out = [0; PAYLOAD_LENGTH];
//         crypto::box_up(array_mut_ref![out, 16, u8, PAYLOAD_LENGTH-16],
//                        &plain, &n, &to, from.secret).unwrap();
//         *array_mut_ref![out, 0, u8, 32] = from.public.0;
//         out
//     }
//     fn encrypt(&self,
//                to: crypto::PublicKey,
//                from: crypto::KeyPair,
//                addresses: HashMap<crypto::PublicKey, Addr>) -> RawEncryptedMessage {
//         match self.contents {
//             Greetings(gift) => {
//                 let pk = crypto::box_keypair();
//                 let payload = self.encrypted_bytes(crypto::Nonce(pk.public.0), to, from);
//                 let ob = onionsalt::onionbox(&[(to, RoutingInfo::empty(20).bytes())],
//                                              &payload, 0, &pk).unwrap();
//                 ob.packet();
//             },
//             _ => {
//                 unimplemented!();
//             },
//         }
//     }
// }

/// The `EPOCH` is when time begins.  We have not facilities for
/// sending messages prior to this time.  However, we also do not
/// promise never to change `EPOCH`.  It may be changed in a future
/// version of the protocol in order to avoid a Y2K-like problem.
/// Therefore, `EPOCH`-difference times should not be stored on disk,
/// and should only be sent over the network.  It is also possible
/// that future changes will needlessly change `EPOCH` (but only while
/// making other network protool changes) simply to flush out
/// buggy use of thereof.
const EPOCH: time::Timespec = time::Timespec { sec: 1420092000, nsec: 0 };

pub fn now() -> u32 {
    (time::get_time().sec - EPOCH.sec) as u32
}

impl RoutingInfo {
    pub fn new(saddr: SocketAddr, delay_time: u32) -> RoutingInfo {
        let eta = now() + delay_time;
        RoutingInfo {
            ip: saddr,
            eta: eta,
            is_for_me: false,
            who_am_i: false,
        }
    }
}

pub fn read_keypair(name: &std::path::Path) -> Result<crypto::KeyPair, Error> {
    use std::io::Read;

    let mut f = try!(std::fs::File::open(name));
    let mut data = Vec::new();
    try!(f.read_to_end(&mut data));
    if data.len() != 64 {
        return Err(Error::new(std::io::ErrorKind::Other, "oh no!"));
    }
    Ok(crypto::KeyPair {
        public: crypto::PublicKey(*array_ref![data, 0, 32]),
        secret: crypto::SecretKey(*array_ref![data, 32, 32]),
    })
}

/// This is just a crude guess as to the hostname.  I didn't put much
/// effort into this because it is only really relevant in the case
/// where you have a shared home directory for multiple different
/// computers that should be independently running pmail.
pub fn gethostname() -> Result<String, Error> {
    use std::io::Read;

    let mut f = try!(std::fs::File::open("/etc/hostname"));
    let mut hostname = String::new();
    try!(f.read_to_string(&mut hostname));
    match hostname.split_whitespace().next() {
        Some(hn) => Ok(String::from(hn)),
        None => Err(Error::new(std::io::ErrorKind::Other, "malformed /etc/hostname")),
    }
}

pub fn read_or_generate_keypair(mut dirname: std::path::PathBuf)
                                -> Result<crypto::KeyPair, Error> {
    use std::io::Write;

    match gethostname() {
        Err(_) => {
            dirname.push(".pmail.key");
        },
        Ok(hostname) => {
            dirname.push(format!(".pmail-{}.key", hostname));
        },
    };
    let name = dirname.as_path();
    match read_keypair(name) {
        Ok(kp) => Ok(kp),
        _ => {
            match crypto::box_keypair() {
                Err(_) => Err(Error::new(std::io::ErrorKind::Other, "oh bad random!")),
                Ok(kp) => {
                    let mut f = try!(std::fs::File::create(name));
                    let mut data = [0; 64];
                    *array_mut_ref![data, 0, 32] = kp.public.0;
                    *array_mut_ref![data, 32, 32] = kp.secret.0;
                    try!(f.write_all(&data));
                    print!("Created new key!  [");
                    for i in 0..32 {
                        print!("{}, ", kp.public.0[i]);
                    }
                    println!("]");
                    Ok(kp)
                }
            }
        }
    }
}

fn bingley() -> RoutingGift {
    let bingley_addr = SocketAddr::from_str("128.193.96.51:54321").unwrap();
    let bingley_key = crypto::PublicKey([212, 73, 217, 51, 40, 221, 144,
                                         145, 86, 176, 174, 255, 41, 29,
                                         172, 191, 136, 196, 210, 157, 215,
                                         11, 144, 238, 198, 47, 200, 43,
                                         227, 172, 76, 45]);
    RoutingGift { addr: bingley_addr, key: bingley_key }
}

fn construct_gift(addrmap: &HashMap<crypto::PublicKey, SocketAddr>)
                  -> [RoutingGift; NUM_IN_RESPONSE] {
    let mut out = [bingley(); NUM_IN_RESPONSE];
    let mut i = 0;
    for k in addrmap.keys() {
        out[i] = RoutingGift {
            addr: addrmap[k],
            key: *k,
        };
        i += 1;
        if i <= NUM_IN_RESPONSE {
            break;
        }
    }
    while i < NUM_IN_RESPONSE {
        out[i] = out[0];
        i += 1;
    }
    out
}

pub fn query_who_i_am(lopriority: &SyncSender<udp::RawEncryptedMessage>,
                      get: &Receiver<udp::RawEncryptedMessage>,
                      who: &RoutingGift,
                      my_key: &crypto::KeyPair) -> SocketAddr {
    let mut hello_payload = [0; PAYLOAD_LENGTH];
    Message::Greetings([*who; NUM_IN_RESPONSE]).bytes(&mut hello_payload);

    let mut keys_and_routes = [(who.key, [0; ROUTING_LENGTH])];
    let mut ri = RoutingInfo::new(who.addr, 60);
    ri.is_for_me = true;
    ri.who_am_i = true;
    ri.bytes(&mut keys_and_routes[0].1);

    let mut ob = onionbox(&keys_and_routes, 0).unwrap();
    ob.add_payload(*my_key, &hello_payload);

    lopriority.send(udp::RawEncryptedMessage{
        ip: who.addr,
        data: ob.packet(),
    }).unwrap();

    fn read_one_packet(get: &Receiver<udp::RawEncryptedMessage>,
                       my_key: &crypto::KeyPair,
                       ob: &onionsalt::OnionBox) -> Result<SocketAddr, crypto::NaClError> {
        let packet = try!(get.recv());
        let resp = try!(ob.read_return(*my_key, &packet.data));
        println!("Packet has valid encryption.");
        match Message::from_bytes(&resp) {
            Message::Greetings(_) => {
                Err(crypto::NaClError::from("Greetings not expected"))
            },
            Message::Response(rgs) => {
                Ok(rgs[0].addr)
            },
            Message::PickUp {..} => {
                Err(crypto::NaClError::from("Pickup not expected"))
            },
            Message::ForwardPlease {..} => {
                Err(crypto::NaClError::from("Forward not expected"))
            },
        }
    }
    loop {
        match read_one_packet(get, my_key, &ob) {
            Ok(sa) => {
                return sa;
            },
            Err(e) => {
                println!("Got problem: {:?}", e);
            },
        }
    }
}

/// Start relaying messages with a static public key (i.e. one that
/// does not change).
pub fn start_static_node() -> Result<(), Error> {
    let mut addresses = HashMap::new();
    let mut pubkeys = HashMap::new();

    let bingley_gift = bingley();
    addresses.insert(bingley_gift.key, bingley_gift.addr);
    pubkeys.insert(bingley_gift.addr, bingley_gift.key);

    let keydirname = match std::env::home_dir() {
        Some(hd) => hd,
        None => std::path::PathBuf::from("."),
    };
    let my_key = read_or_generate_keypair(keydirname).unwrap();

    let (lopriority, _send, get, _) = try!(udp::listen());

    let my_addr = if my_key.public != bingley().key {
        query_who_i_am(&lopriority, &get, &bingley(), &my_key)
    } else {
        bingley().addr
    };
    println!("My address is {}, also known as {:?}", my_addr, my_addr);

    // When we send messages, we should store their OnionBoxen in this
    // map, so we can listen for the return...
    let mut onionboxen: HashMap<[u8; 32], onionsalt::OnionBox> = HashMap::new();

    for packet in get.iter() {
        match onionbox_open(&packet.data, &my_key.secret) {
            Ok(mut oob) => {
                let routing = RoutingInfo::from_bytes(&oob.routing());
                println!("It's for me! {:?}", routing);
                if routing.is_for_me {
                    match oob.payload(&my_key) {
                        Err(e) => {
                            println!("Unable to read message! {:?}", e);
                        },
                        Ok(payload) => {
                            println!("Got lovely payload {:?}", &payload[0..]);
                            if routing.who_am_i {
                                let mut you_are = [0; PAYLOAD_LENGTH];
                                let mut gift = construct_gift(&addresses);
                                gift[0] = RoutingGift{ addr: packet.ip,
                                                       key: oob.key() };
                                Message::Response(gift).bytes(&mut you_are);
                                oob.respond(&my_key, &you_are);
                                lopriority.send(udp::RawEncryptedMessage{
                                    ip: packet.ip,
                                    data: oob.packet(),
                                }).unwrap();
                            }
                        }
                    }
                }
            },
            _ => {
                let maybe_msg = match onionboxen.get(array_ref![packet.data,0,32]) {
                    Some(ob) =>
                        match ob.read_return(my_key, &packet.data) {
                            Ok(msg) => {
                                println!("Response! (Which I am about to ignore)");
                                Some(msg)
                            },
                            _ => {
                                println!("Message illegible!");
                                None
                            },
                        },
                    None => {
                        println!("Not sure what that was!");
                        None
                    },
                };
                if maybe_msg.is_some() {
                    onionboxen.remove(array_ref![packet.data,0,32]);
                }
            },
        }
    }
    // lopriority.send();
    Ok(())
}
