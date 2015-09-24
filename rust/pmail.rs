//! This module handles pmail communication at a logical and personal
//! level, and uses `dht` to manage the actual communication.

// use super::dht;

use onionsalt::crypto;
use std;
use std::collections::HashMap;
use dht;
use dht::{UserMessage, EncryptedMessage,
          MyBytes, DECRYPTED_USER_MESSAGE_LENGTH, USER_MESSAGE_LENGTH};
use message;
use onionsalt::{PAYLOAD_LENGTH};

use std::sync::mpsc::{ Receiver, SyncSender,
                       Sender, };

use str255::{Str255};
use serde;

#[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct Thread(pub u64);

impl Thread {
    pub fn random() -> Self {
        Thread(crypto::random_u64())
    }
}
impl std::fmt::Display for Thread {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        f.write_str(&format!("{:016x}", self.0))
    }
}
impl serde::de::Deserialize for Thread {
    fn deserialize<D>(deserializer: &mut D) -> Result<Self, D::Error> where D: serde::Deserializer {
        use serde::de::Deserialize;
        use serde::de::Error;
        match String::deserialize(deserializer) {
            Err(e) => Err(e),
            Ok(bb) => {
                let bb = bb.as_bytes();
                if bb.len() == 16 {
                    match sixteen_hex_to_u64(array_ref![bb,0,16]) {
                        Some(v) => Ok(Thread(v)),
                        None => Err(D::Error::syntax("invalid hex for Thread")),
                    }
                } else {
                    Err(D::Error::syntax("wrong size for Thread"))
                }
            },
        }
    }
}
impl serde::ser::Serialize for Thread {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error> where S: serde::ser::Serializer {
        use serde::ser::Serialize;
        format!("{}", self).serialize(serializer)
    }
}
fn sixteen_hex_to_u64(bytes: &[u8;16]) -> Option<u64> {
    fn hexit_to_u8(hexit: u8) -> Option<u8> {
        match hexit {
            b'0' ... b'9' => Some(hexit - b'0'),
            b'a' ... b'f' => Some(hexit - b'a' + 10),
            _ => None,
        }
    }
    let mut out = 0;
    for i in 0 .. 16 {
        match hexit_to_u8(bytes[i]) {
            None => { return None; },
            Some(b) => {
                out = out << 4;
                out += b as u64;
            },
        }
    }
    Some(out)
}

pub enum Message {
    UserQuery {
        user: Str255
    },
    UserResponse {
        user: Str255,
        key: crypto::PublicKey
    },
    Comment {
        thread: Thread,
        time: u32,
        message_length: u32,
        message_start: u32, // for long messages!
        contents: [u8; 394],
    },
    ThreadRecipients {
        thread: Thread,
        num_recipients: u8,
        recipients: [crypto::PublicKey; 9],
    },
    ThreadSubject {
        thread: Thread,
        subject: [u8; 80],
    },
    Acknowledge {
        msg_id: message::Id,
    },
}
impl Message {
    fn needs_acknowledgement(&self) -> bool {
        match *self {
            Message::Comment {..} | Message::ThreadSubject {..} | Message::ThreadRecipients {..} => true,
            _ => false,
        }
    }
}
impl Clone for Message {
    fn clone(&self) -> Self {
        use self::Message::*;
        match *self {
            UserQuery { ref user } => UserQuery { user: user.clone() },
            UserResponse {ref user, key} => UserResponse {user: user.clone(), key: key},
            Comment {thread,time,message_length,message_start,contents} =>
                Comment {thread:thread,time:time,message_length:message_length,message_start:message_start,contents:contents},
            ThreadRecipients {thread,num_recipients,recipients} =>
                ThreadRecipients {thread:thread,num_recipients:num_recipients,recipients:recipients},
            ThreadSubject {thread,subject} => ThreadSubject {thread:thread,subject:subject},
            Acknowledge {msg_id} => Acknowledge {msg_id:msg_id},
        }
    }
}
impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match self {
            &Message::UserQuery { ref user } => {
                f.write_str(&format!("UserQuery({})", user))
            },
            &Message::UserResponse { ref user, ref key } => {
                f.write_str(&format!("UserResponse({}, {})", user, key))
            },
            &Message::Comment { ref thread, ref time, ref message_length,
                                ref message_start, .. } => {
                f.write_str(&format!("Comment({:x}, {}, {}, {}, ...)",
                                     thread.0, time, message_length, message_start))
            },
            &Message::Acknowledge { ref msg_id } => {
                if *msg_id == message::Id([0;32]) && false {
                    f.write_str(&format!("<invalid Message>"))
                } else {
                    f.write_str(&format!("Acknowledge({})", msg_id))
                }
            },
            _ => {
                f.write_str("<unhandled?>")
            },
        }
    }
}
impl MyBytes<[u8; DECRYPTED_USER_MESSAGE_LENGTH]> for Message {
    fn bytes(&self, out: &mut[u8; DECRYPTED_USER_MESSAGE_LENGTH]) {
        match *self {
            Message::UserQuery { ref user } => {
                out[0] = b'q';
                user.bytes(array_mut_ref![out,1,256]);
            },
            Message::UserResponse { ref user, ref key } => {
                let (z, u, k, _) = mut_array_refs!(out, 1, 256, 32, 126);
                z[0] = b'r';
                user.bytes(u);
                key.bytes(k);
            },
            Message::Comment { ref thread, ref time, ref message_length,
                               ref message_start, ref contents } => {
                let (z, t, cid, ml, ms, c) = mut_array_refs!(out, 1, 8, 4, 4, 4, 394);
                z[0] = b'c';
                thread.0.bytes(t);
                time.bytes(cid);
                message_length.bytes(ml);
                message_start.bytes(ms);
                *c = *contents;
            },
            Message::Acknowledge { ref msg_id } => {
                let (z, id, _) = mut_array_refs!(out, 1, 32, 382);
                z[0] = b'a';
                msg_id.bytes(id);
            },
            _ => {
                *out = [0; DECRYPTED_USER_MESSAGE_LENGTH];
            },
        }
    }
    fn from_bytes(inp: &[u8; DECRYPTED_USER_MESSAGE_LENGTH]) -> Message {
        match inp[0] {
            b'q' => Message::UserQuery {
                user: Str255::from_bytes(array_ref![inp,1,256]),
            },
            b'r' => {
                let (_, u, k, _) = array_refs!(inp, 1, 256, 32, 126);
                Message::UserResponse {
                    user: Str255::from_bytes(u),
                    key: crypto::PublicKey::from_bytes(k),
                }
            },
            b'c' => {
                let (_, t, cid, ml, ms, c) = array_refs!(inp, 1, 8, 4, 4, 4, 394);
                Message::Comment {
                    thread: Thread(u64::from_bytes(t)),
                    time: u32::from_bytes(cid),
                    message_length: u32::from_bytes(ml),
                    message_start: u32::from_bytes(ms),
                    contents: *c,
                }
            },
            b'a' => {
                let (_, id, _) = array_refs!(inp, 1, 32, 382);
                Message::Acknowledge {
                    msg_id: message::Id::from_bytes(id),
                }
            },
            _ => Message::Acknowledge { msg_id: message::Id([0;32]) }
        }
    }
}

#[cfg(test)]
fn test_message(m: Message) {
    let mut buf = [0; DECRYPTED_USER_MESSAGE_LENGTH];
    m.bytes(&mut buf);
    let newm = Message::from_bytes(&buf);
    let mut buf2 = [0; DECRYPTED_USER_MESSAGE_LENGTH];
    newm.bytes(&mut buf2);
    for i in 0 .. buf.len() {
        assert_eq!(buf[i], buf2[i]);
    }
}

#[test]
fn query_bytes() {
    test_message( Message::UserQuery {
        user: Str255::from("hello"),
    });
}
#[test]
fn response_bytes() {
    test_message( Message::UserResponse {
        user: Str255::from("hello"),
        key: crypto::PublicKey([0;32]),
    });
}
#[test]
fn acknowledge_bytes() {
    let k = crypto::box_keypair();
    let id = message::Id(k.public.0);
    test_message( Message::Acknowledge {
        msg_id: id,
    });
    let k = crypto::box_keypair();
    let id = message::Id(k.public.0);
    test_message( Message::Acknowledge {
        msg_id: id,
    });
    let k = crypto::box_keypair();
    let id = message::Id(k.public.0);
    test_message( Message::Acknowledge {
        msg_id: id,
    });
}

pub fn read_key(name: &std::path::Path) -> Result<crypto::PublicKey, std::io::Error> {
    use std::io::Read;

    let mut f = try!(std::fs::File::open(name));
    let mut data = Vec::new();
    try!(f.read_to_end(&mut data));
    if data.len() != 32 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "oh no!"));
    }
    Ok(crypto::PublicKey(*array_ref![data, 0, 32]))
}

pub struct AddressBook {
    /// These are keys that we are willing to share with others who
    /// might query regarding them.  i.e. we are unashamed that we
    /// know these people.
    public_ids: HashMap<String, crypto::PublicKey>,
    /// These are keys that we do not want to share.  Secret
    /// identities or alter egos, etc.
    secret_ids: HashMap<String, crypto::PublicKey>,
    unacknowledged: HashMap<message::Id, (crypto::PublicKey, [u8;USER_MESSAGE_LENGTH])>,
    myself: crypto::KeyPair,
    hear_rendezvous: Receiver<crypto::PublicKey>,
    ask_rendezvous: SyncSender<crypto::PublicKey>,
    message_sender: Sender<EncryptedMessage>,
    message_receiver: Receiver<UserMessage>,
}

impl AddressBook {
    pub fn lookup(&self, id: &str) -> Option<crypto::PublicKey> {
        match self.public_ids.get(id) {
            Some(k) => {
                return Some(*k);
            },
            None => {},
        }
        match self.secret_ids.get(id) {
            Some(k) => Some(*k),
            None => None,
        }
    }
    pub fn lookup_public(&self, id: &str) -> Option<crypto::PublicKey> {
        match self.public_ids.get(id) {
            Some(k) => {
                Some(*k)
            },
            None => None,
        }
    }
    pub fn reverse_lookup(&self, who: &crypto::PublicKey) -> Option<String> {
        let mut s = String::new();
        for (v,k) in self.public_ids.iter() {
            if k == who {
                if s == "" {
                    s = s + v;
                } else {
                    s = format!("{} a.k.a. {}", s, v);
                }
            }
        }
        for (v,k) in self.secret_ids.iter() {
            if k == who {
                if s == "" {
                    s = format!("\"{}\"", v);
                } else {
                    s = format!("{} a.k.a. \"{}\"", s, v);
                }
            }
        }
        if s == "" {
            None
        } else {
            Some(s)
        }
    }
    pub fn assert_secret_id(&mut self, id: &str, k: &crypto::PublicKey) {
        self.secret_ids.insert(id.to_string(), *k);
        self.public_ids.remove(id);
    }
    pub fn assert_public_equivalence(&mut self, id: &str, new_id: &str) {
        if let Some(k) = self.lookup(id) {
            self.public_ids.insert(new_id.to_string(), k);
            self.secret_ids.remove(new_id);
        }
    }
    pub fn assert_public_id(&mut self, id: &str, k: &crypto::PublicKey) {
        self.public_ids.insert(id.to_string(), *k);
        self.secret_ids.remove(id);
    }
    pub fn remove_id(&mut self, id: &str) {
        self.secret_ids.remove(id);
        self.public_ids.remove(id);
    }
    /// Ugh, this function returns an ugly type and should be changed
    /// to return an `Iterator` when I understand how to do this.
    pub fn list_public_keys(&self) -> Vec<&String> {
        use std::iter::FromIterator;
        Vec::from_iter(self.public_ids.keys())
    }
    /// Ugh, this function also returns an ugly type and should be changed
    /// to return an `Iterator` when I understand how to do this.
    pub fn list_secret_keys(&self) -> Vec<&String> {
        use std::iter::FromIterator;
        Vec::from_iter(self.secret_ids.keys())
    }
    fn public_secret_dirs() -> Result<(std::path::PathBuf, std::path::PathBuf), std::io::Error> {
        let mut address_dir = match std::env::home_dir() {
            Some(hd) => hd,
            None => std::path::PathBuf::from("."),
        };
        address_dir.push(".pmail/addressbook");
        let address_dir = address_dir;

        let mut public_dir = address_dir.clone();
        public_dir.push("public");
        let public_dir = public_dir;
        try!(std::fs::create_dir_all(&public_dir));

        let mut secret_dir = address_dir.clone();
        secret_dir.push("secret");
        let secret_dir = secret_dir;
        try!(std::fs::create_dir_all(&secret_dir));
        Ok((public_dir, secret_dir))
    }

    pub fn rendezvous(&self, k: &crypto::PublicKey) -> crypto::PublicKey {
        self.ask_rendezvous.send(*k).unwrap();
        self.hear_rendezvous.recv().unwrap()
    }

    pub fn send(&mut self, who: &crypto::PublicKey, msg: &Message) -> message::Id {
        let mut plaintext = [0u8; DECRYPTED_USER_MESSAGE_LENGTH];
        msg.bytes(&mut plaintext);
        let (msg_id, c) = dht::double_box(&plaintext, who, &self.myself);
        // info!(" ****** \"{}\" ****** {} ******", dht::codename(&c),
        //       dht::codename(&c[32+24 .. 32+24+6]));

        self.send_doubleboxed(who, &msg_id, &c);

        if msg.needs_acknowledgement() {
            self.unacknowledged.insert(msg_id, (*who, c));

            let mut q = String::new();
            for k in self.unacknowledged.keys() {
                q = format!("{} '{}'", q, dht::codename(&k.0));
            }
            info!("Messages in queue: {}", q);
        }
        msg_id
    }
    pub fn send_doubleboxed(&mut self, who: &crypto::PublicKey, msg_id: &message::Id, c: &[u8;USER_MESSAGE_LENGTH]) {
        let ren = self.rendezvous(who);

        let mut p = [0; PAYLOAD_LENGTH];
        dht::Message::ForwardPlease {
            destination: *who,
            message: *c,
        }.bytes(&mut p);

        info!("Sent message {}", dht::codename(&msg_id.0));
        self.message_sender.send(EncryptedMessage {
            rendezvous: ren,
            contents: p,
        }).unwrap();
    }

    pub fn pickup(&mut self) {
        let ren = self.rendezvous(&self.myself.public);
        // info!("   ═══ Sending pickup request to {}! ═══", ren);
        let msg = [0; DECRYPTED_USER_MESSAGE_LENGTH];
        let (_, c) = dht::double_box(&msg, &ren, &self.myself);
        // info!("  E {} size {}", dht::codename(&c), c.len());

        let mut p = [0; PAYLOAD_LENGTH];
        dht::Message::PickUp {
            destination: self.myself.public,
            message: c,
        }.bytes(&mut p);

        self.message_sender.send(EncryptedMessage {
            rendezvous: ren,
            contents: p,
        }).unwrap();

        let num_unacknowledged = self.unacknowledged.len();
        if num_unacknowledged > 0 {
            // The following is a ridiculous contortion to get around
            // the borrow checker.  This is one trouble with grouping
            // several data structures into an object in rust.  A
            // borrow on any is a borrow on all.  :( To quote the
            // Fullmetal Alchemist: One is all, and all is one.
            let somev: Option<(message::Id, crypto::PublicKey, [u8;USER_MESSAGE_LENGTH])> = {
                let somev = self.unacknowledged.iter().nth(crypto::random_u32() as usize % num_unacknowledged);
                match somev {
                    None => None,
                    Some((a,b)) => Some((a.clone(),b.0.clone(),b.1)),
                }
            };
            if let Some(v) = somev {
                info!("I am going to retry...");
                self.send_doubleboxed(&v.1,&v.0,&v.2);
            }
        }
    }

    pub fn listen(&mut self) -> Option<(crypto::PublicKey, message::Id, Message)> {
        if let Ok(m) = self.message_receiver.try_recv() {
            if m.destination != self.myself.public {
                return None;
            }
            if let Ok((k, msg_id, data)) = dht::double_unbox(&m.message, &self.myself.secret) {
                // println!("\r\n ****** \"{}\" ****** {}\r\n", dht::codename(&m.message),
                //          dht::codename(&m.message[32+24 .. 32+24+6]));
                // println!("\r\nlisten is decrypted to \"{}\" a.k.a. {:?}\r\n",
                //          dht::codename(&data), &data[0..7]);

                let m = Message::from_bytes(&data);
                match m {
                    Message::Acknowledge { msg_id } => {
                        if self.unacknowledged.contains_key(&msg_id) {
                            info!("Acknowledgement of message {}", dht::codename(&msg_id.0));
                            self.unacknowledged.remove(&msg_id);
                        } else {
                            info!("Duplicate acknowledgement of message {}", dht::codename(&msg_id.0));
                        }
                        let mut q = String::new();
                        for k in self.unacknowledged.keys() {
                            q = format!("{} '{}'", q, dht::codename(&k.0));
                        }
                        info!("Messages remaining in queue: {}", q);
                    },
                    _ => {},
                };

                return Some((k, msg_id, m));
            }
        }
        None
    }

    pub fn read() -> Result<AddressBook, std::io::Error> {
        let my_personal_key = {
            let mut name = dht::pmail_dir().unwrap();
            name.push("personal.key");
            dht::read_or_generate_keypair(name).unwrap()
        };
        let (public_dir, secret_dir) = try!(AddressBook::public_secret_dirs());
        let (ask_rendezvous, hear_rendezvous, send, receive) = try!(dht::start_static_node());

        let mut ab = AddressBook {
            public_ids: HashMap::new(),
            secret_ids: HashMap::new(),
            unacknowledged: HashMap::new(),
            myself: my_personal_key,
            ask_rendezvous: ask_rendezvous,
            hear_rendezvous: hear_rendezvous,
            message_sender: send,
            message_receiver: receive,
        };
        ab.secret_ids.insert("myself".to_string(), my_personal_key.public);
        for entry in try!(std::fs::read_dir(&secret_dir)) {
            let entry = try!(entry);
            if try!(std::fs::metadata(&entry.path())).is_file() {
                match entry.file_name().to_str() {
                    Some(filename) => {
                        println!("examining secret {}", filename);
                        match read_key(&entry.path()) {
                            Ok(k) => {
                                ab.secret_ids.insert(filename.to_string(), k);
                            },
                            _ => {
                                println!("Could not read entry {}", entry.path().display());
                            },
                        }
                    },
                    None => (),
                }
            }
        }
        for entry in try!(std::fs::read_dir(&public_dir)) {
            let entry = try!(entry);
            if try!(std::fs::metadata(&entry.path())).is_file() {
                match entry.file_name().to_str() {
                    Some(filename) => {
                        println!("examining public {}", filename);
                        match read_key(&entry.path()) {
                            Ok(k) => {
                                ab.public_ids.insert(filename.to_string(), k);
                            },
                            _ => {
                                println!("Could not read entry {}", entry.path().display());
                            },
                        }
                    },
                    None => (),
                }
            }
        }

        Ok(ab)
    }
    pub fn write(&self) -> Result<(), std::io::Error> {
        use std::io::Write;
        let (public_dir, secret_dir) = try!(AddressBook::public_secret_dirs());
        for s in self.public_ids.keys() {
            let mut name = public_dir.clone();
            name.push(s);
            let name = name; // make it non-mutable.

            let mut f = try!(std::fs::File::create(name));
            try!(f.write_all(&self.public_ids[s].0));
        }
        for s in self.secret_ids.keys() {
            let mut name = secret_dir.clone();
            name.push(s);
            let name = name; // make it non-mutable.

            let mut f = try!(std::fs::File::create(name));
            try!(f.write_all(&self.secret_ids[s].0));
        }
        Ok(())
    }

    pub fn my_key(&self) -> crypto::PublicKey {
        self.myself.public
    }
}

impl Drop for AddressBook {
    fn drop(&mut self) {
        if self.write().is_ok() {
            println!("Wrote addressbook successfully!");
        } else {
            println!("Unable to write addressbook.  :(");
        }
    }
}
