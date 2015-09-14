//! This module handles pmail communication at a logical and personal
//! level, and uses `dht` to manage the actual communication.

// use super::dht;

use onionsalt::crypto;
use std;
use std::collections::HashMap;
use dht;
use dht::{UserMessage, EncryptedMessage,
          USER_MESSAGE_LENGTH, DECRYPTED_USER_MESSAGE_LENGTH};

use std::sync::mpsc::{ Receiver, SyncSender,
                       Sender, };

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

    pub fn send(&self, who: &crypto::PublicKey, msg: &[u8; DECRYPTED_USER_MESSAGE_LENGTH]) {
        let ren = self.rendezvous(who);
        let c = double_box(msg, who, &self.myself);
        self.message_sender.send(EncryptedMessage {
            destination: *who,
            rendezvous: ren,
            contents: c,
        }).unwrap();
    }

    pub fn listen(&self) -> Option<(crypto::PublicKey, [u8; DECRYPTED_USER_MESSAGE_LENGTH])> {
        if let Ok(m) = self.message_receiver.try_recv() {
            if m.destination != self.myself.public {
                return None;
            }
            double_unbox(&m.message, &self.myself.secret).ok()
        } else {
            None
        }
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

pub fn double_box(p: &[u8; DECRYPTED_USER_MESSAGE_LENGTH],
                  pk: &crypto::PublicKey, my: &crypto::KeyPair) -> [u8; USER_MESSAGE_LENGTH] {
    let mut pp = [0u8; USER_MESSAGE_LENGTH];
    let mut c = [0u8; USER_MESSAGE_LENGTH];
    *array_mut_ref![pp, USER_MESSAGE_LENGTH - DECRYPTED_USER_MESSAGE_LENGTH,
                    DECRYPTED_USER_MESSAGE_LENGTH] = *p;
    let n = crypto::random_nonce().unwrap();
    crypto::box_up(array_mut_ref![pp, 32+16+24+32-16, DECRYPTED_USER_MESSAGE_LENGTH+32],
                   array_ref![c, 32+16+24+32-16, DECRYPTED_USER_MESSAGE_LENGTH+32],
                   &n, pk, &my.secret);
    *array_mut_ref![c,32+16, 24] = n.0;
    *array_mut_ref![c,32+16+24, 32] = my.public.0;
    let k = crypto::box_keypair().unwrap();
    crypto::box_up(array_mut_ref![pp, 16, USER_MESSAGE_LENGTH-16],
                   array_ref![c, 16, USER_MESSAGE_LENGTH-16],
                   &crypto::Nonce([0;24]), pk, &k.secret);
    *array_mut_ref![pp,0,32] = k.public.0;
    pp
}

pub fn double_unbox(c: &[u8; USER_MESSAGE_LENGTH], sk: &crypto::SecretKey)
                    -> Result<(crypto::PublicKey, [u8; DECRYPTED_USER_MESSAGE_LENGTH]), crypto::NaClError> {
    let mut p = [0u8; USER_MESSAGE_LENGTH];
    let pk1 = crypto::PublicKey(*array_ref![c, 0, 32]);
    let mut c = *c;
    *array_mut_ref![c, 0, 32] = [0;32];
    try!(crypto::box_open(array_mut_ref![p,16,USER_MESSAGE_LENGTH-16],
                          array_ref![c,16,USER_MESSAGE_LENGTH-16],
                          &crypto::Nonce([0;24]), &pk1, sk));
    let n = crypto::Nonce(*array_mut_ref![c,32+16, 24]);
    let pk = crypto::PublicKey(*array_mut_ref![c,32+16+24, 32]);
    try!(crypto::box_open(array_mut_ref![c, 32+16+24+32-16, DECRYPTED_USER_MESSAGE_LENGTH+32],
                          array_ref![p, 32+16+24+32-16, DECRYPTED_USER_MESSAGE_LENGTH+32],
                          &n, &pk, sk));
    let (_, out) = array_refs!(&c, 32+16+24+32+32, 375);
    Ok((pk, *out))
}
