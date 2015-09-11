//! This module handles pmail communication at a logical and personal
//! level, and uses `dht` to manage the actual communication.

// use super::dht;

use onionsalt::crypto;
use std;
use std::collections::HashMap;

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
    }
    pub fn assert_public_id(&mut self, id: &str, k: &crypto::PublicKey) {
        self.public_ids.insert(id.to_string(), *k);
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
    pub fn read() -> Result<AddressBook, std::io::Error> {
        let (public_dir, secret_dir) = try!(AddressBook::public_secret_dirs());

        let mut ab = AddressBook {
            public_ids: HashMap::new(),
            secret_ids: HashMap::new(),
        };
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
