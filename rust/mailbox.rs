use std;
extern crate time;

use pmail;
use message;
use udp;
use onionsalt::crypto;

pub struct Mailbox {
    dir: std::path::PathBuf,
}

impl Mailbox {
    pub fn new() -> Result<Mailbox, std::io::Error> {
        let mut dir = match std::env::home_dir() {
            Some(hd) => hd,
            None => std::path::PathBuf::from("."),
        };
        dir.push(".pmail/messages");
        try!(std::fs::create_dir_all(&dir));
        Ok(Mailbox {
            dir: dir,
        })
    }
    pub fn save(&mut self, msg_id: message::Id, from: &crypto::PublicKey, msg: &pmail::Message) -> Result<(), std::io::Error> {
        use std::io::Write;
        use pmail::Message::*;
        match *msg {
            Comment { thread, time: epochtime, message_length, contents, .. } => {
                let name = try!(self.comment_name(thread, epochtime, msg_id));
                let mut f = try!(std::fs::File::create(name));
                if (message_length as usize) < contents.len() {
                    try!(f.write_all(format!("{}", from).as_bytes()));
                    try!(f.write_all(&contents));
                }
            },
            _ => {
                info!("How do I save this?");
            },
        }
        Ok(())
    }
    pub fn comment_name(&self, thread: u64, epochtime: u32, id: message::Id)
                        -> Result<std::path::PathBuf, std::io::Error> {
        let mut dir = try!(self.thread_dir(thread));
        try!(std::fs::create_dir_all(&dir));
        let mut when = udp::EPOCH;
        when.sec += epochtime as i64;
        let date = time::at_utc(when);
        dir.push(format!("{}-{}", date.rfc3339(), id));
        Ok(dir)
    }
    pub fn thread_dir(&self, thread: u64) -> Result<std::path::PathBuf, std::io::Error> {
        let mut dir = self.dir.clone();
        dir.push(format!("{:02x}", thread & 0xff));
        dir.push(format!("{:014x}", thread >> 1));
        try!(std::fs::create_dir_all(&dir));
        Ok(dir)
    }

    pub fn threads(&mut self) {
    }
    pub fn users(&mut self) {
    }
    pub fn threads_from_user(&mut self) {
    }
    pub fn comments_in_thread(&mut self) {
    }
}

