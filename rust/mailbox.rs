use std;
use serde_json;
extern crate time;
extern crate lazyfs;

use format;
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
    pub fn in_directory(d: &str) -> Result<Mailbox, std::io::Error> {
        let mut dir = std::path::PathBuf::from(d);
        dir.push(".pmail/messages");
        try!(std::fs::create_dir_all(&dir));
        Ok(Mailbox {
            dir: dir,
        })
    }
    pub fn save(&mut self, msg_id: message::Id, from: &crypto::PublicKey, msg: &pmail::Message) -> Result<(), std::io::Error> {
        use pmail::Message::*;
        match *msg {
            Comment { thread, time: epochtime, message_start, message_length, contents } => {
                let name = try!(self.comment_name(thread, epochtime, msg_id));

                if message_start > 0 || message_length as usize > contents.len() {
                    println!("I do not yet handle broken-up messages.");
                } else {
                    let formatted = format::Message {
                        thread: thread,
                        time: format::epoch_to_rfc3339(epochtime),
                        id: msg_id,
                        from: *from,
                        contents: String::from_utf8_lossy(&contents[0..message_length as usize]).to_string(),
                    };
                    let mut f = try!(std::fs::File::create(name));
                    match serde_json::to_writer(&mut f, &formatted) {
                        Err(e) => { return Err(std::io::Error::new(std::io::ErrorKind::Other,
                                                                   format!("error writing json {}", e))); }
                        _ => {}
                    }
                }
            },
            _ => {
                info!("How do I save this?");
            },
        }
        Ok(())
    }
    pub fn comment_name(&self, thread: pmail::Thread, epochtime: u32, id: message::Id)
                        -> Result<std::path::PathBuf, std::io::Error> {
        let mut dir = try!(self.thread_dir(thread));
        try!(std::fs::create_dir_all(&dir));
        let mut when = udp::EPOCH;
        when.sec += epochtime as i64;
        let date = time::at_utc(when);
        dir.push(format!("{}-{}", date.rfc3339(), id));
        Ok(dir)
    }
    pub fn thread_dir(&self, thread: pmail::Thread) -> Result<std::path::PathBuf, std::io::Error> {
        let mut dir = self.dir.clone();
        dir.push(format!("{:02x}", thread.0 >> 56));
        dir.push(format!("{:14x}", thread.0 & 0xffffffffffffff));
        try!(std::fs::create_dir_all(&dir));
        Ok(dir)
    }

    pub fn threads(&self) -> Box<Iterator<Item=pmail::Thread>> {
        let dir = self.dir.clone();
        Box::new(lazyfs::read_dir(&dir).filter_map(move|de| {
            de.file_name().as_os_str().to_str().and_then(|s| {
                let bs = s.as_bytes();
                if bs.len() == 2 {
                    hex_to_u8(array_ref![bs,0,2])
                } else {
                    None
                }
            })
        }).flat_map(move|first_byte| {
            let mut subdir = dir.clone();
            subdir.push(&format!("{:02x}", first_byte));
            lazyfs::read_dir(&subdir).filter_map(move |de| {
                de.file_name().as_os_str().to_str().and_then(|s| {
                    let s = s.as_bytes();
                    if s.len() != 14 {
                        None
                    } else {
                        fourteen_hex_to_u64(array_ref![s,0,14])
                    }
                }).map(|t| {
                    pmail::Thread(t + ((first_byte as u64) << 56))
                })
            })
        }))
    }
    pub fn users(&mut self) {
    }
    pub fn threads_from_user(&mut self) {
    }
    pub fn comments_in_thread(&self, thread: pmail::Thread)
                              -> Box<Iterator<Item=format::Message>> {
        let dir = match self.thread_dir(thread) {
            Ok(d) => d,
            _ => {
                return Box::new(std::iter::empty());
            },
        };
        Box::new(lazyfs::read_dir(&dir).filter_map(|de| {
            let name = match de.path().as_os_str().to_str() {
                None => { return None; }
                Some(n) => n.to_string()
            };
            if de.file_name().as_os_str().to_string_lossy().len() != 85 {
                // This is not an actual comment file, so no need to
                // open it up.
                return None;
            }
            // let _msg_id = match name.rsplit('-').next().map(|s|{s.as_bytes()}).and_then(|b| {
            //     if b.len() == 64 {
            //         sixtyfour_hex_to_32_bytes(array_ref![b,0,64]).map(|x|{message::Id(x)})
            //     } else {
            //         println!("Wrong length: '{}'", name);
            //         None
            //     }}) {
            //     Some(x) => x,
            //     None => { return None; }
            // };
            let mut f = match std::fs::File::open(name) {
                Err(_) => { return None; }
                Ok(f) => f,
            };
            serde_json::from_reader(&mut f).ok()
        }))
    }
}

// fn sixtyfour_hex_to_32_bytes(bytes: &[u8;64]) -> Option<[u8;32]> {
//     let mut out = [0;32];
//     for i in 0 .. 32 {
//         match hex_to_u8(array_ref![bytes,2*i,2]) {
//             None => { return None; },
//             Some(b) => {
//                 out[i] = b;
//             },
//         }
//     }
//     Some(out)
// }
fn fourteen_hex_to_u64(bytes: &[u8;14]) -> Option<u64> {
    let mut out = 0;
    for i in 0 .. 14 {
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
fn hex_to_u8(bytes: &[u8;2]) -> Option<u8> {
    match (hexit_to_u8(bytes[0]), hexit_to_u8(bytes[1])) {
        (Some(b1), Some(b2)) => Some(b2 + (b1 << 4)),
        _ => None
    }
}

fn hexit_to_u8(hexit: u8) -> Option<u8> {
    match hexit {
        b'0' ... b'9' => Some(hexit - b'0'),
        b'a' ... b'f' => Some(hexit - b'a' + 10),
        _ => None,
    }
}

#[test]
fn test_hexit() {
    assert_eq!(hexit_to_u8(b'0'), Some(0x0));
    assert_eq!(hexit_to_u8(b'1'), Some(0x1));
    assert_eq!(hexit_to_u8(b'2'), Some(0x2));
    assert_eq!(hexit_to_u8(b'3'), Some(0x3));
    assert_eq!(hexit_to_u8(b'4'), Some(0x4));
    assert_eq!(hexit_to_u8(b'5'), Some(0x5));
    assert_eq!(hexit_to_u8(b'6'), Some(0x6));
    assert_eq!(hexit_to_u8(b'7'), Some(0x7));
    assert_eq!(hexit_to_u8(b'8'), Some(0x8));
    assert_eq!(hexit_to_u8(b'9'), Some(0x9));
    assert_eq!(hexit_to_u8(b'a'), Some(0xa));
    assert_eq!(hexit_to_u8(b'b'), Some(0xb));
    assert_eq!(hexit_to_u8(b'c'), Some(0xc));
    assert_eq!(hexit_to_u8(b'd'), Some(0xd));
    assert_eq!(hexit_to_u8(b'e'), Some(0xe));
    assert_eq!(hexit_to_u8(b'f'), Some(0xf));
}

#[test]
fn test_threads() {
    let m = Mailbox::new().unwrap();
    for t in m.threads() {
        println!("thread is: {:x}", t.0);
    }
}

#[test]
fn test_mailbox() {
    let name = format!("/tmp/testing-{:x}", crypto::random_u64());
    println!("mailbox in {}", name);
    let mut mb = Mailbox::in_directory(&name).unwrap();
    let m1 = format::Message {
        thread: pmail::Thread::random(),
        time: format::epoch_to_rfc3339(crypto::random_u64() as u32),
        id: message::Id::random(),
        from: crypto::box_keypair().public,
        contents: "this is m1".to_string(),
    };
    let m2 = format::Message {
        thread: pmail::Thread::random(),
        time: format::epoch_to_rfc3339(crypto::random_u64() as u32),
        id: message::Id::random(),
        from: crypto::box_keypair().public,
        contents: "this is m2".to_string(),
    };
    let m3 = format::Message {
        thread: m2.thread,
        time: format::epoch_to_rfc3339(crypto::random_u64() as u32),
        id: message::Id::random(),
        from: crypto::box_keypair().public,
        contents: "this is m3".to_string(),
    };
    for m in &[&m1,&m2,&m3] {
        let len = m.contents.as_bytes().len();
        let cc = m.contents.as_bytes();
        let mut c = [0;394];
        for i in 0 .. len {
            c[i] = cc[i];
        }
        let pm = pmail::Message::Comment {
            thread: m.thread,
            time: format::rfc3339_to_epoch(m.time),
            message_start: 0,
            message_length: len as u32,
            contents: c,
        };
        println!("saving thread {} message '{}'", m.thread, m.contents);
        mb.save(m.id, &m.from, &pm).unwrap();
    }
    let mut got_t1 = false;
    let mut got_t2 = false;
    let mut got_m1 = false;
    let mut got_m2 = false;
    let mut got_m3 = false;
    for t in mb.threads() {
        println!("t is {}", t);
        if t == m1.thread { got_t1 = true; }
        if t == m2.thread { got_t2 = true; }
        for c in mb.comments_in_thread(t) {
            println!("c is {}", c.contents);
            if t == m1.thread {
                assert_eq!(c, m1);
                got_m1 = true;
            }
            if c.id == m2.id {
                assert_eq!(c, m2);
                got_m2 = true;
            }
            if c.id == m3.id {
                assert_eq!(c, m3);
                got_m3 = true;
            }
        }
    }
    assert!(got_t1);
    assert!(got_t2);
    assert!(got_m1);
    assert!(got_m2);
    assert!(got_m3);
}
