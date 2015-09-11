#[macro_use]
extern crate arrayref;

extern crate log;

extern crate pmail;
extern crate onionsalt;
extern crate rustbox;

use std::sync::mpsc::{ Receiver, Sender, channel, };
use std::sync::{ Mutex };

use rustbox::{Color, RustBox};
use rustbox::Key;

use pmail::dht;
use pmail::dht::{MyBytes};
use pmail::pmail::{AddressBook};

pub struct Str255 {
    pub length: u8,
    pub content: [u8; 255],
}
impl MyBytes<[u8; 256]> for Str255 {
    fn bytes(&self, out: &mut[u8; 256]) {
        let (l, c) = mut_array_refs![out,1,255];
        l[0] = self.length;
        *c = self.content;
    }
    fn from_bytes(inp: &[u8; 256]) -> Str255 {
        let (l, c) = array_refs![inp,1,255];
        Str255 {
            length: l[0],
            content: *c,
        }
    }
}

pub enum X {
    UserQuery(Str255),
    UserResponse(Str255),
    UserMessage {
        thread_id: u64,
        message_id: u64,
        contents: Str255,
    },
}
impl MyBytes<[u8; 511]> for X {
    fn bytes(&self, _out: &mut[u8; 511]) {
        // let (_, _, c) = mut_array_refs![out,1,8,8,255];
        // *l = self.length;
        // *c = self.contents;
    }
    fn from_bytes(inp: &[u8; 511]) -> X {
        unimplemented!()
    }
}

struct LogData {
    messages: Vec<String>,
    r: Receiver<String>,
}
struct LogChan(Mutex<Sender<String>>);

impl log::Log for LogChan {
    fn enabled(&self, metadata: &log::LogMetadata) -> bool {
        metadata.level() <= log::LogLevel::Info
    }

    fn log(&self, record: &log::LogRecord) {
        if self.enabled(record.metadata()) {
            self.0.lock().unwrap().send(format!("{}", record.args()));
        }
    }
}

fn show_logs(rb: &RustBox, logdata: &mut LogData) {
    while let Ok(s) = logdata.r.try_recv() {
        logdata.messages.push(s);
    }
    let right = rb.width();
    for i in 0 .. logdata.messages.len() {
        rb.print(right/3, 1 + i,
                 rustbox::RB_NORMAL, Color::White, Color::Black, &logdata.messages[i]);
    }
}
fn show_addressbook(rb: &RustBox, ab: &AddressBook) {
    rb.clear();
    rb.print(1, 1, rustbox::RB_BOLD, Color::White, Color::Black, "Hello, world!");
    rb.print(1, 3, rustbox::RB_BOLD, Color::Red, Color::Black,
             "Press 'q' to quit.");
    let names = ab.list_public_keys();
    let mut width = "Users".len();
    for n in names.iter() {
        if n.len() > width {
            width = n.len();
        }
    }
    let width = width + 3;
    for i in 0 .. names.len() {
        rb.print_char(0, 5 + i*2-1, rustbox::RB_NORMAL, Color::Green, Color::Black, '├');
        for j in 1 .. width {
            rb.print_char(j, 5 + i*2-1, rustbox::RB_NORMAL, Color::Green, Color::Black, '─');
        }
        rb.print_char(width, 5 + i*2-1, rustbox::RB_NORMAL, Color::Green, Color::Black, '┤');
        rb.print_char(0, 5 + i*2, rustbox::RB_NORMAL, Color::Green, Color::Black, '│');
        rb.print_char(width, 5 + i*2, rustbox::RB_NORMAL, Color::Green, Color::Black, '│');
        rb.print(1+(width - names[i].len())/2, 5 + i*2,
                 rustbox::RB_BOLD, Color::White, Color::Black, names[i]);
    }
    rb.print_char(0, 5 + names.len()*2-1, rustbox::RB_NORMAL, Color::Green, Color::Black, '└');
    for j in 1 .. width {
        rb.print_char(j, 5 + names.len()*2-1, rustbox::RB_NORMAL, Color::Green, Color::Black, '─');
    }
    rb.print_char(width, 5 + names.len()*2-1, rustbox::RB_NORMAL, Color::Green, Color::Black, '┘');

    rb.print_char(0, 4, rustbox::RB_NORMAL, Color::Green, Color::Black, '┌');
    rb.print_char(width, 4, rustbox::RB_NORMAL, Color::Green, Color::Black, '┐');
}

fn main() {
    let mut logdata = {
        let (s,r) = channel();
        log::set_logger(move|max_log_level| {
            max_log_level.set(log::LogLevelFilter::Info);
            Box::new(LogChan(Mutex::new(s)))
        });
        LogData {
            messages: Vec::new(),
            r: r,
        }
    };

    let my_personal_key = {
        let mut name = dht::pmail_dir().unwrap();
        name.push("personal.key");
        dht::read_or_generate_keypair(name).unwrap()
    };
    let mut addressbook = AddressBook::read().unwrap();
    addressbook.assert_secret_id("myself", &my_personal_key.public);

    println!("Pmail starting! {:?}", my_personal_key.public);
    let (ask_rendevous, hear_rendevous, _send, receive) = dht::start_static_node().unwrap();
    if false {
        for r in receive.iter() {
            println!("received {:?}", r);

            ask_rendevous.send(my_personal_key.public).unwrap();
            let rendevous_point = hear_rendevous.recv().unwrap();
            println!("Rendezvous point {:?}", rendevous_point);
        }
        println!("All done!");
    }


    let rustbox = match RustBox::init(Default::default()) {
        Result::Ok(v) => v,
        Result::Err(e) => panic!("{}", e),
    };

    loop {
        show_addressbook(&rustbox, &addressbook);
        show_logs(&rustbox, &mut logdata);
        rustbox.present();
        match rustbox.poll_event(false) {
            Ok(rustbox::Event::KeyEvent(key)) => {
                match key {
                    Some(Key::Char('q')) => { break; }
                    _ => { }
                }
            },
            Err(e) => panic!("{}", e),
            _ => { }
        }
    }
}
