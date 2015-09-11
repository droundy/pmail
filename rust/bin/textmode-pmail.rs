#[macro_use]
extern crate arrayref;

extern crate pmail;
extern crate onionsalt;
extern crate rustbox;

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

fn main() {
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

    rustbox.print(1, 1, rustbox::RB_BOLD, Color::White, Color::Black, "Hello, world!");
    rustbox.print(1, 3, rustbox::RB_BOLD, Color::Red, Color::Black,
                  "Press 'q' to quit.");
    loop {
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
