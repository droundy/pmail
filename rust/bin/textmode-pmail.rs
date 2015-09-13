#[macro_use]
extern crate arrayref;

extern crate log;
extern crate time;

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
            self.0.lock().unwrap().send(format!("{}", record.args())).unwrap();
        }
    }
}

fn show_logs(rb: &RustBox, logdata: &mut LogData, offset: usize) {
    while let Ok(s) = logdata.r.try_recv() {
        logdata.messages.push(s);
    }
    let right = rb.width();
    let bottom = rb.height();
    if logdata.messages.len() > bottom - 2 {
        let start = logdata.messages.len() - (bottom - 2);
        for i in 0 .. bottom-2 {
            rb.print(offset+1, 1 + i,
                     rustbox::RB_NORMAL, Color::White, Color::Black, &logdata.messages[start+i]);
        }
    } else {
        for i in 0 .. logdata.messages.len() {
            rb.print(offset+1, 1 + i,
                     rustbox::RB_NORMAL, Color::White, Color::Black, &logdata.messages[i]);
        }
    }
    draw_box(rb, offset, 0, right-offset-1, bottom-1);
}
fn show_finduser(rb: &RustBox, logdata: &mut LogData, query: &str, offset: usize) {
    while let Ok(s) = logdata.r.try_recv() {
        logdata.messages.push(s);
    }
    let right = rb.width();
    let bottom = rb.height() - 3;
    if logdata.messages.len() > bottom - 1 {
        let start = logdata.messages.len() - (bottom - 1);
        for i in 0 .. bottom-1 {
            rb.print(offset+1, 1 + i,
                     rustbox::RB_NORMAL, Color::White, Color::Black, &logdata.messages[start+i]);
        }
    } else {
        for i in 0 .. logdata.messages.len() {
            rb.print(offset+1, 1 + i,
                     rustbox::RB_NORMAL, Color::White, Color::Black, &logdata.messages[i]);
        }
    }
    draw_box(rb, offset, 0, right-offset-1, bottom);
    text_box_below(rb, query, offset, bottom, right-offset-1);
}
fn show_messages(rb: &RustBox, logdata: &mut LogData, composing: &str, offset: usize) {
    while let Ok(s) = logdata.r.try_recv() {
        logdata.messages.push(s);
    }
    let right = rb.width();
    let bottom = rb.height() - 3;
    if logdata.messages.len() > bottom - 1 {
        let start = logdata.messages.len() - (bottom - 1);
        for i in 0 .. bottom-1 {
            rb.print(offset+1, 1 + i,
                     rustbox::RB_NORMAL, Color::White, Color::Black, &logdata.messages[start+i]);
        }
    } else {
        for i in 0 .. logdata.messages.len() {
            rb.print(offset+1, 1 + i,
                     rustbox::RB_NORMAL, Color::White, Color::Black, &logdata.messages[i]);
        }
    }
    draw_box(rb, offset, 0, right-offset-1, bottom);
    text_box_below(rb, composing, offset, bottom, right-offset-1);
}
fn show_addressbook(rb: &RustBox, ab: &AddressBook, us: UserState) -> usize {
    rb.clear();
    let names = ab.list_public_keys();
    let mut width = "Show messages [p]".len();
    for n in names.iter() {
        if n.len() > width {
            width = n.len();
        }
    }
    let width = width + 3;
    let mkbold = |b| { if b { rustbox::RB_BOLD } else { rustbox::RB_NORMAL } };
    text_dbox(rb, "Quit [q]", mkbold(false), Color::White, 0, 0, width);
    text_dbox_below(rb, "Show logs [l]", mkbold(us == UserState::Logs), Color::White, 0, 2, width);
    text_dbox_below(rb, "Show messages [p]", mkbold(us == UserState::Messages), Color::White, 0, 4, width);
    text_dbox_below(rb, "Find user [u]", mkbold(us == UserState::FindUser), Color::White, 0, 6, width);
    text_boxes(rb, &names, 0, 9, width);
    width
}

fn main() {
    let mut logdata = {
        let (s,r) = channel();
        log::set_logger(move|max_log_level| {
            max_log_level.set(log::LogLevelFilter::Info);
            Box::new(LogChan(Mutex::new(s)))
        }).unwrap();
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
    let (ask_rendezvous, hear_rendezvous, _send, receive) = dht::start_static_node().unwrap();
    if false {
        for r in receive.iter() {
            println!("received {:?}", r);

            ask_rendezvous.send(my_personal_key.public).unwrap();
            let rendezvous_point = hear_rendezvous.recv().unwrap();
            println!("Rendezvous point {:?}", rendezvous_point);
        }
        println!("All done!");
    }

    println!("Initializing rustbox.");
    let rustbox = match RustBox::init(Default::default()) {
        Result::Ok(v) => v,
        Result::Err(e) => {
            println!("Unable to initialize rustbox!!! :(");
            panic!("Unable to initialize rustbox: {}", e)
        },
    };
    println!("Finished nitializing rustbox.");

    let mut us = UserState::Logs;
    let mut finduser_query = String::new();
    let mut message_tosend = String::new();
    let mut dummy = String::new();
    loop {
        match us {
            UserState::Logs => {
                let width = show_addressbook(&rustbox, &addressbook, us);
                show_logs(&rustbox, &mut logdata, width+1);
            },
            UserState::Messages => {
                let width = show_addressbook(&rustbox, &addressbook, us);
                show_messages(&rustbox, &mut logdata, &message_tosend, width+1);
            },
            UserState::FindUser => {
                let width = show_addressbook(&rustbox, &addressbook, us);
                show_finduser(&rustbox, &mut logdata, &finduser_query, width+1);
            },
        }
        rustbox.present();
        match rustbox.peek_event(time::Duration::milliseconds(500), false) {
            Ok(rustbox::Event::KeyEvent(key)) => {
                let editing = match us {
                    UserState::Logs => { &mut dummy }
                    UserState::FindUser => { &mut finduser_query }
                    UserState::Messages => { &mut message_tosend }
                };
                match key {
                    Some(Key::Ctrl('q')) => { break; }
                    Some(Key::Esc) => { break; }
                    Some(Key::Ctrl('l')) => { us = UserState::Logs; }
                    Some(Key::Ctrl('p')) => { us = UserState::Messages; }
                    Some(Key::Ctrl('u')) => { us = UserState::FindUser; }
                    Some(Key::Char(c)) => { editing.push(c); }
                    Some(Key::Enter) => { *editing = String::new(); }
                    Some(Key::Backspace) => { editing.pop(); }
                    _ => { }
                }
            },
            Err(e) => panic!("{}", e),
            _ => { }
        }
    }
}

#[derive(Clone,Copy,Eq,PartialEq)]
enum UserState {
    Logs,
    Messages,
    FindUser,
}

fn draw_box(rb: &RustBox, x: usize, y: usize, width: usize, height: usize) {
    rb.print_char(x, y, rustbox::RB_NORMAL, Color::Green, Color::Black, '┌');
    rb.print_char(x, y+height, rustbox::RB_NORMAL, Color::Green, Color::Black, '└');
    rb.print_char(x+width, y, rustbox::RB_NORMAL, Color::Green, Color::Black, '┐');
    rb.print_char(x+width, y+height, rustbox::RB_NORMAL, Color::Green, Color::Black, '┘');
    for j in 1 .. width {
        rb.print_char(x+j, y, rustbox::RB_NORMAL, Color::Green, Color::Black, '─');
        rb.print_char(x+j, y+height, rustbox::RB_NORMAL, Color::Green, Color::Black, '─');
    }
    for j in 1 .. height {
        rb.print_char(x, y+j, rustbox::RB_NORMAL, Color::Green, Color::Black, '│');
        rb.print_char(x+width, y+j, rustbox::RB_NORMAL, Color::Green, Color::Black, '│');
    }
}

fn draw_box_below(rb: &RustBox, x: usize, y: usize, width: usize, height: usize) {
    draw_box(rb, x, y, width, height);
    rb.print_char(x, y, rustbox::RB_NORMAL, Color::Green, Color::Black, '├');
    rb.print_char(x+width, y, rustbox::RB_NORMAL, Color::Green, Color::Black, '┤');
}

// ═	║	╔	╗	╚	╝	╞	╟	╠	╡	╢	╣	╤	╥	╦	╧	╨	╩	╪	╫	╬

fn draw_dbox(rb: &RustBox, x: usize, y: usize, width: usize, height: usize) {
    rb.print_char(x, y, rustbox::RB_NORMAL, Color::Green, Color::Black, '╔');
    rb.print_char(x, y+height, rustbox::RB_NORMAL, Color::Green, Color::Black, '╚');
    rb.print_char(x+width, y, rustbox::RB_NORMAL, Color::Green, Color::Black, '╗');
    rb.print_char(x+width, y+height, rustbox::RB_NORMAL, Color::Green, Color::Black, '╝');
    for j in 1 .. width {
        rb.print_char(x+j, y, rustbox::RB_NORMAL, Color::Green, Color::Black, '═');
        rb.print_char(x+j, y+height, rustbox::RB_NORMAL, Color::Green, Color::Black, '═');
    }
    for j in 1 .. height {
        rb.print_char(x, y+j, rustbox::RB_NORMAL, Color::Green, Color::Black, '║');
        rb.print_char(x+width, y+j, rustbox::RB_NORMAL, Color::Green, Color::Black, '║');
    }
}

fn draw_dbox_below(rb: &RustBox, x: usize, y: usize, width: usize, height: usize) {
    draw_dbox(rb, x, y, width, height);
    rb.print_char(x, y, rustbox::RB_NORMAL, Color::Green, Color::Black, '╠');
    rb.print_char(x+width, y, rustbox::RB_NORMAL, Color::Green, Color::Black, '╣');
}

fn text_dbox(rb: &RustBox, t: &str, style: rustbox::Style, color: rustbox::Color,
             x: usize, y: usize, width: usize) {
    rb.print(x+1+(width - t.len())/2, y+1, style, color, Color::Black, t);
    draw_dbox(rb, x, y, width, 2);
}

fn text_dbox_below(rb: &RustBox, t: &str, style: rustbox::Style, color: rustbox::Color,
                   x: usize, y: usize, width: usize) {
    rb.print(x+1+(width - t.len())/2, y+1, style, color, Color::Black, t);
    draw_dbox_below(rb, x, y, width, 2);
}

fn text_box(rb: &RustBox, t: &str, x: usize, y: usize, width: usize) {
    rb.print(x+1+(width - t.len())/2, y+1, rustbox::RB_BOLD, Color::White, Color::Black, t);
    draw_box(rb, x, y, width, 2);
}

fn text_box_below(rb: &RustBox, t: &str, x: usize, y: usize, width: usize) {
    rb.print(x+1+(width - t.len())/2, y+1, rustbox::RB_BOLD, Color::White, Color::Black, t);
    draw_box_below(rb, x, y, width, 2);
}

fn text_boxes(rb: &RustBox, names: &[&String], x: usize, y: usize, width: usize) {
    if names.len() > 0 {
        text_box(rb, names[0], x, y, width);
        for i in 1 .. names.len() {
            text_box_below(rb, names[i], x, y+2*i, width);
        }
    }
}
