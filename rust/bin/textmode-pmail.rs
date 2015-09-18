#[macro_use]
extern crate arrayref;

#[macro_use]
extern crate log;
extern crate time;

extern crate pmail;
extern crate onionsalt;
extern crate rustbox;

use std::sync::mpsc::{ Receiver, Sender, channel, };
use std::sync::{ Mutex };

use rustbox::{Color, RustBox};
use rustbox::Key;

use pmail::pmail::{AddressBook, Message};
use pmail::str255::{Str255};
use pmail::dht;

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
    text_box_below(rb, query, rustbox::RB_NORMAL, Color::White, offset, bottom, right-offset-1);
}
fn show_messages(rb: &RustBox, msgs: &Vec<String>, composing: &str, offset: usize) {
    let right = rb.width();
    let bottom = rb.height() - 3;
    if msgs.len() > bottom - 1 {
        let start = msgs.len() - (bottom - 1);
        for i in 0 .. bottom-1 {
            rb.print(offset+1, 1 + i,
                     rustbox::RB_NORMAL, Color::White, Color::Black, &msgs[start+i]);
        }
    } else {
        for i in 0 .. msgs.len() {
            rb.print(offset+1, 1 + i,
                     rustbox::RB_NORMAL, Color::White, Color::Black, &msgs[i]);
        }
    }
    draw_box(rb, offset, 0, right-offset-1, bottom);
    text_box_below(rb, composing, rustbox::RB_NORMAL, Color::White, offset, bottom, right-offset-1);
}
fn which_user_selected(ab: &AddressBook, selected: usize) -> String {
    let names = ab.list_public_keys();
    let secret_names = ab.list_secret_keys();
    if selected < names.len() {
        return names[selected].clone();
    }
    if selected < names.len() + secret_names.len() {
        return secret_names[selected - names.len()].clone();
    }
    secret_names[secret_names.len()-1].clone()
}
fn show_addressbook(rb: &RustBox, ab: &AddressBook, us: UserState, selected: usize) -> usize {
    rb.clear();
    let names = ab.list_public_keys();
    let secret_names = ab.list_secret_keys();
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
    text_boxes(rb, &names, rustbox::RB_BOLD, Color::White, 0, 9, width);
    if selected < names.len() {
        rb.print_char(1, 10 + 2*selected, rustbox::RB_BOLD, Color::Red, Color::Black, '⇒');
        rb.print_char(width-1, 10 + 2*selected, rustbox::RB_BOLD, Color::Red, Color::Black, '⇐');
    }
    text_boxes(rb, &secret_names, rustbox::RB_NORMAL, Color::White, 0, 10+names.len()*2, width);
    if selected >= names.len() && selected < names.len() + secret_names.len() {
        rb.print_char(1, 11 + 2*selected, rustbox::RB_BOLD, Color::Red, Color::Black, '⇒');
        rb.print_char(width-1, 11 + 2*selected, rustbox::RB_BOLD, Color::Red, Color::Black, '⇐');
    }
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
    let mut nice_comments = Vec::new(); // for now, just store messages here

    let mut addressbook = AddressBook::read().unwrap();

    let rustbox = match RustBox::init(Default::default()) {
        Result::Ok(v) => v,
        Result::Err(e) => {
            panic!("Unable to initialize rustbox: {}", e)
        },
    };

    let mut us = UserState::Logs;
    let mut finduser_query = String::new();
    let mut message_tosend = String::new();
    let mut dummy = String::new();
    let mut selected_user = 0;
    let mut count_to_pickup = 0;
    loop {
        match us {
            UserState::Logs => {
                let width = show_addressbook(&rustbox, &addressbook, us, selected_user);
                show_logs(&rustbox, &mut logdata, width+1);
            },
            UserState::Messages => {
                let width = show_addressbook(&rustbox, &addressbook, us, selected_user);
                show_messages(&rustbox, &nice_comments, &message_tosend, width+1);
            },
            UserState::FindUser => {
                let width = show_addressbook(&rustbox, &addressbook, us, selected_user);
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
                    Some(Key::Enter) => {
                        match us {
                            UserState::Logs => { info!("Noop"); }
                            UserState::FindUser => {
                                if editing.len() == 0 { continue; }
                                let e = which_user_selected(&addressbook, selected_user);
                                info!("Finduser \"{}\" from \"{}\"", editing, e);
                                let m = Message::UserQuery {
                                    user: Str255::from(editing.as_ref()),
                                };
                                if let Some(k) = addressbook.lookup(&e) {
                                    addressbook.send(&k, &m);
                                }
                            }
                            UserState::Messages => {
                                if editing.len() == 0 { continue; }
                                let mess: Str255 = Str255::from(editing.as_ref());
                                let name = which_user_selected(&addressbook, selected_user);
                                info!("Message \"{}\" to \"{}\"", editing, name);
                                let mut c = [0u8; 394];
                                for i in 0 .. mess.length as usize {
                                    c[i] = mess.content[i];
                                }
                                let m = Message::Comment {
                                    thread: 0,
                                    time: 0,
                                    message_length: editing.len() as u32,
                                    message_start: 0,
                                    contents: c,
                                };
                                if let Some(k) = addressbook.lookup(&name) {
                                    addressbook.send(&k, &m);
                                }
                                nice_comments.push(format!("me: {}", editing));
                            }
                        }
                        *editing = String::new();
                    }
                    Some(Key::End) => {
                        match us {
                            UserState::Logs => { }
                            UserState::FindUser => {
                                if editing.len() == 0 { continue; }
                                let e = which_user_selected(&addressbook, selected_user);
                                info!("Equating \"{}\" with \"{}\"", editing, e);
                                addressbook.assert_public_equivalence(&e, editing);
                            }
                            UserState::Messages => { }
                        }
                        *editing = String::new();
                    }
                    Some(Key::Backspace) => { editing.pop(); }
                    Some(Key::Up) => { selected_user = if selected_user == 0 {0} else {selected_user-1}; }
                    Some(Key::Down) => { selected_user += 1; }
                    _ => { }
                }
            },
            Err(e) => panic!("{}", e),
            _ => { }
        }
        count_to_pickup += 1;
        if count_to_pickup == 120 { // this is very hokey...
            addressbook.pickup();
            count_to_pickup = 0;
        }
        if let Some((p,msg_id,m)) = addressbook.listen() {
            info!("I got personal message {:?}!", m);
            match m {
                Message::UserQuery{ user } => {
                    info!("A query about {}", user);
                    if let Some(userk) = addressbook.lookup_public(&user) {
                        info!("Responding with user {} == {}",
                              user, userk);
                        let m = Message::UserResponse {
                            user: user,
                            key: userk,
                        };
                        addressbook.send(&p, &m);
                    } else {
                        info!("User {} not known", user);
                    }
                },
                Message::UserResponse{ user, key } => {
                    info!("A user response about {}", user);
                    addressbook.assert_secret_id(&user, &key);
                },
                Message::Comment { contents, message_length, .. } => {
                    info!("Got comment from {}", p);
                    info!("    {}", &std::str::from_utf8(&contents[0 .. message_length as usize]).unwrap());
                    match addressbook.reverse_lookup(&p) {
                        Some(user) => {
                            nice_comments.push(format!("{}: {}",
                                                       user, &std::str::from_utf8(&contents).unwrap()));
                        }
                        None => {
                            nice_comments.push(format!("{}: {}",
                                                       dht::codename(&p.0),
                                                       &std::str::from_utf8(&contents).unwrap()));
                        }
                    }
                    let ack = Message::Acknowledge {
                        msg_id: msg_id,
                    };
                    info!("Sending acknowledgement to {}!", dht::codename(&p.0));
                    addressbook.send(&p, &ack);
                },
                Message::Acknowledge { msg_id } => {
                    info!("Acknowledgement of message {}", dht::codename(&msg_id.0));
                },
                _ => {
                    println!("\r\nI got message {:?}!\r\n", m);
                    info!("I heard something fun from {}!",
                          dht::codename(&p.0));
                    println!("\r\nI heard something fun from {}! i.e. {}\r\n",
                             dht::codename(&p.0), p);
                    std::thread::sleep_ms(1000000);
                    panic!("the end");
                },
            }
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

fn text_box(rb: &RustBox, t: &str, style: rustbox::Style, color: rustbox::Color,
            x: usize, y: usize, width: usize) {
    rb.print(x+1+(width - t.len())/2, y+1, style, color, Color::Black, t);
    draw_box(rb, x, y, width, 2);
}

fn text_box_below(rb: &RustBox, t: &str, style: rustbox::Style, color: rustbox::Color,
                  x: usize, y: usize, width: usize) {
    rb.print(x+1+(width - t.len())/2, y+1, style, color, Color::Black, t);
    draw_box_below(rb, x, y, width, 2);
}

fn text_boxes(rb: &RustBox, names: &[&String], style: rustbox::Style, color: rustbox::Color,
              x: usize, y: usize, width: usize) {
    if names.len() > 0 {
        text_box(rb, names[0], style, color, x, y, width);
        for i in 1 .. names.len() {
            text_box_below(rb, names[i], style, color, x, y+2*i, width);
        }
    }
}
