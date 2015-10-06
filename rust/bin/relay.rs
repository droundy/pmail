#[macro_use]
extern crate arrayref;

#[macro_use]
extern crate log;
extern crate time;

extern crate pmail;
extern crate onionsalt;
extern crate env_logger;
extern crate smtp;

use pmail::pmail::{AddressBook, Message};
use pmail::dht;

use smtp::sender::{SenderBuilder};
use smtp::email::SimpleSendableEmail;

fn main() {
    {
        use env_logger::init;
        init().unwrap();
    }

    let mut addressbook = AddressBook::read(&pmail::pmail::relay_dir().unwrap()).unwrap();

    loop {
        std::thread::sleep_ms(1000*10); // sleep a while before doing a pickup...
        if let Some((p,msg_id,m)) = addressbook.listen() {
            info!("I got personal message {:?} with id {}!", m, msg_id);
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
                Message::Acknowledge { msg_id } => {
                    info!("Acknowledgement of message {}", dht::codename(&msg_id.0));
                },
                Message::Comment { contents, message_length, message_start, .. } => {
                    info!("Got comment from {}", p);
                    info!("    {}", &std::str::from_utf8(&contents[0 .. message_length as usize]).unwrap());
                    if message_start == 0 && message_length as usize <= contents.len() {
                        let s = String::from_utf8_lossy(&contents[0..message_length as usize]).to_string();
                        info!("Nice comment! {}", s);

                        let mut sender = SenderBuilder::localhost().unwrap().build();
                        let result = sender.send(SimpleSendableEmail::new(
                            "daveroundy@gmail.com", &s,
                            &format!("Hello world {}!", msg_id)));
                        if result.is_err() {
                            info!("Trouble sending: {:?}", result);
                        }

                        let ack = Message::Acknowledge {
                            msg_id: msg_id,
                        };
                        info!("Sending acknowledgement to {}!", dht::codename(&p.0));
                        addressbook.send(&p, &ack);
                    }
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
