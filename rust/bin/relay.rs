#[macro_use]
extern crate arrayref;

#[macro_use]
extern crate log;
extern crate time;
extern crate serde_json;

extern crate tiny_http;
extern crate pmail;
extern crate onionsalt;
extern crate env_logger;
extern crate smtp;
extern crate rustc_serialize;

use rustc_serialize::base64::{ToBase64, FromBase64, URL_SAFE};
use tiny_http::{ServerBuilder, Response};
use serde_json::{ser,de};

use pmail::pmail::{AddressBook, Message};
use pmail::dht;

use smtp::sender::{SenderBuilder};
use smtp::email::SimpleSendableEmail;
use onionsalt::crypto;

fn main() {
    {
        use env_logger::init;
        init().unwrap();
    }

    let mut addressbook = AddressBook::read(&pmail::pmail::relay_dir().unwrap()).unwrap();

    let response_keys = crypto::box_keypair();
    std::thread::spawn(|| {
        let server = ServerBuilder::new().with_port(8000).build().unwrap();

        for request in server.incoming_requests() {
            match *request.method() {
                tiny_http::Method::Get => {
                    println!("received request! method: {:?}, url: {:?}",
                             request.method(), request.url());
                    if let Ok(vvv) = request.url().as_bytes()[1..].from_base64() {
                        let rrr: Result<crypto::PublicKey,_> = de::from_slice(&vvv);
                        if let Ok(v) = rrr {
                            println!("public key: {}", v);
                        }
                    }

                    let response = Response::from_string("hello world");
                    request.respond(response);
                },
                _ => { info!("Got weird post or something..."); }, // ignore anything else...
            }
        }
    });

    loop {
        std::thread::sleep_ms(1000*30); // sleep a while before doing a pickup...
        addressbook.pickup();
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
                            &format!("Hello world {} http://knightley.physics.oregonstate.edu:8000/{}!",
                                     msg_id, ser::to_vec(&response_keys.public).unwrap().to_base64(URL_SAFE))));
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
