#[macro_use]
extern crate arrayref;

#[macro_use]
extern crate log;
extern crate time;

extern crate tiny_http;
extern crate pmail;
extern crate onionsalt;
extern crate env_logger;
extern crate smtp;
extern crate rustc_serialize;

use rustc_serialize::base64::{ToBase64, FromBase64, URL_SAFE};
use tiny_http::{ServerBuilder, Response};

use pmail::pmail::{AddressBook, Message};
use pmail::dht;

use smtp::sender::{SenderBuilder};
use smtp::email::SimpleSendableEmail;
use onionsalt::crypto;

use std::sync::{Arc,Mutex};

fn main() {
    {
        use env_logger::init;
        init().unwrap();
    }

    let addressbook = Arc::new(Mutex::new(AddressBook::read(&pmail::pmail::relay_dir().unwrap()).unwrap()));

    let response_keys = crypto::box_keypair();
    let secret_key_for_http = response_keys.public.0;

    let ab = addressbook.clone();
    std::thread::spawn(move|| {
        let server = ServerBuilder::new().with_port(8000).build().unwrap();
        for request in server.incoming_requests() {
            match *request.method() {
                tiny_http::Method::Get => {
                    println!("received request! method: {:?}, url: {:?}",
                             request.method(), request.url());
                    if let Ok(vvv) = request.url().as_bytes()[1..].from_base64() {
                        let n = crypto::Nonce(*array_ref![vvv, 0, 24]);
                        let mut decrypted = vec![0; vvv.len() - 8];
                        if crypto::secretbox_open(&mut decrypted, &vvv[8..], &n, &secret_key_for_http).is_ok() {
                            let id = String::from_utf8_lossy(&decrypted[64..]).to_string();
                            let k = crypto::PublicKey(*array_ref![decrypted,32,32]);
                            println!("confirmed identity: {} with key {}", id, k);
                            ab.lock().unwrap().assert_public_id(&id, &k);
                            ab.lock().unwrap().write().unwrap();
                            println!("we now know: {:?}", ab.lock().unwrap().list_public_keys());
                        } else {
                            println!("decryption failed!  :(");
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
        let mut addressbook = addressbook.lock().unwrap();
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
                    let message_length = message_length as usize;
                    info!("    {}", &std::str::from_utf8(&contents[0 .. message_length]).unwrap());
                    if message_start == 0 && message_length <= contents.len() {
                        let s = String::from_utf8_lossy(&contents[0..message_length]).to_string();
                        info!("Nice comment! {}", s);

                        let mut sender = SenderBuilder::localhost().unwrap().build();
                        let mut raw_cookie = vec![0; 32 + 32 + message_length];
                        for i in 0 .. message_length {
                            raw_cookie[32+32+i] = contents[i];
                        }
                        *array_mut_ref![raw_cookie,32,32] = p.0;
                        let mut cookie = vec![0; 40 + 32 + message_length];
                        let n = crypto::random_nonce();
                        crypto::secretbox(&mut cookie[8..], &raw_cookie, &n, &response_keys.public.0);
                        *array_mut_ref![cookie, 0, 24] = n.0;
                        let cookie = cookie.to_base64(URL_SAFE);
                        let result = sender.send(SimpleSendableEmail::new(
                            "daveroundy@gmail.com", &s,
                            &format!("If you registered as {}, click on the following link:\n\n http://knightley.physics.oregonstate.edu:8000/{}",
                                     s, cookie)));
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
