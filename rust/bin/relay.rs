extern crate pmail;
extern crate onionsalt;

use pmail::dht;

fn main() {
    println!("Getting started!");
    let (_, _, _send, receive) = dht::start_static_node().unwrap();
    for r in receive.iter() {
        println!("received {:?}", r);
    }
    println!("All done!");
}
