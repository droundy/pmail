#[macro_use]
extern crate log;

extern crate pmail;
extern crate onionsalt;
extern crate env_logger;

use pmail::dht;

fn main() {
    {
        use env_logger::init;
        init().unwrap();
    }
    info!("Getting started!");
    let (_, _, _send, receive) = dht::start_static_node().unwrap();
    for r in receive.iter() {
        info!("received {:?}", r);
    }
    info!("All done!");
}
