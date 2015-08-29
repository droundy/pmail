extern crate pmail;
extern crate onionsalt;

use pmail::dht;

fn main() {
    println!("Hello world");
    dht::start_static_node().unwrap();
}
