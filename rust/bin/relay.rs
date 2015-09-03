extern crate pmail;
extern crate onionsalt;

use pmail::dht;

fn main() {
    dht::start_static_node().unwrap();
}
