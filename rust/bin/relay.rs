extern crate pmail;
extern crate onionsalt;

use onionsalt::crypto;
use pmail::dht;

fn main() {
    println!("Hello world");
    dht::start();
}
