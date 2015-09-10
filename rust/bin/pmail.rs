extern crate pmail;
extern crate onionsalt;

use pmail::dht;

fn main() {
    let my_personal_key = {
        let mut name = match std::env::home_dir() {
            Some(hd) => hd,
            None => std::path::PathBuf::from("."),
        };
        name.push(".pmail-personal.key");
        dht::read_or_generate_keypair(name).unwrap()
    };

    println!("Pmail starting! {:?}", my_personal_key.public);
    let (ask_rendevous, hear_rendevous, _send, receive) = dht::start_static_node().unwrap();
    for r in receive.iter() {
        println!("received {:?}", r);

        ask_rendevous.send(my_personal_key.public).unwrap();
        let rendevous_point = hear_rendevous.recv().unwrap();
        println!("Rendezvous point {:?}", rendevous_point);
    }
    println!("All done!");
}
