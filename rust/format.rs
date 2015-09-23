extern crate serde;
extern crate serde_json;

include!(concat!(env!("OUT_DIR"), "/format.rs"));

#[cfg(test)]
mod test {
    use std::fs;
    use serde_json;
    use pmail;
    use message;
    use onionsalt::crypto;

    #[test]
    fn serialize() {
        let name = ".test-message";
        let x = super::Message {
            thread: pmail::Thread(5),
            id: message::Id::random(),
            from: crypto::box_keypair().public,
        };

        {
            let mut f = fs::File::create(name).unwrap();
            serde_json::to_writer(&mut f, &x).unwrap();
        }
        {
            let mut f = fs::File::open(name).unwrap();
            let kk: super::Message = serde_json::from_reader(&mut f).unwrap();
            println!("found {:?}", kk);
            assert_eq!(kk, x);
        }
    }
}
