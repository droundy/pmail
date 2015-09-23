extern crate serde;
extern crate serde_json;

include!(concat!(env!("OUT_DIR"), "/format.rs"));

#[cfg(test)]
mod test {
    use serde_json;
    use pmail;
    use message;
    use onionsalt::crypto;
    use tempfile;
    use std;
    use std::io::Seek;

    #[test]
    fn serialize() {
        let x = super::Message {
            thread: pmail::Thread(5),
            id: message::Id::random(),
            from: crypto::box_keypair().public,
            contents: "This is a nice test".to_string(),
        };

        let mut f = tempfile::TempFile::new().unwrap();
        serde_json::to_writer(&mut f, &x).unwrap();

        f.seek(std::io::SeekFrom::Start(0)).unwrap();
        let kk: super::Message = serde_json::from_reader(&mut f).unwrap();
        println!("found {:?}", kk);
        assert_eq!(kk, x);
    }
}
