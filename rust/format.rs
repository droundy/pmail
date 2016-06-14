extern crate serde;
extern crate serde_json;
extern crate time;

use std;
use udp;

#[derive(Debug,Copy,Clone,Hash,PartialEq,Eq,PartialOrd,Ord)]
pub struct DateRfc3339(u32);

pub fn epoch_to_rfc3339(t: u32) -> DateRfc3339 {
    DateRfc3339(t)
}
pub fn rfc3339_to_epoch(t: DateRfc3339) -> u32 {
    t.0
}
impl DateRfc3339 {
    pub fn now() -> DateRfc3339 {
        DateRfc3339(udp::epoch_time())
    }
}
impl std::ops::Sub for DateRfc3339 {
    type Output = time::Duration;
    fn sub(self, other: DateRfc3339) -> time::Duration {
        time::Duration::seconds((self.0 - other.0) as i64)
    }
}

impl std::fmt::Display for DateRfc3339 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        let mut when = udp::EPOCH;
        when.sec += self.0 as i64;
        f.write_str(&format!("{}", time::at_utc(when).rfc3339()))
    }
}
impl serde::de::Deserialize for DateRfc3339 {
    fn deserialize<D>(deserializer: &mut D) -> Result<Self, D::Error>
        where D: serde::de::Deserializer {
            use serde::de::{Deserialize,Error};
            match String::deserialize(deserializer) {
                Err(e) => Err(e),
                Ok(ref bb) => {
                    match time::strptime(bb, "%Y-%m-%dT%H:%M:%SZ") {
                        Ok(t) => {
                            let epochtime: time::Duration = t - time::at_utc(udp::EPOCH);
                            Ok(DateRfc3339(epochtime.num_seconds() as u32))
                        },
                        Err(e) => Err(D::Error::syntax(&format!("error parsing time: {}", e))),
                    }
                },
            }
        }
}
impl serde::ser::Serialize for DateRfc3339 {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error> where S: serde::Serializer {
        serializer.visit_str(&format!("{}", self))
    }
}

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
            time: super::epoch_to_rfc3339(137),
        };

        let mut f = tempfile::tempfile().unwrap();
        serde_json::to_writer(&mut f, &x).unwrap();

        f.seek(std::io::SeekFrom::Start(0)).unwrap();
        let kk: super::Message = serde_json::from_reader(&mut f).unwrap();
        println!("found {:?}", kk);
        assert_eq!(kk, x);
    }
}
