use std;
use onionsalt::crypto;
use serde;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Id(pub [u8; 32]);
impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        let mut s = String::new();
        s = s + &format!("{:02x}{:02x}{:02x}{:02x}", self.0[0], self.0[1], self.0[2], self.0[3]);
        s = s + &format!("{:02x}{:02x}{:02x}{:02x}", self.0[4], self.0[5], self.0[6], self.0[7]);
        s = s + &format!("{:02x}{:02x}{:02x}{:02x}", self.0[8], self.0[9], self.0[10], self.0[11]);
        s = s + &format!("{:02x}{:02x}{:02x}{:02x}", self.0[12], self.0[13], self.0[14], self.0[15]);
        s = s + &format!("{:02x}{:02x}{:02x}{:02x}", self.0[16], self.0[17], self.0[18], self.0[19]);
        s = s + &format!("{:02x}{:02x}{:02x}{:02x}", self.0[20], self.0[21], self.0[22], self.0[23]);
        s = s + &format!("{:02x}{:02x}{:02x}{:02x}", self.0[24], self.0[25], self.0[26], self.0[27]);
        s = s + &format!("{:02x}{:02x}{:02x}{:02x}", self.0[28], self.0[29], self.0[30], self.0[31]);
        f.write_str(&s)
    }
}
impl Id {
    pub fn random() -> Self {
        Id(crypto::random_32())
    }
}
impl serde::de::Deserialize for Id {
    fn deserialize<D>(deserializer: &mut D) -> Result<Self, D::Error> where D: serde::Deserializer {
        use serde::de::Deserialize;
        match crypto::PublicKey::deserialize(deserializer) {
            Err(e) => Err(e),
            Ok(pk) => Ok(Id(pk.0)),
        }
    }
}
impl serde::ser::Serialize for Id {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error> where S: serde::Serializer {
        use serde::ser::Serialize;
        crypto::PublicKey(self.0).serialize(serializer)
    }
}

#[cfg(test)]
mod test {
    use serde_json;
    use onionsalt::crypto;
    use tempfile;
    use std;
    use std::io::Seek;

    #[test]
    fn serialize() {
        let x = super::Id(crypto::box_keypair().public.0);

        let mut f = tempfile::tempfile().unwrap();
        serde_json::to_writer(&mut f, &x).unwrap();

        f.seek(std::io::SeekFrom::Start(0)).unwrap();
        let kk: super::Id = serde_json::from_reader(&mut f).unwrap();
        println!("found {}", kk);
        assert_eq!(kk, x);
    }
}
