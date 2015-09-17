use std;
use dht::{MyBytes};

pub struct Str255 {
    pub length: u8,
    pub content: [u8; 255],
}
impl MyBytes<[u8; 256]> for Str255 {
    fn bytes(&self, out: &mut[u8; 256]) {
        let (l, c) = mut_array_refs![out,1,255];
        l[0] = self.length;
        *c = self.content;
    }
    fn from_bytes(inp: &[u8; 256]) -> Str255 {
        let (l, c) = array_refs![inp,1,255];
        Str255 {
            length: l[0],
            content: *c,
        }
    }
}

impl<'a> std::convert::From<&'a str> for Str255 {
    fn from(s: &'a str) -> Str255 {
        let b = &s.as_bytes();
        let b: &[u8] = if b.len() > 255 { &b[..255] } else { b };
        let mut bb = [0u8; 255];
        for i in 0 .. b.len() {
            bb[i] = b[i];
        }
        Str255 {
            length: b.len() as u8,
            content: bb,
        }
    }
}

impl std::ops::Deref for Str255 {
    type Target = str;
    fn deref(&self) -> &str {
        match std::str::from_utf8(&self.content[0 .. self.length as usize]) {
            Ok(s) => s,
            _ => "<invalid>"
        }
    }
}

impl std::fmt::Display for Str255 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match std::str::from_utf8(&self.content[0..self.length as usize]) {
            Ok(s) => f.write_str(&format!("'{}'", s)),
            _ => f.write_str("<invalid>")
        }
    }
}

impl std::fmt::Debug for Str255 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match std::str::from_utf8(&self.content[0..self.length as usize]) {
            Ok(s) => f.write_str(&format!("'{}'", s)),
            _ => f.write_str("<invalid>")
        }
    }
}


#[test]
fn test_from_string() {
    let s = "test".to_string();
    let s255 = Str255::from(s.as_ref());
    println!("{}", s255.length);
    assert_eq!(s255.length, 4);
}
