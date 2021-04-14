/// Code to parse a dump file
use std::collections::HashMap;
use std::convert::TryInto;
use std::iter::Peekable;

use super::{AsBlock, NetBlock};

pub struct BlockReader<I>
where
    I: Iterator<Item = std::io::Result<String>>,
{
    iter: Peekable<I>,
}

pub enum AnyBlock {
    NetBlock(NetBlock),
    AsBlock(AsBlock),
    OtherBlock,
}

impl<I> BlockReader<I>
where
    I: Iterator<Item = std::io::Result<String>>,
{
    pub fn new(iter: I) -> Self {
        BlockReader {
            iter: iter.peekable(),
        }
    }

    /// Extract the initial header from the file.
    pub fn extract_header(&mut self) -> String {
        let mut res: String = "".to_string();

        while let Some(Ok(line)) = self.iter.peek() {
            if !line.starts_with('#') {
                break;
            }
            res.push_str(line.as_str());
            res.push('\n');
            let _ = self.iter.next();
        }

        res
    }

    /// Extract the next empty-line-delimited block from the file.
    ///
    /// This isn't terribly efficient, but it's "fast enough".
    fn get_block(&mut self) -> Option<std::io::Result<AnyBlock>> {
        let mut kv = HashMap::new();

        while let Some(line) = self.iter.next() {
            //dbg!(&line);
            if let Err(e) = line {
                return Some(Err(e));
            }
            let line_orig = line.unwrap();
            let line = line_orig.splitn(2, '#').next().unwrap().trim();
            if line.is_empty() {
                if kv.is_empty() {
                    continue;
                } else {
                    break;
                }
            }
            let kwds: Vec<_> = line.splitn(2, ':').collect();
            if kwds.len() != 2 {
                return None; // XXXX handle the error better.
            }
            kv.insert(kwds[0].trim().to_string(), kwds[1].trim().to_string());
        }

        if kv.is_empty() {
            return None;
        }

        if let Some(name) = kv.remove("name") {
            // This is an AS block.
            let asn = kv.get("aut-num").unwrap(); // XXXX handle error better
            assert!(asn.starts_with("AS"));
            let asn = asn[2..].parse().unwrap();
            return Some(Ok(AnyBlock::AsBlock(AsBlock { name, asn })));
        }

        let net = if let Some(net) = kv.get("net") {
            net.parse().unwrap() //XXXX handle the error better.
        } else {
            return Some(Ok(AnyBlock::OtherBlock));
        };

        let asn = if let Some(asn) = kv.get("aut-num") {
            asn.parse().ok()
        } else {
            None
        };

        let cc = if let Some(country) = kv.get("country") {
            assert!(country.as_bytes().len() == 2);
            country.as_bytes()[0..2].try_into().unwrap()
        } else {
            *b"??"
        };

        fn is_true(v: Option<&String>) -> bool {
            match v {
                Some(s) => s == "true",
                None => false,
            }
        }

        let is_anon_proxy = is_true(kv.get("is-anonymous-proxy"));
        let is_anycast = is_true(kv.get("is-anycast-proxy"));
        let is_satellite = is_true(kv.get("is-satellite-provider"));

        Some(Ok(AnyBlock::NetBlock(NetBlock {
            net,
            asn,
            cc,
            is_anon_proxy,
            is_anycast,
            is_satellite,
        })))
    }
}

impl<I> Iterator for BlockReader<I>
where
    I: Iterator<Item = std::io::Result<String>>,
{
    type Item = AnyBlock;
    fn next(&mut self) -> Option<Self::Item> {
        match self.get_block() {
            Some(Ok(b)) => Some(b),
            _ => None,
        }
    }
}
