/// A basic tool to convert IPFire Location dumps into the CSV formats that Tor
/// expects.
mod db;

use argh::FromArgs;
use ipnetwork::IpNetwork;
use rangemap::RangeInclusiveMap;

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU32;
use std::path::PathBuf;

fn default_ipv4_path() -> PathBuf {
    "./geoip".into()
}
fn default_ipv6_path() -> PathBuf {
    "./geoip6".into()
}

#[derive(FromArgs)]
/// Convert an IPFire Location dump into CSV geoip files.
struct Args {
    /// where to store the IPv4 geoip output
    #[argh(option, default = "default_ipv4_path()", short = '4')]
    output_ipv4: PathBuf,

    /// where to store the IPv6 geoip6 output
    #[argh(option, default = "default_ipv6_path()", short = '6')]
    output_ipv6: PathBuf,

    /// where to find the dump file
    #[argh(option, short = 'i')]
    input: PathBuf,

    /// whether to include AS information in our output
    #[argh(switch)]
    include_asn: bool,

    /// where to store the AS map.
    #[argh(option)]
    output_asn: Option<PathBuf>,
}

/// Represents a network block from running `location dump`.
#[derive(Debug, Clone)]
pub struct NetBlock {
    pub net: IpNetwork,
    pub cc: [u8; 2],
    pub asn: Option<NonZeroU32>,
    pub is_anon_proxy: bool,
    pub is_anycast: bool,
    pub is_satellite: bool,
}

/// Represents an AS definition from running `location dump`.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct AsBlock {
    pub asn: NonZeroU32,
    pub name: String,
}

impl PartialEq for NetBlock {
    fn eq(&self, other: &Self) -> bool {
        self.net == other.net
    }
}

/// We define network blocks as being sorted first from largest to smallest,
/// then by address.
impl Ord for NetBlock {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.net
            .prefix()
            .cmp(&other.net.prefix())
            .then_with(|| self.net.network().cmp(&other.net.network()))
    }
}

impl PartialOrd for NetBlock {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for NetBlock {}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
struct NetDefn {
    cc: [u8; 2],
    asn: Option<NonZeroU32>,
}

impl NetBlock {
    fn into_defn(self, include_asn: bool) -> NetDefn {
        if include_asn {
            NetDefn {
                cc: self.cc,
                asn: self.asn,
            }
        } else {
            NetDefn {
                cc: self.cc,
                asn: None,
            }
        }
    }
}

impl NetDefn {
    fn cc(&self) -> &str {
        std::str::from_utf8(&self.cc).unwrap()
    }
    fn asn(&self) -> u32 {
        match self.asn {
            Some(v) => v.into(),
            None => 0,
        }
    }
}

const PROLOGUE: &str = "\
# This file has been converted from the IPFire Location database
# using Tor's geoip-db-tool.  For more information on the data, see
# https://location.ipfire.org/.
#
# Below is the header from the original export:
#
";

/// Read an input file in the `location dump` format, and write CSV ipv4 and ipv6 files.
///
/// This code tries to be "efficient enough"; most of the logic is handled by
/// using the rangemap crate.
fn convert(args: Args) -> std::io::Result<()> {
    let input = args.input.as_path();
    let output_v4 = args.output_ipv4.as_path();
    let output_v6 = args.output_ipv6.as_path();
    let include_asn = args.include_asn;

    let f = File::open(input)?;
    let f = BufReader::new(f);
    let mut blocks = Vec::new();
    let mut networks = Vec::new();

    let mut reader = db::BlockReader::new(f.lines());
    let hdr = reader.extract_header();
    // Read blocks, and then sort them by specificity and address.
    for nb in reader {
        match nb {
            db::AnyBlock::AsBlock(a) => networks.push(a),
            db::AnyBlock::NetBlock(n) => blocks.push(n),
            _ => {}
        }
    }
    blocks.sort();

    // Convert the sorted blocks into a map from address ranges into
    // country codes.
    //
    // Note that since we have sorted the blocks from least to most specific,
    // we will be puttting them into the maps in the right order, so that the
    // most specific rule "wins".
    //
    // We use u32 and u128 as the index types for these RangeInclusiveMaps,
    // so that we don't need to implement a step function for IpAddr.
    let mut v4map: RangeInclusiveMap<u32, NetDefn, _> = RangeInclusiveMap::new();
    let mut v6map: RangeInclusiveMap<u128, NetDefn, _> = RangeInclusiveMap::new();

    let mut n = 0usize;
    let num_blocks = blocks.len();
    for nb in blocks {
        n += 1;
        if n % 100000 == 0 {
            println!("{}/{}", n, num_blocks);
        }
        let start = nb.net.network();
        let end = nb.net.broadcast();
        match (start, end) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                v4map.insert(a.into()..=b.into(), nb.into_defn(include_asn));
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                v6map.insert(a.into()..=b.into(), nb.into_defn(include_asn));
            }
            (_, _) => panic!("network started and ended in different families!?"),
        }
    }

    // Write the ranges out to the appropriate files, in order.
    let mut v4 = BufWriter::new(File::create(output_v4)?);
    let mut v6 = BufWriter::new(File::create(output_v6)?);

    v4.write_all(PROLOGUE.as_bytes())?;
    v4.write_all(hdr.as_bytes())?;
    for (r, defn) in v4map.iter() {
        let a: u32 = *r.start();
        let b: u32 = *r.end();
        if include_asn {
            writeln!(&mut v4, "{},{},{},{}", a, b, defn.cc(), defn.asn())?;
        } else {
            writeln!(&mut v4, "{},{},{}", a, b, defn.cc())?;
        }
    }

    v6.write_all(PROLOGUE.as_bytes())?;
    v6.write_all(hdr.as_bytes())?;
    for (r, defn) in v6map.iter() {
        let a: Ipv6Addr = (*r.start()).into();
        let b: Ipv6Addr = (*r.end()).into();
        if include_asn {
            writeln!(&mut v6, "{},{},{},{}", a, b, defn.cc(), defn.asn())?;
        } else {
            writeln!(&mut v6, "{},{},{}", a, b, defn.cc())?;
        }
    }

    // The documentation says you should always flush a BufWriter.
    v4.flush()?;
    v6.flush()?;

    if let Some(output_asn) = args.output_asn {
        networks.sort();
        let mut asn = BufWriter::new(File::create(output_asn)?);
        for net in networks {
            writeln!(&mut asn, "{},{}", net.asn, net.name)?;
        }
        asn.flush()?;
    }

    Ok(())
}

fn main() -> std::io::Result<()> {
    let args: Args = argh::from_env();

    convert(args)
}
