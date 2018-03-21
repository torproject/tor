// Copyright (c) 2016-2017, The Tor Project, Inc. */
// See LICENSE for licensing information */

use external::c_tor_version_as_new_as;

use std::str;
use std::str::FromStr;
use std::fmt;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::string::String;
use std::u32;

use tor_util::strings::NUL_BYTE;

use errors::ProtoverError;
use protoset::Version;

/// The first version of Tor that included "proto" entries in its descriptors.
/// Authorities should use this to decide whether to guess proto lines.
///
/// C_RUST_COUPLED:
///     src/or/protover.h `FIRST_TOR_VERSION_TO_ADVERTISE_PROTOCOLS`
const FIRST_TOR_VERSION_TO_ADVERTISE_PROTOCOLS: &'static str = "0.2.9.3-alpha";

/// The maximum number of subprotocol version numbers we will attempt to expand
/// before concluding that someone is trying to DoS us
///
/// C_RUST_COUPLED: src/or/protover.c `MAX_PROTOCOLS_TO_EXPAND`
pub(crate) const MAX_PROTOCOLS_TO_EXPAND: usize = (1<<16);

/// Currently supported protocols and their versions, as a byte-slice.
///
/// # Warning
///
/// This byte-slice ends in a NUL byte.  This is so that we can directly convert
/// it to an `&'static CStr` in the FFI code, in order to hand the static string
/// to C in a way that is compatible with C static strings.
///
/// Rust code which wishes to accesses this string should use
/// `protover::get_supported_protocols()` instead.
///
/// C_RUST_COUPLED: src/or/protover.c `protover_get_supported_protocols`
pub(crate) const SUPPORTED_PROTOCOLS: &'static [u8] =
    b"Cons=1-2 \
    Desc=1-2 \
    DirCache=1-2 \
    HSDir=1-2 \
    HSIntro=3-4 \
    HSRend=1-2 \
    Link=1-5 \
    LinkAuth=1,3 \
    Microdesc=1-2 \
    Relay=1-2\0";

/// Known subprotocols in Tor. Indicates which subprotocol a relay supports.
///
/// C_RUST_COUPLED: src/or/protover.h `protocol_type_t`
#[derive(Hash, Eq, PartialEq, Debug)]
pub enum Proto {
    Cons,
    Desc,
    DirCache,
    HSDir,
    HSIntro,
    HSRend,
    Link,
    LinkAuth,
    Microdesc,
    Relay,
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Translates a string representation of a protocol into a Proto type.
/// Error if the string is an unrecognized protocol name.
///
/// C_RUST_COUPLED: src/or/protover.c `PROTOCOL_NAMES`
impl FromStr for Proto {
    type Err = ProtoverError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Cons" => Ok(Proto::Cons),
            "Desc" => Ok(Proto::Desc),
            "DirCache" => Ok(Proto::DirCache),
            "HSDir" => Ok(Proto::HSDir),
            "HSIntro" => Ok(Proto::HSIntro),
            "HSRend" => Ok(Proto::HSRend),
            "Link" => Ok(Proto::Link),
            "LinkAuth" => Ok(Proto::LinkAuth),
            "Microdesc" => Ok(Proto::Microdesc),
            "Relay" => Ok(Proto::Relay),
            _ => Err(ProtoverError::UnknownProtocol),
        }
    }
}

/// Get the string representation of current supported protocols
///
/// # Returns
///
/// A `String` whose value is the existing protocols supported by tor.
/// Returned data is in the format as follows:
///
/// "HSDir=1-1 LinkAuth=1"
///
pub fn get_supported_protocols() -> &'static str {
    // The `len() - 1` is to remove the NUL byte.
    // The `unwrap` is safe becauase we SUPPORTED_PROTOCOLS is under
    // our control.
    str::from_utf8(&SUPPORTED_PROTOCOLS[..SUPPORTED_PROTOCOLS.len() - 1])
        .unwrap_or("")
}

pub struct SupportedProtocols(HashMap<Proto, Versions>);

impl SupportedProtocols {
    pub fn from_proto_entries<I, S>(protocol_strs: I) -> Result<Self, &'static str>
    where
        I: Iterator<Item = S>,
        S: AsRef<str>,
    {
        let mut parsed = HashMap::new();
        for subproto in protocol_strs {
            let (name, version) = get_proto_and_vers(subproto.as_ref())?;
            parsed.insert(name, version);
        }
        Ok(SupportedProtocols(parsed))
    }

    /// Translates a string representation of a protocol list to a
    /// SupportedProtocols instance.
    ///
    /// # Examples
    ///
    /// ```
    /// use protover::SupportedProtocols;
    ///
    /// let supported_protocols = SupportedProtocols::from_proto_entries_string(
    ///     "HSDir=1-2 HSIntro=3-4"
    /// );
    /// ```
    pub fn from_proto_entries_string(
        proto_entries: &str,
    ) -> Result<Self, &'static str> {
        Self::from_proto_entries(proto_entries.split(" "))
    }

    /// Translate the supported tor versions from a string into a
    /// HashMap, which is useful when looking up a specific
    /// subprotocol.
    ///
    fn tor_supported() -> Result<Self, &'static str> {
        Self::from_proto_entries_string(get_supported_protocols())
    }
}

/// Parse the subprotocol type and its version numbers.
///
/// # Inputs
///
/// * A `protocol_entry` string, comprised of a keyword, an "=" sign, and one
/// or more version numbers.
///
/// # Returns
///
/// A `Result` whose `Ok` value is a tuple of `(Proto, HashSet<u32>)`, where the
/// first element is the subprotocol type (see `protover::Proto`) and the last
/// element is a(n unordered) set of unique version numbers which are supported.
/// Otherwise, the `Err` value of this `Result` is a description of the error
///
fn get_proto_and_vers<'a>(
    protocol_entry: &'a str,
) -> Result<(Proto, Versions), &'static str> {
    let mut parts = protocol_entry.splitn(2, "=");

    let proto = match parts.next() {
        Some(n) => n,
        None => return Err("invalid protover entry"),
    };

    let vers = match parts.next() {
        Some(n) => n,
        None => return Err("invalid protover entry"),
    };

    let versions = Versions::from_version_string(vers)?;
    let proto_name = proto.parse()?;

    Ok((proto_name, versions))
}

/// Parses a single subprotocol entry string into subprotocol and version
/// parts, and then checks whether any of those versions are unsupported.
/// Helper for protover::all_supported
///
/// # Inputs
///
/// Accepted data is in the string format as follows:
///
/// "HSDir=1-1"
///
/// # Returns
///
/// Returns `true` if the protocol entry is well-formatted and only contains
/// versions that are also supported in tor. Otherwise, returns false
///
fn contains_only_supported_protocols(proto_entry: &str) -> bool {
    let (name, mut vers) = match get_proto_and_vers(proto_entry) {
        Ok(n) => n,
        Err(_) => return false,
    };

    let currently_supported = match SupportedProtocols::tor_supported() {
        Ok(n) => n.0,
        Err(_) => return false,
    };

    let supported_versions = match currently_supported.get(&name) {
        Some(n) => n,
        None => return false,
    };

    vers.0.retain(|x| !supported_versions.0.contains(x));
    vers.0.is_empty()
}

/// Determine if we support every protocol a client supports, and if not,
/// determine which protocols we do not have support for.
///
/// # Inputs
///
/// Accepted data is in the string format as follows:
///
/// "HSDir=1-1 LinkAuth=1-2"
///
/// # Returns
///
/// Return `true` if every protocol version is one that we support.
/// Otherwise, return `false`.
/// Optionally, return parameters which the client supports but which we do not
///
/// # Examples
/// ```
/// use protover::all_supported;
///
/// let (is_supported, unsupported)  = all_supported("Link=1");
/// assert_eq!(true, is_supported);
///
/// let (is_supported, unsupported)  = all_supported("Link=5-6");
/// assert_eq!(false, is_supported);
/// assert_eq!("Link=5-6", unsupported);
///
pub fn all_supported(protocols: &str) -> (bool, String) {
    let unsupported = protocols
        .split_whitespace()
        .filter(|v| !contains_only_supported_protocols(v))
        .collect::<Vec<&str>>();

    (unsupported.is_empty(), unsupported.join(" "))
}

/// Return true iff the provided protocol list includes support for the
/// indicated protocol and version.
/// Otherwise, return false
///
/// # Inputs
///
/// * `list`, a string representation of a list of protocol entries.
/// * `proto`, a `Proto` to test support for
/// * `vers`, a `Version` version which we will go on to determine whether the
/// specified protocol supports.
///
/// # Examples
/// ```
/// use protover::*;
///
/// let is_supported = protover_string_supports_protocol("Link=3-4 Cons=1",
///                                                      Proto::Cons,1);
/// assert_eq!(true, is_supported);
///
/// let is_not_supported = protover_string_supports_protocol("Link=3-4 Cons=1",
///                                                           Proto::Cons,5);
/// assert_eq!(false, is_not_supported)
/// ```
pub fn protover_string_supports_protocol(
    list: &str,
    proto: Proto,
    vers: Version,
) -> bool {
    let supported = match SupportedProtocols::from_proto_entries_string(list) {
        Ok(result) => result.0,
        Err(_) => return false,
    };

    let supported_versions = match supported.get(&proto) {
        Some(n) => n,
        None => return false,
    };

    supported_versions.0.contains(&vers)
}

/// As protover_string_supports_protocol(), but also returns True if
/// any later version of the protocol is supported.
///
/// # Examples
/// ```
/// use protover::*;
///
/// let is_supported = protover_string_supports_protocol_or_later(
///                       "Link=3-4 Cons=5", Proto::Cons, 5);
///
/// assert_eq!(true, is_supported);
///
/// let is_supported = protover_string_supports_protocol_or_later(
///                       "Link=3-4 Cons=5", Proto::Cons, 4);
///
/// assert_eq!(true, is_supported);
///
/// let is_supported = protover_string_supports_protocol_or_later(
///                       "Link=3-4 Cons=5", Proto::Cons, 6);
///
/// assert_eq!(false, is_supported);
/// ```
pub fn protover_string_supports_protocol_or_later(
    list: &str,
    proto: Proto,
    vers: u32,
) -> bool {
    let supported = match SupportedProtocols::from_proto_entries_string(list) {
        Ok(result) => result.0,
        Err(_) => return false,
    };

    let supported_versions = match supported.get(&proto) {
        Some(n) => n,
        None => return false,
    };

    supported_versions.0.iter().any(|v| v >= &vers)
}

/// Parses a protocol list without validating the protocol names
///
/// # Inputs
///
/// * `protocol_string`, a string comprised of keys and values, both which are
/// strings. The keys are the protocol names while values are a string
/// representation of the supported versions.
///
/// The input is _not_ expected to be a subset of the Proto types
///
/// # Returns
///
/// A `Result` whose `Ok` value is a `HashSet<Version>` holding all of the
/// unique version numbers.
///
/// The returned `Result`'s `Err` value is an `&'static str` with a description
/// of the error.
///
/// # Errors
///
/// This function will error if:
///
/// * The protocol string does not follow the "protocol_name=version_list"
/// expected format
/// * If the version string is malformed. See `Versions::from_version_string`.
///
fn parse_protocols_from_string_with_no_validation<'a>(
    protocol_string: &'a str,
) -> Result<HashMap<String, Versions>, &'static str> {
    let mut parsed: HashMap<String, Versions> = HashMap::new();

    for subproto in protocol_string.split(" ") {
        let mut parts = subproto.splitn(2, "=");

        let name = match parts.next() {
            Some("") => return Err("invalid protover entry"),
            Some(n) => n,
            None => return Err("invalid protover entry"),
        };

        let vers = match parts.next() {
            Some(n) => n,
            None => return Err("invalid protover entry"),
        };

        let versions = Versions::from_version_string(vers)?;

        parsed.insert(String::from(name), versions);
    }
    Ok(parsed)
}

/// Protocol voting implementation.
///
/// Given a list of strings describing protocol versions, return a new
/// string encoding all of the protocols that are listed by at
/// least threshold of the inputs.
///
/// The string is sorted according to the following conventions:
///   - Protocols names are alphabetized
///   - Protocols are in order low to high
///   - Individual and ranges are listed together. For example,
///     "3, 5-10,13"
///   - All entries are unique
///
/// # Examples
/// ```
/// use protover::compute_vote;
///
/// let protos = vec![String::from("Link=3-4"), String::from("Link=3")];
/// let vote = compute_vote(protos, 2);
/// assert_eq!("Link=3", vote)
/// ```
pub fn compute_vote(
    list_of_proto_strings: Vec<String>,
    threshold: i32,
) -> String {
    let empty = String::from("");

    if list_of_proto_strings.is_empty() {
        return empty;
    }

    // all_count is a structure to represent the count of the number of
    // supported versions for a specific protocol. For example, in JSON format:
    // {
    //  "FirstSupportedProtocol": {
    //      "1": "3",
    //      "2": "1"
    //  }
    // }
    // means that FirstSupportedProtocol has three votes which support version
    // 1, and one vote that supports version 2
    let mut all_count: HashMap<String, HashMap<Version, usize>> =
        HashMap::new();

    // parse and collect all of the protos and their versions and collect them
    for vote in list_of_proto_strings {
        let this_vote: HashMap<String, Versions> =
            match parse_protocols_from_string_with_no_validation(&vote) {
                Ok(result) => result,
                Err(_) => continue,
            };
        for (protocol, versions) in this_vote {
            let supported_vers: &mut HashMap<Version, usize> =
                all_count.entry(protocol).or_insert(HashMap::new());

            for version in versions.0 {
                let counter: &mut usize =
                    supported_vers.entry(version).or_insert(0);
                *counter += 1;
            }
        }
    }

    let mut final_output: HashMap<String, String> =
        HashMap::with_capacity(get_supported_protocols().split(" ").count());

    // Go through and remove verstions that are less than the threshold
    for (protocol, versions) in all_count {
        let mut meets_threshold = HashSet::new();
        for (version, count) in versions {
            if count >= threshold as usize {
                meets_threshold.insert(version);
            }
        }

        // For each protocol, compress its version list into the expected
        // protocol version string format
        let contracted = contract_protocol_list(&meets_threshold);
        if !contracted.is_empty() {
            final_output.insert(protocol, contracted);
        }
    }

    write_vote_to_string(&final_output)
}

/// Return a String comprised of protocol entries in alphabetical order
///
/// # Inputs
///
/// * `vote`, a `HashMap` comprised of keys and values, both which are strings.
/// The keys are the protocol names while values are a string representation of
/// the supported versions.
///
/// # Returns
///
/// A `String` whose value is series of pairs, comprising of the protocol name
/// and versions that it supports. The string takes the following format:
///
/// "first_protocol_name=1,2-5, second_protocol_name=4,5"
///
/// Sorts the keys in alphabetical order and creates the expected subprotocol
/// entry format.
///
fn write_vote_to_string(vote: &HashMap<String, String>) -> String {
    let mut keys: Vec<&String> = vote.keys().collect();
    keys.sort();

    let mut output = Vec::new();
    for key in keys {
        // TODO error in indexing here?
        output.push(format!("{}={}", key, vote[key]));
    }
    output.join(" ")
}

/// Returns a boolean indicating whether the given protocol and version is
/// supported in any of the existing Tor protocols
///
/// # Examples
/// ```
/// use protover::*;
///
/// let is_supported = is_supported_here(Proto::Link, 10);
/// assert_eq!(false, is_supported);
///
/// let is_supported = is_supported_here(Proto::Link, 1);
/// assert_eq!(true, is_supported);
/// ```
pub fn is_supported_here(proto: Proto, vers: Version) -> bool {
    let currently_supported = match SupportedProtocols::tor_supported() {
        Ok(result) => result.0,
        Err(_) => return false,
    };

    let supported_versions = match currently_supported.get(&proto) {
        Some(n) => n,
        None => return false,
    };

    supported_versions.0.contains(&vers)
}

/// Older versions of Tor cannot infer their own subprotocols
/// Used to determine which subprotocols are supported by older Tor versions.
///
/// # Inputs
///
/// * `version`, a string comprised of "[0-9a-z.-]"
///
/// # Returns
///
/// A `&'static [u8]` encoding a list of protocol names and supported
/// versions. The string takes the following format:
///
/// "HSDir=1-1 LinkAuth=1"
///
/// This function returns the protocols that are supported by the version input,
/// only for tor versions older than FIRST_TOR_VERSION_TO_ADVERTISE_PROTOCOLS.
///
/// C_RUST_COUPLED: src/rust/protover.c `compute_for_old_tor`
pub fn compute_for_old_tor(version: &str) -> &'static [u8] {
    if c_tor_version_as_new_as(version, FIRST_TOR_VERSION_TO_ADVERTISE_PROTOCOLS) {
        return NUL_BYTE;
    }

    if c_tor_version_as_new_as(version, "0.2.9.1-alpha") {
        return b"Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 HSIntro=3 HSRend=1-2 \
                 Link=1-4 LinkAuth=1 Microdesc=1-2 Relay=1-2\0";
    }

    if c_tor_version_as_new_as(version, "0.2.7.5") {
        return b"Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 \
                 Link=1-4 LinkAuth=1 Microdesc=1-2 Relay=1-2\0";
    }

    if c_tor_version_as_new_as(version, "0.2.4.19") {
        return b"Cons=1 Desc=1 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 \
                 Link=1-4 LinkAuth=1 Microdesc=1 Relay=1-2\0";
    }

    NUL_BYTE
}

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use std::string::ToString;

    use super::*;

    #[test]
    fn test_versions_from_version_string() {
        use std::collections::HashSet;

        use super::Versions;

        assert_eq!(Err("invalid protocol entry"), Versions::from_version_string("a,b"));
        assert_eq!(Err("invalid protocol entry"), Versions::from_version_string("1,!"));

        {
            let mut versions: HashSet<Version> = HashSet::new();
            versions.insert(1);
            assert_eq!(versions, Versions::from_version_string("1").unwrap().0);
        }
        {
            let mut versions: HashSet<Version> = HashSet::new();
            versions.insert(1);
            versions.insert(2);
            assert_eq!(versions, Versions::from_version_string("1,2").unwrap().0);
        }
        {
            let mut versions: HashSet<Version> = HashSet::new();
            versions.insert(1);
            versions.insert(2);
            versions.insert(3);
            assert_eq!(versions, Versions::from_version_string("1-3").unwrap().0);
        }
        {
            let mut versions: HashSet<Version> = HashSet::new();
            versions.insert(1);
            versions.insert(2);
            versions.insert(5);
            assert_eq!(versions, Versions::from_version_string("1-2,5").unwrap().0);
        }
        {
            let mut versions: HashSet<Version> = HashSet::new();
            versions.insert(1);
            versions.insert(3);
            versions.insert(4);
            versions.insert(5);
            assert_eq!(versions, Versions::from_version_string("1,3-5").unwrap().0);
        }
    }

    #[test]
    fn test_contains_only_supported_protocols() {
        use super::contains_only_supported_protocols;

        assert_eq!(false, contains_only_supported_protocols(""));
        assert_eq!(true, contains_only_supported_protocols("Cons="));
        assert_eq!(true, contains_only_supported_protocols("Cons=1"));
        assert_eq!(false, contains_only_supported_protocols("Cons=0"));
        assert_eq!(false, contains_only_supported_protocols("Cons=0-1"));
        assert_eq!(false, contains_only_supported_protocols("Cons=5"));
        assert_eq!(false, contains_only_supported_protocols("Cons=1-5"));
        assert_eq!(false, contains_only_supported_protocols("Cons=1,5"));
        assert_eq!(false, contains_only_supported_protocols("Cons=5,6"));
        assert_eq!(false, contains_only_supported_protocols("Cons=1,5,6"));
        assert_eq!(true, contains_only_supported_protocols("Cons=1,2"));
        assert_eq!(true, contains_only_supported_protocols("Cons=1-2"));
    }

    #[test]
    fn test_find_range() {
        use super::find_range;

        assert_eq!((false, 0), find_range(&vec![]));
        assert_eq!((false, 1), find_range(&vec![1]));
        assert_eq!((true, 2), find_range(&vec![1, 2]));
        assert_eq!((true, 3), find_range(&vec![1, 2, 3]));
        assert_eq!((true, 3), find_range(&vec![1, 2, 3, 5]));
    }

    #[test]
    fn test_expand_version_range() {
        use super::expand_version_range;

        assert_eq!(Err("version string empty"), expand_version_range(""));
        assert_eq!(Ok(1..3), expand_version_range("1-2"));
        assert_eq!(Ok(1..5), expand_version_range("1-4"));
        assert_eq!(
            Err("cannot parse protocol range lower bound"),
            expand_version_range("a")
        );
        assert_eq!(
            Err("cannot parse protocol range upper bound"),
            expand_version_range("1-a")
        );
        assert_eq!(Ok(1000..66536), expand_version_range("1000-66535"));
        assert_eq!(Err("Too many protocols in expanded range"),
                   expand_version_range("1000-66536"));
    }

    #[test]
    fn test_contract_protocol_list() {
        use std::collections::HashSet;
        use super::contract_protocol_list;

        {
            let mut versions = HashSet::<Version>::new();
            assert_eq!(String::from(""), contract_protocol_list(&versions));

            versions.insert(1);
            assert_eq!(String::from("1"), contract_protocol_list(&versions));

            versions.insert(2);
            assert_eq!(String::from("1-2"), contract_protocol_list(&versions));
        }

        {
            let mut versions = HashSet::<Version>::new();
            versions.insert(1);
            versions.insert(3);
            assert_eq!(String::from("1,3"), contract_protocol_list(&versions));
        }

        {
            let mut versions = HashSet::<Version>::new();
            versions.insert(1);
            versions.insert(2);
            versions.insert(3);
            versions.insert(4);
            assert_eq!(String::from("1-4"), contract_protocol_list(&versions));
        }

        {
            let mut versions = HashSet::<Version>::new();
            versions.insert(1);
            versions.insert(3);
            versions.insert(5);
            versions.insert(6);
            versions.insert(7);
            assert_eq!(
                String::from("1,3,5-7"),
                contract_protocol_list(&versions)
            );
        }

        {
            let mut versions = HashSet::<Version>::new();
            versions.insert(1);
            versions.insert(2);
            versions.insert(3);
            versions.insert(500);
            assert_eq!(
                String::from("1-3,500"),
                contract_protocol_list(&versions)
            );
        }
    }
}
