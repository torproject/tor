// Copyright (c) 2016-2017, The Tor Project, Inc. */
// See LICENSE for licensing information */

use external::c_tor_version_as_new_as;

use std::str::FromStr;
use std::fmt;
use std::collections::{HashMap, HashSet};
use std::string::String;

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
const MAX_PROTOCOLS_TO_EXPAND: u32 = 500;

/// Currently supported protocols and their versions
///
/// C_RUST_COUPLED: src/or/protover.c `protover_get_supported_protocols`
const SUPPORTED_PROTOCOLS: &'static [&'static str] = &[
    "Cons=1-2",
    "Desc=1-2",
    "DirCache=1-2",
    "HSDir=1-2",
    "HSIntro=3-4",
    "HSRend=1-2",
    "Link=1-4",
    "LinkAuth=1,3",
    "Microdesc=1-2",
    "Relay=1-2",
];

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
    type Err = &'static str;

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
            _ => Err("Not a valid protocol type"),
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
pub fn get_supported_protocols() -> String {
    SUPPORTED_PROTOCOLS.join(" ")
}

/// Translates a vector representation of a protocol list into a HashMap
fn parse_protocols(
    protocols: &[&str],
) -> Result<HashMap<Proto, HashSet<u32>>, &'static str> {
    let mut parsed = HashMap::new();

    for subproto in protocols {
        let (name, version) = get_proto_and_vers(subproto)?;
        parsed.insert(name, version);
    }
    Ok(parsed)
}

/// Translates a string representation of a protocol list to a HashMap
fn parse_protocols_from_string<'a>(
    protocol_string: &'a str,
) -> Result<HashMap<Proto, HashSet<u32>>, &'static str> {
    let protocols: &[&'a str] =
        &protocol_string.split(" ").collect::<Vec<&'a str>>()[..];

    parse_protocols(protocols)
}

/// Translates supported tor versions from  a string into a HashMap, which is
/// useful when looking up a specific subprotocol.
///
/// # Returns
///
/// A `Result` whose `Ok` value is a `HashMap<Proto, <u32>>` holding all
/// subprotocols and versions currently supported by tor.
///
/// The returned `Result`'s `Err` value is an `&'static str` with a description
/// of the error.
///
fn tor_supported() -> Result<HashMap<Proto, HashSet<u32>>, &'static str> {
    parse_protocols(&SUPPORTED_PROTOCOLS)
}

/// Get the unique version numbers supported by a subprotocol.
///
/// # Inputs
///
/// * `version_string`, a string comprised of "[0-9,-]"
///
/// # Returns
///
/// A `Result` whose `Ok` value is a `HashSet<u32>` holding all of the unique
/// version numbers.  If there were ranges in the `version_string`, then these
/// are expanded, i.e. `"1-3"` would expand to `HashSet<u32>::new([1, 2, 3])`.
/// The returned HashSet is *unordered*.
///
/// The returned `Result`'s `Err` value is an `&'static str` with a description
/// of the error.
///
/// # Errors
///
/// This function will error if:
///
/// * the `version_string` is empty or contains an equals (`"="`) sign,
/// * the expansion of a version range produces an error (see
///  `expand_version_range`),
/// * any single version number is not parseable as an `u32` in radix 10, or
/// * there are greater than 2^16 version numbers to expand.
///
fn get_versions(version_string: &str) -> Result<HashSet<u32>, &'static str> {
    if version_string.is_empty() {
        return Err("version string is empty");
    }

    let mut versions = HashSet::<u32>::new();

    for piece in version_string.split(",") {
        if piece.contains("-") {
            for p in expand_version_range(piece)? {
                versions.insert(p);
            }
        } else {
            versions.insert(u32::from_str(piece).or(
                Err("invalid protocol entry"),
            )?);
        }

        if versions.len() > MAX_PROTOCOLS_TO_EXPAND as usize {
            return Err("Too many versions to expand");
        }
    }
    Ok(versions)
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
) -> Result<(Proto, HashSet<u32>), &'static str> {
    let mut parts = protocol_entry.splitn(2, "=");

    let proto = match parts.next() {
        Some(n) => n,
        None => return Err("invalid protover entry"),
    };

    let vers = match parts.next() {
        Some(n) => n,
        None => return Err("invalid protover entry"),
    };

    let versions = get_versions(vers)?;
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

    let currently_supported: HashMap<Proto, HashSet<u32>> =
        match tor_supported() {
            Ok(n) => n,
            Err(_) => return false,
        };

    let supported_versions = match currently_supported.get(&name) {
        Some(n) => n,
        None => return false,
    };

    vers.retain(|x| !supported_versions.contains(x));
    vers.is_empty()
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
/// * `vers`, a `u32` version which we will go on to determine whether the
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
    vers: u32,
) -> bool {
    let supported: HashMap<Proto, HashSet<u32>>;

    match parse_protocols_from_string(list) {
        Ok(result) => supported = result,
        Err(_) => return false,
    }

    let supported_versions = match supported.get(&proto) {
        Some(n) => n,
        None => return false,
    };

    supported_versions.contains(&vers)
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
    let supported: HashMap<Proto, HashSet<u32>>;

    match parse_protocols_from_string(list) {
        Ok(result) => supported = result,
        Err(_) => return false,
    }

    let supported_versions = match supported.get(&proto) {
        Some(n) => n,
        None => return false,
    };

    supported_versions.iter().any(|v| v >= &vers)
}

/// Fully expand a version range. For example, 1-3 expands to 1,2,3
/// Helper for get_versions
///
/// # Inputs
///
/// `range`, a string comprised of "[0-9,-]"
///
/// # Returns
///
/// A `Result` whose `Ok` value a vector of unsigned integers representing the
/// expanded range of supported versions by a single protocol.
/// Otherwise, the `Err` value of this `Result` is a description of the error
///
/// # Errors
///
/// This function will error if:
///
/// * the specified range is empty
/// * the version range does not contain both a valid lower and upper bound.
///
fn expand_version_range(range: &str) -> Result<Vec<u32>, &'static str> {
    if range.is_empty() {
        return Err("version string empty");
    }

    let mut parts = range.split("-");

    let lower_string = parts.next().ok_or(
        "cannot parse protocol range lower bound",
    )?;

    let lower = u32::from_str_radix(lower_string, 10).or(Err(
        "cannot parse protocol range lower bound",
    ))?;

    let higher_string = parts.next().ok_or(
        "cannot parse protocol range upper bound",
    )?;

    let higher = u32::from_str_radix(higher_string, 10).or(Err(
        "cannot parse protocol range upper bound",
    ))?;

    // We can use inclusive range syntax when it becomes stable.
    Ok((lower..higher + 1).collect())
}

/// Checks to see if there is a continuous range of integers, starting at the
/// first in the list. Returns the last integer in the range if a range exists.
/// Helper for compute_vote
///
/// # Inputs
///
/// `list`, an ordered  vector of `u32` integers of "[0-9,-]" representing the
/// supported versions for a single protocol.
///
/// # Returns
///
/// A `bool` indicating whether the list contains a range, starting at the
/// first in the list, and an `u32` of the last integer in the range.
///
/// For example, if given vec![1, 2, 3, 5], find_range will return true,
/// as there is a continuous range, and 3, which is the last number in the
/// continuous range.
///
fn find_range(list: &Vec<u32>) -> (bool, u32) {
    if list.len() == 0 {
        return (false, 0);
    }

    let mut iterable = list.iter().peekable();
    let mut range_end = match iterable.next() {
        Some(n) => *n,
        None => return (false, 0),
    };

    let mut has_range = false;

    while iterable.peek().is_some() {
        let n = *iterable.next().unwrap();
        if n != range_end + 1 {
            break;
        }

        has_range = true;
        range_end = n;
    }

    (has_range, range_end)
}

/// Contracts a HashSet representation of supported versions into a string.
/// Helper for compute_vote
///
/// # Inputs
///
/// `supported_set`, a set of integers of "[0-9,-]" representing the
/// supported versions for a single protocol.
///
/// # Returns
///
/// A `String` representation of this set in ascending order.
///
fn contract_protocol_list<'a>(supported_set: &'a HashSet<u32>) -> String {
    let mut supported: Vec<u32> = supported_set.iter()
                                               .map(|x| *x)
                                               .collect();
    supported.sort();

    let mut final_output: Vec<String> = Vec::new();

    while supported.len() != 0 {
        let (has_range, end) = find_range(&supported);
        let current = supported.remove(0);

        if has_range {
            final_output.push(format!(
                "{}-{}",
                current.to_string(),
                &end.to_string(),
            ));
            supported.retain(|&x| x > end);
        } else {
            final_output.push(current.to_string());
        }
    }

    final_output.join(",")
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
/// A `Result` whose `Ok` value is a `HashSet<u32>` holding all of the unique
/// version numbers.
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
/// * If the version string is malformed. See `get_versions`.
///
fn parse_protocols_from_string_with_no_validation<'a>(
    protocol_string: &'a str,
) -> Result<HashMap<String, HashSet<u32>>, &'static str> {
    let protocols = &protocol_string.split(" ").collect::<Vec<&'a str>>()[..];

    let mut parsed: HashMap<String, HashSet<u32>> = HashMap::new();

    for subproto in protocols {
        let mut parts = subproto.splitn(2, "=");

        let name = match parts.next() {
            Some(n) => n,
            None => return Err("invalid protover entry"),
        };

        let vers = match parts.next() {
            Some(n) => n,
            None => return Err("invalid protover entry"),
        };

        let versions = get_versions(vers)?;

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
    let mut all_count: HashMap<String, HashMap<u32, usize>> = HashMap::new();

    // parse and collect all of the protos and their versions and collect them
    for vote in list_of_proto_strings {
        let this_vote: HashMap<String, HashSet<u32>> =
            match parse_protocols_from_string_with_no_validation(&vote) {
                Ok(result) => result,
                Err(_) => continue,
            };

        for (protocol, versions) in this_vote {
            let supported_vers: &mut HashMap<u32, usize> =
                all_count.entry(protocol).or_insert(HashMap::new());

            for version in versions {
                let counter: &mut usize =
                    supported_vers.entry(version).or_insert(0);
                *counter += 1;
            }
        }
    }

    let mut final_output: HashMap<String, String> =
        HashMap::with_capacity(SUPPORTED_PROTOCOLS.len());

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
/// let is_supported = is_supported_here(Proto::Link, 5);
/// assert_eq!(false, is_supported);
///
/// let is_supported = is_supported_here(Proto::Link, 1);
/// assert_eq!(true, is_supported);
/// ```
pub fn is_supported_here(proto: Proto, vers: u32) -> bool {
    let currently_supported: HashMap<Proto, HashSet<u32>>;

    match tor_supported() {
        Ok(result) => currently_supported = result,
        Err(_) => return false,
    }

    let supported_versions = match currently_supported.get(&proto) {
        Some(n) => n,
        None => return false,
    };

    supported_versions.contains(&vers)
}

/// Older versions of Tor cannot infer their own subprotocols
/// Used to determine which subprotocols are supported by older Tor versions.
///
/// # Inputs
///
/// * `version`, a string comprised of "[0-9,-]"
///
/// # Returns
///
/// A `String` whose value is series of pairs, comprising of the protocol name
/// and versions that it supports. The string takes the following format:
///
/// "HSDir=1-1 LinkAuth=1"
///
/// This function returns the protocols that are supported by the version input,
/// only for tor versions older than FIRST_TOR_VERSION_TO_ADVERTISE_PROTOCOLS.
///
/// C_RUST_COUPLED: src/rust/protover.c `compute_for_old_tor`
pub fn compute_for_old_tor(version: &str) -> String {
    if c_tor_version_as_new_as(
        version,
        FIRST_TOR_VERSION_TO_ADVERTISE_PROTOCOLS,
    )
    {
        return String::new();
    }

    if c_tor_version_as_new_as(version, "0.2.9.1-alpha") {
        let ret = "Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 HSIntro=3 HSRend=1-2 \
                   Link=1-4 LinkAuth=1 Microdesc=1-2 Relay=1-2";
        return String::from(ret);
    }

    if c_tor_version_as_new_as(version, "0.2.7.5") {
        let ret = "Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 \
                   Link=1-4 LinkAuth=1 Microdesc=1-2 Relay=1-2";
        return String::from(ret);
    }

    if c_tor_version_as_new_as(version, "0.2.4.19") {
        let ret = "Cons=1 Desc=1 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 \
                   Link=1-4 LinkAuth=1 Microdesc=1 Relay=1-2";
        return String::from(ret);
    }
    String::new()
}

#[cfg(test)]
mod test {
    #[test]
    fn test_get_versions() {
        use std::collections::HashSet;

        use super::get_versions;

        assert_eq!(Err("version string is empty"), get_versions(""));
        assert_eq!(Err("invalid protocol entry"), get_versions("a,b"));
        assert_eq!(Err("invalid protocol entry"), get_versions("1,!"));

        {
            let mut versions: HashSet<u32> = HashSet::new();
            versions.insert(1);
            assert_eq!(Ok(versions), get_versions("1"));
        }
        {
            let mut versions: HashSet<u32> = HashSet::new();
            versions.insert(1);
            versions.insert(2);
            assert_eq!(Ok(versions), get_versions("1,2"));
        }
        {
            let mut versions: HashSet<u32> = HashSet::new();
            versions.insert(1);
            versions.insert(2);
            versions.insert(3);
            assert_eq!(Ok(versions), get_versions("1-3"));
        }
        {
            let mut versions: HashSet<u32> = HashSet::new();
            versions.insert(1);
            versions.insert(2);
            versions.insert(5);
            assert_eq!(Ok(versions), get_versions("1-2,5"));
        }
        {
            let mut versions: HashSet<u32> = HashSet::new();
            versions.insert(1);
            versions.insert(3);
            versions.insert(4);
            versions.insert(5);
            assert_eq!(Ok(versions), get_versions("1,3-5"));
        }
    }

    #[test]
    fn test_contains_only_supported_protocols() {
        use super::contains_only_supported_protocols;

        assert_eq!(false, contains_only_supported_protocols(""));
        assert_eq!(false, contains_only_supported_protocols("Cons="));
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
        assert_eq!(Ok(vec![1, 2]), expand_version_range("1-2"));
        assert_eq!(Ok(vec![1, 2, 3, 4]), expand_version_range("1-4"));
        assert_eq!(
            Err("cannot parse protocol range lower bound"),
            expand_version_range("a")
        );
        assert_eq!(
            Err("cannot parse protocol range upper bound"),
            expand_version_range("1-a")
        );
    }

    #[test]
    fn test_contract_protocol_list() {
        use std::collections::HashSet;
        use super::contract_protocol_list;

        {
            let mut versions = HashSet::<u32>::new();
            assert_eq!(String::from(""), contract_protocol_list(&versions));

            versions.insert(1);
            assert_eq!(String::from("1"), contract_protocol_list(&versions));

            versions.insert(2);
            assert_eq!(String::from("1-2"), contract_protocol_list(&versions));
        }

        {
            let mut versions = HashSet::<u32>::new();
            versions.insert(1);
            versions.insert(3);
            assert_eq!(String::from("1,3"), contract_protocol_list(&versions));
        }

        {
            let mut versions = HashSet::<u32>::new();
            versions.insert(1);
            versions.insert(2);
            versions.insert(3);
            versions.insert(4);
            assert_eq!(String::from("1-4"), contract_protocol_list(&versions));
        }

        {
            let mut versions = HashSet::<u32>::new();
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
            let mut versions = HashSet::<u32>::new();
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
