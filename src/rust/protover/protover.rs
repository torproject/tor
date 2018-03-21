// Copyright (c) 2016-2017, The Tor Project, Inc. */
// See LICENSE for licensing information */

use std::collections::HashMap;
use std::collections::hash_map;
use std::ffi::CStr;
use std::fmt;
use std::str;
use std::str::FromStr;
use std::string::String;

use external::c_tor_version_as_new_as;

use errors::ProtoverError;
use protoset::Version;
use protoset::ProtoSet;

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

/// Known subprotocols in Tor. Indicates which subprotocol a relay supports.
///
/// C_RUST_COUPLED: src/or/protover.h `protocol_type_t`
#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub enum Protocol {
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

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Translates a string representation of a protocol into a Proto type.
/// Error if the string is an unrecognized protocol name.
///
/// C_RUST_COUPLED: src/or/protover.c `PROTOCOL_NAMES`
impl FromStr for Protocol {
    type Err = ProtoverError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Cons" => Ok(Protocol::Cons),
            "Desc" => Ok(Protocol::Desc),
            "DirCache" => Ok(Protocol::DirCache),
            "HSDir" => Ok(Protocol::HSDir),
            "HSIntro" => Ok(Protocol::HSIntro),
            "HSRend" => Ok(Protocol::HSRend),
            "Link" => Ok(Protocol::Link),
            "LinkAuth" => Ok(Protocol::LinkAuth),
            "Microdesc" => Ok(Protocol::Microdesc),
            "Relay" => Ok(Protocol::Relay),
            _ => Err(ProtoverError::UnknownProtocol),
        }
    }
}

/// A protocol string which is not one of the `Protocols` we currently know
/// about.
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct UnknownProtocol(String);

impl fmt::Display for UnknownProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for UnknownProtocol {
    type Err = ProtoverError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(UnknownProtocol(s.to_string()))
    }
}

impl From<Protocol> for UnknownProtocol {
    fn from(p: Protocol) -> UnknownProtocol {
        UnknownProtocol(p.to_string())
    }
}

/// Get a CStr representation of current supported protocols, for
/// passing to C, or for converting to a `&str` for Rust.
///
/// # Returns
///
/// An `&'static CStr` whose value is the existing protocols supported by tor.
/// Returned data is in the format as follows:
///
/// "HSDir=1-1 LinkAuth=1"
///
/// # Note
///
/// Rust code can use the `&'static CStr` as a normal `&'a str` by
/// calling `protover::get_supported_protocols`.
///
//  C_RUST_COUPLED: src/or/protover.c `protover_get_supported_protocols`
pub(crate) fn get_supported_protocols_cstr() -> &'static CStr {
    cstr!("Cons=1-2 \
           Desc=1-2 \
           DirCache=1-2 \
           HSDir=1-2 \
           HSIntro=3-4 \
           HSRend=1-2 \
           Link=1-5 \
           LinkAuth=1,3 \
           Microdesc=1-2 \
           Relay=1-2")
}

/// A map of protocol names to the versions of them which are supported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtoEntry(HashMap<Protocol, ProtoSet>);

impl Default for ProtoEntry {
    fn default() -> ProtoEntry {
        ProtoEntry( HashMap::new() )
    }
}

impl ProtoEntry {
    /// Get an iterator over the `Protocol`s and their `ProtoSet`s in this `ProtoEntry`.
    pub fn iter(&self) -> hash_map::Iter<Protocol, ProtoSet> {
        self.0.iter()
    }

    /// Translate the supported tor versions from a string into a
    /// ProtoEntry, which is useful when looking up a specific
    /// subprotocol.
    pub fn supported() -> Result<Self, ProtoverError> {
        let supported_cstr: &'static CStr = get_supported_protocols_cstr();
        let supported: &str = supported_cstr.to_str().unwrap_or("");

        supported.parse()
    }

    pub fn get(&self, protocol: &Protocol) -> Option<&ProtoSet> {
        self.0.get(protocol)
    }

    pub fn insert(&mut self, key: Protocol, value: ProtoSet) {
        self.0.insert(key, value);
    }

    pub fn remove(&mut self, key: &Protocol) -> Option<ProtoSet> {
        self.0.remove(key)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromStr for ProtoEntry {
    type Err = ProtoverError;

    /// Parse a string of subprotocol types and their version numbers.
    ///
    /// # Inputs
    ///
    /// * A `protocol_entry` string, comprised of a keywords, an "=" sign, and
    /// one or more version numbers, each separated by a space.  For example,
    /// `"Cons=3-4 HSDir=1"`.
    ///
    /// # Returns
    ///
    /// A `Result` whose `Ok` value is a `ProtoEntry`, where the
    /// first element is the subprotocol type (see `protover::Protocol`) and the last
    /// element is an ordered set of `(low, high)` unique version numbers which are supported.
    /// Otherwise, the `Err` value of this `Result` is a `ProtoverError`.
    fn from_str(protocol_entry: &str) -> Result<ProtoEntry, ProtoverError> {
        let mut proto_entry: ProtoEntry = ProtoEntry::default();
        let entries = protocol_entry.split(' ');

        for entry in entries {
            let mut parts = entry.splitn(2, '=');

            let proto = match parts.next() {
                Some(n) => n,
                None => return Err(ProtoverError::Unparseable),
            };

            let vers = match parts.next() {
                Some(n) => n,
                None => return Err(ProtoverError::Unparseable),
            };
            let versions: ProtoSet = vers.parse()?;
            let proto_name: Protocol = proto.parse()?;

            proto_entry.insert(proto_name, versions);
        }

        Ok(proto_entry)
    }
}

/// A `ProtoEntry`, but whose `Protocols` can be any `UnknownProtocol`, not just
/// the supported ones enumerated in `Protocols`.  The protocol versions are
/// validated, however.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnvalidatedProtoEntry(HashMap<UnknownProtocol, ProtoSet>);

impl Default for UnvalidatedProtoEntry {
    fn default() -> UnvalidatedProtoEntry {
        UnvalidatedProtoEntry( HashMap::new() )
    }
}

impl UnvalidatedProtoEntry {
    /// Get an iterator over the `Protocol`s and their `ProtoSet`s in this `ProtoEntry`.
    pub fn iter(&self) -> hash_map::Iter<UnknownProtocol, ProtoSet> {
        self.0.iter()
    }

    pub fn get(&self, protocol: &UnknownProtocol) -> Option<&ProtoSet> {
        self.0.get(protocol)
    }

    pub fn insert(&mut self, key: UnknownProtocol, value: ProtoSet) {
        self.0.insert(key, value);
    }

    pub fn remove(&mut self, key: &UnknownProtocol) -> Option<ProtoSet> {
        self.0.remove(key)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Determine if we support every protocol a client supports, and if not,
    /// determine which protocols we do not have support for.
    ///
    /// # Returns
    ///
    /// Optionally, return parameters which the client supports but which we do not.
    ///
    /// # Examples
    /// ```
    /// use protover::UnvalidatedProtoEntry;
    ///
    /// let protocols: UnvalidatedProtoEntry = "LinkAuth=1 Microdesc=1-2 Relay=2".parse().unwrap();
    /// let unsupported: Option<UnvalidatedProtoEntry> = protocols.all_supported();
    /// assert_eq!(true, unsupported.is_none());
    ///
    /// let protocols: UnvalidatedProtoEntry = "Link=1-2 Wombat=9".parse().unwrap();
    /// let unsupported: Option<UnvalidatedProtoEntry> = protocols.all_supported();
    /// assert_eq!(true, unsupported.is_some());
    /// assert_eq!("Wombat=9", &unsupported.unwrap().to_string());
    /// ```
    pub fn all_supported(&self) -> Option<UnvalidatedProtoEntry> {
        let mut unsupported: UnvalidatedProtoEntry = UnvalidatedProtoEntry::default();
        let supported: ProtoEntry = match ProtoEntry::supported() {
            Ok(x)  => x,
            Err(_) => return None,
        };

        for (protocol, versions) in self.iter() {
            let is_supported: Result<Protocol, ProtoverError> = protocol.0.parse();
            let supported_protocol: Protocol;

            // If the protocol wasn't even in the enum, then we definitely don't
            // know about it and don't support any of its versions.
            if is_supported.is_err() {
                if !versions.is_empty() {
                    unsupported.insert(protocol.clone(), versions.clone());
                }
                continue;
            } else {
                supported_protocol = is_supported.unwrap();
            }

            let maybe_supported_versions: Option<&ProtoSet> = supported.get(&supported_protocol);
            let supported_versions: &ProtoSet;
            let mut unsupported_versions: ProtoSet;

            // If the protocol wasn't in the map, then we don't know about it
            // and don't support any of its versions.  Add its versions to the
            // map (if it has versions).
            if maybe_supported_versions.is_none() {
                if !versions.is_empty() {
                    unsupported.insert(protocol.clone(), versions.clone());
                }
                continue;
            } else {
                supported_versions = maybe_supported_versions.unwrap();
            }
            unsupported_versions = versions.clone();
            unsupported_versions.retain(|x| !supported_versions.contains(x));

            if !unsupported_versions.is_empty() {
                unsupported.insert(protocol.clone(), unsupported_versions);
            }
        }

        if unsupported.is_empty() {
            return None;
        }
        Some(unsupported)
    }

    /// Determine if we have support for some protocol and version.
    ///
    /// # Inputs
    ///
    /// * `proto`, an `UnknownProtocol` to test support for
    /// * `vers`, a `Version` which we will go on to determine whether the
    /// specified protocol supports.
    ///
    /// # Return
    ///
    /// Returns `true` iff this `UnvalidatedProtoEntry` includes support for the
    /// indicated protocol and version, and `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::str::FromStr;
    /// use protover::*;
    /// # use protover::errors::ProtoverError;
    ///
    /// # fn do_test () -> Result<UnvalidatedProtoEntry, ProtoverError> {
    /// let proto: UnvalidatedProtoEntry = "Link=3-4 Cons=1 Doggo=3-5".parse()?;
    /// assert_eq!(true, proto.supports_protocol(&Protocol::Cons.into(), &1));
    /// assert_eq!(false, proto.supports_protocol(&Protocol::Cons.into(), &5));
    /// assert_eq!(true, proto.supports_protocol(&UnknownProtocol::from_str("Doggo")?, &4));
    /// # Ok(proto)
    /// # } fn main () { do_test(); }
    /// ```
    pub fn supports_protocol(&self, proto: &UnknownProtocol, vers: &Version) -> bool {
        let supported_versions: &ProtoSet = match self.get(proto) {
            Some(n) => n,
            None => return false,
        };
        supported_versions.contains(&vers)
    }

    /// As `UnvalidatedProtoEntry::supports_protocol()`, but also returns `true`
    /// if any later version of the protocol is supported.
    ///
    /// # Examples
    /// ```
    /// use protover::*;
    /// # use protover::errors::ProtoverError;
    ///
    /// # fn do_test () -> Result<UnvalidatedProtoEntry, ProtoverError> {
    /// let proto: UnvalidatedProtoEntry = "Link=3-4 Cons=5".parse()?;
    ///
    /// assert_eq!(true, proto.supports_protocol_or_later(&Protocol::Cons.into(), &5));
    /// assert_eq!(true, proto.supports_protocol_or_later(&Protocol::Cons.into(), &4));
    /// assert_eq!(false, proto.supports_protocol_or_later(&Protocol::Cons.into(), &6));
    /// # Ok(proto)
    /// # } fn main () { do_test(); }
    /// ```
    pub fn supports_protocol_or_later(&self, proto: &UnknownProtocol, vers: &Version) -> bool {
        let supported_versions: &ProtoSet = match self.get(&proto) {
            Some(n) => n,
            None => return false,
        };
        supported_versions.iter().any(|v| v.1 >= *vers)
    }
}

impl FromStr for UnvalidatedProtoEntry {
    type Err = ProtoverError;

    /// Parses a protocol list without validating the protocol names.
    ///
    /// # Inputs
    ///
    /// * `protocol_string`, a string comprised of keys and values, both which are
    /// strings. The keys are the protocol names while values are a string
    /// representation of the supported versions.
    ///
    /// The input is _not_ expected to be a subset of the Protocol types
    ///
    /// # Returns
    ///
    /// A `Result` whose `Ok` value is a `ProtoSet` holding all of the
    /// unique version numbers.
    ///
    /// The returned `Result`'s `Err` value is an `ProtoverError` whose `Display`
    /// impl has a description of the error.
    ///
    /// # Errors
    ///
    /// This function will error if:
    ///
    /// * The protocol string does not follow the "protocol_name=version_list"
    ///   expected format, or
    /// * If the version string is malformed. See `impl FromStr for ProtoSet`.
    fn from_str(protocol_string: &str) -> Result<UnvalidatedProtoEntry, ProtoverError> {
        let mut parsed: UnvalidatedProtoEntry = UnvalidatedProtoEntry::default();

        for subproto in protocol_string.split(' ') {
            let mut parts = subproto.splitn(2, '=');

            let name = match parts.next() {
                Some("") => return Err(ProtoverError::Unparseable),
                Some(n) => n,
                None => return Err(ProtoverError::Unparseable),
            };
            let vers = match parts.next() {
                Some(n) => n,
                None => return Err(ProtoverError::Unparseable),
            };
            let versions = ProtoSet::from_str(vers)?;
            let protocol = UnknownProtocol::from_str(name)?;

            parsed.insert(protocol, versions);
        }
        Ok(parsed)
    }
}

/// Pretend a `ProtoEntry` is actually an `UnvalidatedProtoEntry`.
impl From<ProtoEntry> for UnvalidatedProtoEntry {
    fn from(proto_entry: ProtoEntry) -> UnvalidatedProtoEntry {
        let mut unvalidated: UnvalidatedProtoEntry = UnvalidatedProtoEntry::default();

        for (protocol, versions) in proto_entry.iter() {
            unvalidated.insert(UnknownProtocol::from(protocol.clone()), versions.clone());
        }
        unvalidated
    }
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
/// A `&'static CStr` encoding a list of protocol names and supported
/// versions. The string takes the following format:
///
/// "HSDir=1-1 LinkAuth=1"
///
/// This function returns the protocols that are supported by the version input,
/// only for tor versions older than FIRST_TOR_VERSION_TO_ADVERTISE_PROTOCOLS.
///
/// C_RUST_COUPLED: src/rust/protover.c `compute_for_old_tor`
pub fn compute_for_old_tor(version: &str) -> &'static CStr {
    let empty: &'static CStr = cstr!("");

    if c_tor_version_as_new_as(version, FIRST_TOR_VERSION_TO_ADVERTISE_PROTOCOLS) {
        return empty;
    }

    if c_tor_version_as_new_as(version, "0.2.9.1-alpha") {
        return cstr!("Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 HSIntro=3 HSRend=1-2 \
                      Link=1-4 LinkAuth=1 Microdesc=1-2 Relay=1-2");
    }

    if c_tor_version_as_new_as(version, "0.2.7.5") {
        return cstr!("Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 \
                      Link=1-4 LinkAuth=1 Microdesc=1-2 Relay=1-2");
    }

    if c_tor_version_as_new_as(version, "0.2.4.19") {
        return cstr!("Cons=1 Desc=1 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 \
                      Link=1-4 LinkAuth=1 Microdesc=1 Relay=1-2");
    }

    empty
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
