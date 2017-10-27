// Copyright (c) 2016-2017, The Tor Project, Inc. */
// See LICENSE for licensing information */

extern crate protover;

#[test]
fn parse_protocol_list_with_single_proto_and_single_version() {
    let protocol = "Cons=1";
    let (is_supported, unsupported) = protover::all_supported(protocol);
    assert_eq!(true, is_supported);
    assert_eq!("", &unsupported);
}

#[test]
fn parse_protocol_list_with_single_protocol_and_multiple_versions() {
    let protocol = "Cons=1-2";
    let (is_supported, unsupported) = protover::all_supported(protocol);
    assert_eq!(true, is_supported);
    assert_eq!("", &unsupported);
}

#[test]
fn parse_protocol_list_with_different_single_protocol_and_single_version() {
    let protocol = "HSDir=1";
    let (is_supported, unsupported) = protover::all_supported(protocol);
    assert_eq!(true, is_supported);
    assert_eq!("", &unsupported);
}

#[test]
fn parse_protocol_list_with_single_protocol_and_supported_version() {
    let protocol = "Desc=2";
    let (is_supported, unsupported) = protover::all_supported(protocol);
    assert_eq!(true, is_supported);
    assert_eq!("", &unsupported);
}

#[test]
fn parse_protocol_list_with_two_protocols_and_single_version() {
    let protocols = "Cons=1 HSDir=1";
    let (is_supported, unsupported) = protover::all_supported(protocols);
    assert_eq!(true, is_supported);
    assert_eq!("", &unsupported);
}


#[test]
fn parse_protocol_list_with_single_protocol_and_two_nonsequential_versions() {
    let protocol = "Desc=1,2";
    let (is_supported, unsupported) = protover::all_supported(protocol);
    assert_eq!(true, is_supported);
    assert_eq!("", &unsupported);
}


#[test]
fn parse_protocol_list_with_single_protocol_and_two_sequential_versions() {
    let protocol = "Desc=1-2";
    let (is_supported, unsupported) = protover::all_supported(protocol);
    assert_eq!(true, is_supported);
    assert_eq!("", &unsupported);
}

#[test]
fn parse_protocol_list_with_single_protocol_and_protocol_range_returns_set() {
    let protocol = "Link=1-4";
    let (is_supported, unsupported) = protover::all_supported(protocol);
    assert_eq!(true, is_supported);
    assert_eq!("", &unsupported);
}

#[test]
fn parse_protocol_list_with_single_protocol_and_protocol_set() {
    let protocols = "Link=3-4 Desc=2";
    let (is_supported, unsupported) = protover::all_supported(protocols);
    assert_eq!(true, is_supported);
    assert_eq!("", &unsupported);
}

#[test]
fn protover_all_supported_with_two_values() {
    let protocols = "Microdesc=1-2 Relay=2";
    let (is_supported, unsupported) = protover::all_supported(protocols);
    assert_eq!("", &unsupported);
    assert_eq!(true, is_supported);
}

#[test]
fn protover_all_supported_with_one_value() {
    let protocols = "Microdesc=1-2";
    let (is_supported, unsupported) = protover::all_supported(protocols);
    assert_eq!("", &unsupported);
    assert_eq!(true, is_supported);
}

#[test]
fn protover_all_supported_with_empty() {
    let protocols = "";
    let (is_supported, unsupported) = protover::all_supported(protocols);
    assert_eq!(true, is_supported);
    assert_eq!("", &unsupported);
}

#[test]
fn protover_all_supported_with_three_values() {
    let protocols = "LinkAuth=1 Microdesc=1-2 Relay=2";
    let (is_supported, unsupported) = protover::all_supported(protocols);
    assert_eq!("", &unsupported);
    assert_eq!(true, is_supported);
}

#[test]
fn protover_all_supported_with_unsupported_protocol() {
    let protocols = "Wombat=9";
    let (is_supported, unsupported) = protover::all_supported(protocols);
    assert_eq!(false, is_supported);
    assert_eq!("Wombat=9", &unsupported);
}

#[test]
fn protover_all_supported_with_unsupported_versions() {
    let protocols = "Link=3-999";
    let (is_supported, unsupported) = protover::all_supported(protocols);
    assert_eq!(false, is_supported);
    assert_eq!("Link=3-999", &unsupported);
}

#[test]
fn protover_all_supported_with_unsupported_low_version() {
    let protocols = "Cons=0-1";
    let (is_supported, unsupported) = protover::all_supported(protocols);
    assert_eq!(false, is_supported);
    assert_eq!("Cons=0-1", &unsupported);
}

#[test]
fn protover_all_supported_with_unsupported_high_version() {
    let protocols = "Cons=1-3";
    let (is_supported, unsupported) = protover::all_supported(protocols);
    assert_eq!(false, is_supported);
    assert_eq!("Cons=1-3", &unsupported);
}

#[test]
fn protover_all_supported_with_mix_of_supported_and_unsupproted() {
    let protocols = "Link=3-4 Wombat=9";
    let (is_supported, unsupported) = protover::all_supported(protocols);
    assert_eq!(false, is_supported);
    assert_eq!("Wombat=9", &unsupported);
}

#[test]
fn protover_string_supports_protocol_returns_true_for_single_supported() {
    let protocols = "Link=3-4 Cons=1";
    let is_supported = protover::protover_string_supports_protocol(
        protocols,
        protover::Proto::Cons,
        1,
    );
    assert_eq!(true, is_supported);
}

#[test]
fn protover_string_supports_protocol_returns_false_for_single_unsupported() {
    let protocols = "Link=3-4 Cons=1";
    let is_supported = protover::protover_string_supports_protocol(
        protocols,
        protover::Proto::Cons,
        2,
    );
    assert_eq!(false, is_supported);
}

#[test]
fn protover_string_supports_protocol_returns_false_for_unsupported() {
    let protocols = "Link=3-4";
    let is_supported = protover::protover_string_supports_protocol(
        protocols,
        protover::Proto::Cons,
        2,
    );
    assert_eq!(false, is_supported);
}

#[test]
fn protover_all_supported_with_unexpected_characters() {
    let protocols = "Cons=*-%";
    let (is_supported, unsupported) = protover::all_supported(protocols);
    assert_eq!(false, is_supported);
    assert_eq!("Cons=*-%", &unsupported);
}

#[test]
fn protover_compute_vote_returns_empty_for_empty_string() {
    let protocols = vec![String::from("")];
    let listed = protover::compute_vote(protocols, 1);
    assert_eq!("", listed);
}

#[test]
fn protover_compute_vote_returns_single_protocol_for_matching() {
    let protocols = vec![String::from("Cons=1")];
    let listed = protover::compute_vote(protocols, 1);
    assert_eq!("Cons=1", listed);
}

#[test]
fn protover_compute_vote_returns_two_protocols_for_two_matching() {
    let protocols = vec![String::from("Link=1 Cons=1")];
    let listed = protover::compute_vote(protocols, 1);
    assert_eq!("Cons=1 Link=1", listed);
}

#[test]
fn protover_compute_vote_returns_one_protocol_when_one_out_of_two_matches() {
    let protocols = vec![String::from("Cons=1 Link=2"), String::from("Cons=1")];
    let listed = protover::compute_vote(protocols, 2);
    assert_eq!("Cons=1", listed);
}

#[test]
fn protover_compute_vote_returns_protocols_that_it_doesnt_currently_support() {
    let protocols = vec![String::from("Foo=1 Cons=2"), String::from("Bar=1")];
    let listed = protover::compute_vote(protocols, 1);
    assert_eq!("Bar=1 Cons=2 Foo=1", listed);
}

#[test]
fn protover_compute_vote_returns_matching_for_mix() {
    let protocols = vec![String::from("Link=1-10,500 Cons=1,3-7,8")];
    let listed = protover::compute_vote(protocols, 1);
    assert_eq!("Cons=1,3-8 Link=1-10,500", listed);
}

#[test]
fn protover_compute_vote_returns_matching_for_longer_mix() {
    let protocols = vec![
        String::from("Desc=1-10,500 Cons=1,3-7,8"),
        String::from("Link=123-456,78 Cons=2-6,8 Desc=9"),
    ];

    let listed = protover::compute_vote(protocols, 1);
    assert_eq!("Cons=1-8 Desc=1-10,500 Link=78,123-456", listed);
}

#[test]
fn protover_compute_vote_returns_matching_for_longer_mix_with_threshold_two() {
    let protocols = vec![
        String::from("Desc=1-10,500 Cons=1,3-7,8"),
        String::from("Link=123-456,78 Cons=2-6,8 Desc=9"),
    ];

    let listed = protover::compute_vote(protocols, 2);
    assert_eq!("Cons=3-6,8 Desc=9", listed);
}

#[test]
fn protover_compute_vote_handles_duplicated_versions() {
    let protocols = vec![String::from("Cons=1"), String::from("Cons=1")];
    assert_eq!("Cons=1", protover::compute_vote(protocols, 2));

    let protocols = vec![String::from("Cons=1-2"), String::from("Cons=1-2")];
    assert_eq!("Cons=1-2", protover::compute_vote(protocols, 2));
}

#[test]
fn protover_compute_vote_handles_invalid_proto_entries() {
    let protocols = vec![
        String::from("Cons=1"),
        String::from("Cons=1"),
        String::from("Link=a"),
    ];
    assert_eq!("Cons=1", protover::compute_vote(protocols, 2));

    let protocols = vec![
        String::from("Cons=1"),
        String::from("Cons=1"),
        String::from("Link=1-%"),
    ];
    assert_eq!("Cons=1", protover::compute_vote(protocols, 2));
}

#[test]
fn protover_is_supported_here_returns_true_for_supported_protocol() {
    assert_eq!(true, protover::is_supported_here(protover::Proto::Cons, 1));
}

#[test]
fn protover_is_supported_here_returns_false_for_unsupported_protocol() {
    assert_eq!(false, protover::is_supported_here(protover::Proto::Cons, 5));
}
