// Copyright (c) 2018, The Tor Project, Inc.
// Copyright (c) 2018, isis agora lovecruft
// See LICENSE for licensing information

// External dependencies
extern crate rand_core;

// Internal dependencies
extern crate external;
#[cfg(not(test))]
#[macro_use]
extern crate tor_log;

pub mod rng;
pub mod prng;
