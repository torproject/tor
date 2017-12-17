// Copyright (c) 2016-2017, The Tor Project, Inc. */
// See LICENSE for licensing information */

// Note that these functions are untested due to the fact that there are no
// return variables to test and they are calling into a C API.

/// The related domain which the logging message is relevant. For example,
/// log messages relevant to networking would use LogDomain::LdNet, whereas
/// general messages can use LdGeneral.
#[derive(Eq, PartialEq)]
pub enum LogDomain {
    LdNet,
    LdGeneral,
}

/// The severity level at which to log messages.
#[derive(Eq, PartialEq)]
pub enum LogSeverity {
    Notice,
    Warn,
}

/// Main entry point for Rust modules to log messages.
///
/// # Inputs
///
/// * A `severity` of type LogSeverity, which defines the level of severity the
/// message will be logged.
/// * A `domain` of type LogDomain, which defines the domain the log message
/// will be associated with.
/// * A `function` of type &str, which defines the name of the function where
/// the message is being logged. There is a current RFC for a macro that
/// defines function names. When it is, we should use it. See
/// https://github.com/rust-lang/rfcs/pull/1719
/// * A `message` of type &str, which is the log message itself.
#[macro_export]
macro_rules! tor_log_msg {
    ($severity: path,
     $domain: path,
     $function: expr,
     $($message:tt)*) =>
    {
        {
            let msg = format!($($message)*);
            $crate::tor_log_msg_impl($severity, $domain, $function, msg)
        }
    };
}

#[inline]
pub fn tor_log_msg_impl(
    severity: LogSeverity,
    domain: LogDomain,
    function: &str,
    message: String,
) {
    use std::ffi::CString;

    /// Default function name to log in case of errors when converting
    /// a function name to a CString
    const ERR_LOG_FUNCTION: &str = "tor_log_msg";

    /// Default message to log in case of errors when converting a log
    /// message to a CString
    const ERR_LOG_MSG: &str = "Unable to log message from Rust
            module due to error when converting to CString";

    let func = match CString::new(function) {
        Ok(n) => n,
        Err(_) => CString::new(ERR_LOG_FUNCTION).unwrap(),
    };

    let msg = match CString::new(message) {
        Ok(n) => n,
        Err(_) => CString::new(ERR_LOG_MSG).unwrap(),
    };

    // Bind to a local variable to preserve ownership. This is essential so
    // that ownership is guaranteed until these local variables go out of scope
    let func_ptr = func.as_ptr();
    let msg_ptr = msg.as_ptr();

    let c_severity = unsafe { log::translate_severity(severity) };
    let c_domain = unsafe { log::translate_domain(domain) };

    unsafe { log::tor_log_string(c_severity, c_domain, func_ptr, msg_ptr) }
}

/// This module exposes no-op functionality for testing other Rust modules
/// without linking to C.
#[cfg(any(test, feature = "testing"))]
pub mod log {
    use libc::{c_char, c_int};
    use super::LogDomain;
    use super::LogSeverity;

    pub unsafe fn tor_log_string<'a>(
        _severity: c_int,
        _domain: u32,
        _function: *const c_char,
        _message: *const c_char,
    ) {
    }

    pub unsafe fn translate_domain(_domain: LogDomain) -> u32 {
        1
    }

    pub unsafe fn translate_severity(_severity: LogSeverity) -> c_int {
        1
    }
}

/// This implementation is used when compiling for actual use, as opposed to
/// testing.
#[cfg(all(not(test), not(feature = "testing")))]
pub mod log {
    use libc::{c_char, c_int};
    use super::LogDomain;
    use super::LogSeverity;

    /// Severity log types. These mirror definitions in /src/common/torlog.h
    /// C_RUST_COUPLED: src/common/log.c, log domain types
    extern "C" {
        #[no_mangle]
        static _LOG_WARN: c_int;
        static _LOG_NOTICE: c_int;
    }

    /// Domain log types. These mirror definitions in /src/common/torlog.h
    /// C_RUST_COUPLED: src/common/log.c, log severity types
    extern "C" {
        #[no_mangle]
        static _LD_NET: u32;
        static _LD_GENERAL: u32;
    }

    /// Translate Rust defintions of log domain levels to C. This exposes a 1:1
    /// mapping between types.
    pub unsafe fn translate_domain(domain: LogDomain) -> u32 {
        match domain {
            LogDomain::LdNet => _LD_NET,
            LogDomain::LdGeneral => _LD_GENERAL,
        }
    }

    /// Translate Rust defintions of log severity levels to C. This exposes a
    /// 1:1 mapping between types.
    pub unsafe fn translate_severity(severity: LogSeverity) -> c_int {
        match severity {
            LogSeverity::Warn => _LOG_WARN,
            LogSeverity::Notice => _LOG_NOTICE,
        }
    }

    /// The main entry point into Tor's logger. When in non-test mode, this
    /// will link directly with `tor_log_string` in /src/or/log.c
    extern "C" {
        pub fn tor_log_string(
            severity: c_int,
            domain: u32,
            function: *const c_char,
            string: *const c_char,
        );
    }
}
