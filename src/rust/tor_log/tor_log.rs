// Copyright (c) 2016-2017, The Tor Project, Inc. */
// See LICENSE for licensing information */


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
            use std::ffi::CString;

            /// Default function name to log in case of errors when converting
            /// a function name to a CString
            const ERR_LOG_FUNCTION: &str = "tor_log_msg";

            /// Default message to log in case of errors when converting a log
            /// message to a CString
            const ERR_LOG_MSG: &str = "Unable to log message from Rust
            module due to error when converting to CString";

            let func = match CString::new($function) {
                Ok(n) => n,
                Err(_) => CString::new(ERR_LOG_FUNCTION).unwrap(),
            };

            let msg = match CString::new(format!($($message)*)) {
                Ok(n) => n,
                Err(_) => CString::new(ERR_LOG_MSG).unwrap(),
            };

            let func_ptr = func.as_ptr();
            let msg_ptr = msg.as_ptr();

            let c_severity = unsafe { translate_severity($severity) };
            let c_domain = unsafe { translate_domain($domain) };

            unsafe {
                $crate::tor_log_string(c_severity, c_domain, func_ptr, msg_ptr )
            }
        }
    };
}

/// This module exposes no-op functionality purely for the purpose of testing
/// Rust at the module level.
#[cfg(any(test, feature = "testing"))]
pub mod log {
    use libc::{c_char, c_int};
    use super::LogDomain;
    use super::LogSeverity;

    /// Expose a no-op logging interface purely for testing Rust modules at the
    /// module level.
    pub fn tor_log_string<'a>(
        severity: c_int,
        domain: u32,
        function: *const c_char,
        message: *const c_char,
    ) -> (c_int, u32, String, String) {
        use std::ffi::CStr;

        let func = unsafe { CStr::from_ptr(function) }.to_str().unwrap();
        let func_allocated = String::from(func);

        let msg = unsafe { CStr::from_ptr(message) }.to_str().unwrap();
        let msg_allocated = String::from(msg);
        (severity, domain, func_allocated, msg_allocated)
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
    #[allow(unreachable_patterns)]
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

#[cfg(test)]
mod test {
    use tor_log::*;
    use tor_log::log::*;

    use libc::c_int;

    #[test]
    fn test_get_log_message() {

        fn test_macro<'a>() -> (c_int, u32, String, String) {
            let (x, y, z, a) =
                tor_log_msg!(
                    LogSeverity::Warn,
                    LogDomain::LdNet,
                    "test_macro",
                    "test log message {}",
                    "a",
                    );
            (x, y, z, a)
        }

        let (severity, domain, function_name, log_msg) = test_macro();

        let expected_severity =
            unsafe { translate_severity(LogSeverity::Warn) };
        assert_eq!(severity, expected_severity);

        let expected_domain = unsafe { translate_domain(LogDomain::LdNet) };
        assert_eq!(domain, expected_domain);

        assert_eq!("test_macro", function_name);
        assert_eq!("test log message a", log_msg);
    }

    #[test]
    fn test_get_log_message_multiple_values() {
        fn test_macro<'a>() -> (c_int, u32, String, String) {
            let (x, y, z, a) = tor_log_msg!(
                LogSeverity::Warn,
                LogDomain::LdNet,
                "test_macro 2",
                "test log message {} {} {} {}",
                10,
                9,
                8,
                7
            );
            (x, y, z, a)
        }

        let (severity, domain, function_name, log_msg) = test_macro();

        let expected_severity =
            unsafe { translate_severity(LogSeverity::Warn) };
        assert_eq!(severity, expected_severity);

        let expected_domain = unsafe { translate_domain(LogDomain::LdNet) };
        assert_eq!(domain, expected_domain);

        assert_eq!("test_macro 2", function_name);
        assert_eq!("test log message 10 9 8 7", log_msg);
    }
}
