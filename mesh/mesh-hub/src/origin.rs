// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Which web pages may open the daemon's WebSocket, judged by the `Origin`
//! header a browser sends and a page cannot forge, under the rule
//! [`crate::ConnectionPolicy::allowed_origins`] states; without it, any page
//! the user visits could read the mesh. Checked by the tests below,
//! `tests/origin.rs` and `fuzz_origin`.

use std::fmt;
use std::net::Ipv6Addr;

/// An origin, besides the loopback ones, whose pages may open the daemon's
/// WebSocket: `scheme://host[:port]`, such as `https://example.com`.
///
/// It is kept in a normal form (scheme and host lowercased, an IPv6 host in its
/// shortest form, a scheme's default port dropped), and admits an upgrade whose
/// `Origin`, in the same form, is equal. That is the form browsers send, but
/// for an IPv4-mapped IPv6 host, written here in dotted decimal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AllowedOrigin(String);

impl AllowedOrigin {
    /// Parse `text` as an origin.
    ///
    /// # Errors
    ///
    /// [`InvalidOrigin`] unless `text` is `scheme://host[:port]` with an ASCII
    /// host (an internationalised name in its `xn--` form) and a port from 1 to
    /// 65535, and not `null`, which pages of every site can send.
    pub fn parse(text: &str) -> Result<Self, InvalidOrigin> {
        WebOrigin::parse(text)
            .map(|origin| Self(origin.to_string()))
            .map_err(|reason| InvalidOrigin {
                text: text.to_string(),
                reason,
            })
    }

    /// The origin in its normal form (see [`AllowedOrigin`]).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for AllowedOrigin {
    type Err = InvalidOrigin;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl fmt::Display for AllowedOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a text is not an origin that can be allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidOrigin {
    text: String,
    reason: &'static str,
}

impl fmt::Display for InvalidOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} is not an origin ({}); an origin is scheme://host[:port], \
             as a browser sends it, such as https://example.com",
            self.text, self.reason
        )
    }
}

impl std::error::Error for InvalidOrigin {}

/// What the WebSocket makes of an upgrade's `Origin` headers; public, and
/// hidden, for `fuzz_origin`.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// No `Origin`: a client that is not a web page.
    NoOrigin,
    /// A page served from this machine.
    Loopback,
    /// A page from an origin the operator allowed.
    Allowed,
    /// Refused, and why, for the log.
    Refused(&'static str),
}

/// Judge an upgrade by its `Origin` header values against `allowed`; public,
/// and hidden, for `fuzz_origin`.
#[doc(hidden)]
pub fn judge<'a>(
    mut origins: impl Iterator<Item = &'a [u8]>,
    allowed: &[AllowedOrigin],
) -> Verdict {
    let Some(first) = origins.next() else {
        return Verdict::NoOrigin;
    };
    if origins.next().is_some() {
        return Verdict::Refused("more than one Origin header");
    }
    let Ok(text) = std::str::from_utf8(first) else {
        return Verdict::Refused("the Origin header is not text");
    };
    match WebOrigin::parse(text) {
        Err(reason) => Verdict::Refused(reason),
        Ok(origin) if origin.is_loopback() => Verdict::Loopback,
        Ok(origin) => {
            let origin = origin.to_string();
            if allowed.iter().any(|a| a.as_str() == origin) {
                Verdict::Allowed
            } else {
                Verdict::Refused("not a loopback origin, and not allowed with --allow-origin")
            }
        }
    }
}

/// An origin taken apart, in the normal form [`AllowedOrigin`] describes.
struct WebOrigin {
    scheme: String,
    host: String,
    port: Option<u16>,
}

impl WebOrigin {
    fn parse(text: &str) -> Result<Self, &'static str> {
        if text.eq_ignore_ascii_case("null") {
            return Err(
                "`null` is the opaque origin of sandboxed frames and file: pages on any site",
            );
        }
        let (scheme, authority) = text
            .split_once("://")
            .ok_or("it has no `://` after a scheme")?;
        let scheme_ok = scheme
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic())
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'));
        if !scheme_ok {
            return Err("its scheme is not a letter followed by letters, digits, `+`, `-` or `.`");
        }
        let scheme = scheme.to_ascii_lowercase();
        let (host, port) = split_host_port(authority)?;
        let port = port.map(parse_port).transpose()?;
        let default = match scheme.as_str() {
            "http" | "ws" => Some(80),
            "https" | "wss" => Some(443),
            _ => None,
        };
        Ok(Self {
            scheme,
            host,
            port: port.filter(|&p| Some(p) != default),
        })
    }

    /// A page served from this machine: `http` or `https` on `localhost`,
    /// `127.0.0.1` or `[::1]`, at any port.
    fn is_loopback(&self) -> bool {
        matches!(self.scheme.as_str(), "http" | "https")
            && matches!(self.host.as_str(), "localhost" | "127.0.0.1" | "[::1]")
    }
}

impl fmt::Display for WebOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.scheme, self.host)?;
        match self.port {
            Some(port) => write!(f, ":{port}"),
            None => Ok(()),
        }
    }
}

/// The host of `authority`, lowercased, and the text of its port, if any.
fn split_host_port(authority: &str) -> Result<(String, Option<&str>), &'static str> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let (inside, after) = bracketed
            .split_once(']')
            .ok_or("its IPv6 host has no closing `]`")?;
        let address: Ipv6Addr = inside
            .parse()
            .map_err(|_| "its bracketed host is not an IPv6 address")?;
        let port = match after {
            "" => None,
            _ => Some(
                after
                    .strip_prefix(':')
                    .ok_or("something other than a port follows its host")?,
            ),
        };
        return Ok((format!("[{address}]"), port));
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if host.is_empty() {
        return Err("it has no host");
    }
    let host_ok = host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'));
    if !host_ok {
        return Err("its host is not ASCII letters, digits, `-`, `.` and `_` (a path, a query, user information, or a name not in its xn-- form)");
    }
    Ok((host.to_ascii_lowercase(), port))
}

/// A port: one to five digits naming a number from 1 to 65535.
fn parse_port(text: &str) -> Result<u16, &'static str> {
    const BAD: &str = "its port is not a number from 1 to 65535";
    if text.is_empty() || text.len() > 5 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(BAD);
    }
    match text.parse::<u16>() {
        Ok(0) | Err(_) => Err(BAD),
        Ok(port) => Ok(port),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn admitted(verdict: Verdict) -> bool {
        !matches!(verdict, Verdict::Refused(_))
    }

    fn verdict(origins: &[&str], allowed: &[&str]) -> Verdict {
        let allowed: Vec<AllowedOrigin> = allowed
            .iter()
            .map(|a| AllowedOrigin::parse(a).unwrap())
            .collect();
        judge(origins.iter().map(|o| o.as_bytes()), &allowed)
    }

    #[test]
    fn an_upgrade_without_an_origin_is_admitted() {
        assert_eq!(verdict(&[], &[]), Verdict::NoOrigin);
    }

    #[test]
    fn pages_served_from_this_machine_are_admitted() {
        for origin in [
            "http://localhost:8000",
            "http://localhost",
            "https://localhost:8443",
            "http://127.0.0.1:5173",
            "http://[::1]:8090",
            "https://[0:0:0:0:0:0:0:1]",
            "HTTP://LocalHost:8000",
        ] {
            assert_eq!(verdict(&[origin], &[]), Verdict::Loopback, "{origin}");
        }
    }

    #[test]
    fn every_other_origin_is_refused_unless_allowed() {
        for origin in [
            "https://evil.example",
            "http://localhost.evil.example",
            "http://127.0.0.2:8000",
            "http://[::2]",
            "ftp://localhost",
            "chrome-extension://abcdefghijklmnop",
            "null",
            "http://localhost:8000/",
            "http://user@localhost:8000",
            "localhost:8000",
            "",
            "http://localhost:0",
            "http://localhost:65536",
        ] {
            assert!(
                !admitted(verdict(&[origin], &[])),
                "{origin} must be refused"
            );
        }
        assert!(!admitted(verdict(
            &["http://localhost", "http://localhost"],
            &[]
        )));
        assert!(!admitted(judge([&[0xff_u8, 0xfe][..]].into_iter(), &[])));
    }

    #[test]
    fn an_allowed_origin_is_admitted_in_any_spelling_a_browser_could_send() {
        let allowed = ["https://app.example", "http://intranet.lan:8080"];
        for origin in [
            "https://app.example",
            "https://APP.example:443",
            "http://intranet.lan:8080",
        ] {
            assert_eq!(verdict(&[origin], &allowed), Verdict::Allowed, "{origin}");
        }
        for origin in [
            "https://app.example:8443",
            "http://app.example",
            "https://sub.app.example",
            "http://intranet.lan",
        ] {
            assert!(!admitted(verdict(&[origin], &allowed)), "{origin}");
        }
    }

    #[test]
    fn an_allowed_origin_is_kept_in_the_form_browsers_send() {
        for (given, kept) in [
            ("https://Example.COM", "https://example.com"),
            ("https://example.com:443", "https://example.com"),
            ("http://example.com:80", "http://example.com"),
            ("http://example.com:08080", "http://example.com:8080"),
            ("wss://example.com:443", "wss://example.com"),
            ("chrome-extension://AbC", "chrome-extension://abc"),
            ("http://[0:0:0:0:0:0:0:1]:3000", "http://[::1]:3000"),
            ("tauri://localhost", "tauri://localhost"),
        ] {
            assert_eq!(
                AllowedOrigin::parse(given).unwrap().as_str(),
                kept,
                "{given}"
            );
        }
    }

    #[test]
    fn what_is_not_an_origin_cannot_be_allowed() {
        for text in [
            "null",
            "NULL",
            "example.com",
            "https://",
            "https://example.com/",
            "https://example.com/app",
            "https://example.com?x",
            "https://user@example.com",
            "https://exämple.com",
            "https://example.com:",
            "https://example.com:0",
            "https://example.com:99999",
            "https://[::1",
            "https://[not-an-address]",
            "https://[::1]x",
            "1https://example.com",
        ] {
            let error = AllowedOrigin::parse(text).unwrap_err();
            let message = error.to_string();
            assert!(
                message.contains("is not an origin") && message.contains("scheme://host[:port]"),
                "{text}: {message}"
            );
        }
    }
}
