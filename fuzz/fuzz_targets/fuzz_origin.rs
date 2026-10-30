// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//
// Fuzz target: the daemon's WebSocket `Origin` check,
// `mesh_hub::internals::judge`, and the parsing of the origins an operator
// allows with `--allow-origin`, `AllowedOrigin::parse`.
//
// The input draws an allow-list and the values of an upgrade's `Origin`
// headers (mostly one, now and then none or several): raw bytes, UTF-8 or
// not, or text assembled from parts, many of them look-alikes of the
// loopback origins (user information, trailing dots, percent-escapes,
// `localhost.evil`, `127.0.0.1.evil`, IPv4-mapped IPv6, other spellings of
// `[::1]`, upper case, embedded NUL and white space, overlong ports), and
// allowed origins respelled as a browser could send them, or nearly.
//
// The oracle is written from the specifications, not from origin.rs, and
// calls none of its helpers. An origin is RFC 6454's serialization,
// `scheme "://" host [ ":" port ]` (section 7.1), with RFC 3986's scheme
// (section 3.1), under the rules origin.rs documents: the scheme and a host
// name compare without regard to case; a host name is ASCII letters,
// digits, `-`, `.` and `_` (so no user information, percent-escape, path,
// query or white space); a host in brackets is an IPv6 address in the text
// forms of RFC 4291 section 2.2, read here, and compares by value; a port
// is one to five digits naming 1 to 65535, and 80 for `http` and `ws` or
// 443 for `https` and `wss` is the same origin as no port (RFC 6454
// section 6.2). A value holding a list of origins, which RFC 6454 section
// 7.1 allows, names no single page and is refused. A page served from this
// machine is `http` or `https` on the name `localhost`, the name
// `127.0.0.1` or the address `::1`: an IPv4 address is a name, compared as
// written, so `127.1` or `::ffff:127.0.0.1` is not loopback, which refuses
// only what a browser, which writes an IPv4 host in dotted decimal, never
// sends for a loopback page.
//
// Invariants:
// - an upgrade without an `Origin` is admitted as no origin, one with more
//   than one is refused, and one whose value is not UTF-8 or not an origin
//   is refused;
// - nothing is admitted whose `Origin` is not a loopback origin and not
//   the same origin as one on the allow-list;
// - every verdict is the oracle's: no origin, loopback, allowed or refused;
// - `AllowedOrigin::parse` (and `FromStr`) accepts exactly the texts that
//   are origins, and keeps one re-serialized: the scheme and a host name in
//   lower case, the default port dropped, an IPv6 address in the canonical
//   text of RFC 5952 section 4, or, for an IPv4-mapped address, the mixed
//   notation of its section 5; that text parses back to the same origin
//   and the same `AllowedOrigin`; a refusal says what an origin is;
// - nothing panics.

#![no_main]

use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use mesh_hub::internals::{judge, Verdict};
use mesh_hub::AllowedOrigin;
use pulse_mesh_fuzz::{rarely, take};

/// Most entries in an allow-list.
const MAX_ALLOWED: usize = 4;
/// Most `Origin` headers on one upgrade.
const MAX_HEADERS: usize = 3;
/// The address `::1`.
const LOOPBACK_V6: [u16; 8] = [0, 0, 0, 0, 0, 0, 0, 1];

/// Schemes a browser sends for a page, most of the time.
const SCHEMES: &[&str] = &[
    "http",
    "https",
    "ws",
    "wss",
    "HTTP",
    "Https",
    "hTtP",
    "WSS",
    "ftp",
    "chrome-extension",
    "tauri",
];
/// Schemes, and texts in their place, that are odd or not schemes.
const ODD_SCHEMES: &[&str] = &[
    "",
    "h",
    "x-y.z+w",
    "1http",
    "-http",
    " http",
    "http ",
    "ht tp",
    "http\0",
    "null",
    "NULL",
    "file",
    "about",
    "blob:http",
    "http:",
    "https:/",
    "\u{0445}ttp",
];
/// What may stand between the scheme and the host.
const SEPARATORS: &[&str] = &[
    "://", ":/", ":///", "//", ":", "", ":\\\\", "://\\", ": //", "::/",
];
/// User information, which no origin carries.
const USERINFO: &[&str] = &[
    "@",
    "user@",
    "user:pass@",
    "localhost@",
    "127.0.0.1@",
    "[::1]@",
    "evil.example@",
    ":@",
    "%40",
];
/// Hosts: the loopback ones, their look-alikes, and others.
const HOSTS: &[&str] = &[
    "localhost",
    "LOCALHOST",
    "LocalHost",
    "127.0.0.1",
    "[::1]",
    "localhost.",
    "localhost..",
    ".localhost",
    "localhost.evil",
    "localhost.evil.example",
    "evil.localhost",
    "localhost-evil",
    "localhost_",
    "localhos",
    "localhostt",
    "xn--localhost",
    "127.0.0.1.",
    "127.0.0.1.evil",
    "127.0.0.1.nip.io",
    "127.1",
    "127.0.1",
    "127.0.0.01",
    "0177.0.0.1",
    "0x7f.0.0.1",
    "0x7f000001",
    "2130706433",
    "127.0.0.2",
    "0.0.0.0",
    "0",
    "[0:0:0:0:0:0:0:1]",
    "[::0001]",
    "[0::1]",
    "[::0:1]",
    "[::0.0.0.1]",
    "[0:0:0:0:0:0:0.0.0.1]",
    "[::ffff:127.0.0.1]",
    "[::ffff:7f00:1]",
    "[::127.0.0.1]",
    "[::1%25lo0]",
    "[::1%lo0]",
    "[fe80::1]",
    "[::2]",
    "[::]",
    "[::1:0]",
    "[1::]",
    "[::1",
    "::1]",
    "::1",
    "[[::1]]",
    "[::1]]",
    "[ ::1]",
    "[::1 ]",
    "[::1]x",
    "[::1].evil",
    "[v1.x]",
    "[]",
    "%6cocalhost",
    "local%68ost",
    "localhost%2eevil",
    "localhost%00",
    "%31%32%37.0.0.1",
    "localhost\0",
    "localhost\0.evil",
    "local\0host",
    "local host",
    " localhost",
    "localhost ",
    "localhost\t",
    "localhost\r\n",
    "l\u{043e}calhost",
    "\u{ff4c}ocalhost",
    "localhost\u{200b}",
    "example.com",
    "EXAMPLE.com",
    "app.example",
    "intranet.lan",
    "a_b.test",
    "-",
    ".",
    "_",
];
/// Labels a host name is assembled from.
const LABELS: &[&str] = &[
    "localhost",
    "LOCALHOST",
    "127",
    "0",
    "1",
    "evil",
    "example",
    "com",
    "xn--nxasmq6b",
    "a-b",
    "a_b",
    "",
];
/// Port numbers, valid or not, worth drawing often.
const COMMON_PORTS: &[u32] = &[80, 443, 8000, 8080, 0, 1, 65535, 65536];
/// Ports, and texts in their place, beyond plain numbers.
const ODD_PORTS: &[&str] = &[
    ":",
    "::80",
    ":+80",
    ":-1",
    ": 80",
    ":80 ",
    ":0x50",
    ":\u{ff18}\u{ff10}",
    ":80:80",
    ":80/",
    ":80\0",
    ":8e1",
    ":000080",
    ":0000080",
    ":65536",
    ":99999",
    ":100000",
    ":4294967376",
];
/// What may follow an origin, making it not one.
const SUFFIXES: &[&str] = &[
    "/",
    "/x",
    "?",
    "?q",
    "#",
    "#f",
    " ",
    "\0",
    "\r\n",
    ".",
    ":",
    " http://localhost",
    ",http://localhost",
    "/..",
    "\\",
];

fuzz_target!(|data: &[u8]| {
    let _ = fuzz(data);
});

fn fuzz(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    // The operator's allow-list: the entries `AllowedOrigin::parse` takes.
    let mut texts = Vec::new();
    let mut allowed = Vec::new();
    let mut spec_allowed = Vec::new();
    for _ in 0..u.int_in_range(0..=MAX_ALLOWED)? {
        let text = text(&mut u)?;
        if let Some((entry, origin)) = check_parse(&text) {
            allowed.push(entry);
            spec_allowed.push(origin);
        }
        texts.push(text);
    }
    // Mostly one header, which an input that has run out takes.
    let count = match u.int_in_range(0..=15u8)? {
        14 => 0,
        15 => u.int_in_range(2..=MAX_HEADERS)?,
        _ => 1,
    };
    let mut headers = Vec::with_capacity(count);
    for _ in 0..count {
        headers.push(header(&mut u, &spec_allowed)?);
    }

    let got = judge(headers.iter().map(Vec::as_slice), &allowed);
    let want = expect(&headers, &spec_allowed);
    let shown: Vec<_> = headers.iter().map(|h| String::from_utf8_lossy(h)).collect();
    if !matches!(got, Verdict::Refused(_)) && !headers.is_empty() {
        assert!(
            matches!(want, Expect::Loopback | Expect::Allowed),
            "{shown:?} was admitted ({got:?}) with the allow-list {texts:?}, \
             though it is not a loopback origin and not an allowed one"
        );
    }
    assert_eq!(
        Expect::of(got),
        want,
        "the verdict on {shown:?} with the allow-list {texts:?} ({got:?})"
    );
    if let Verdict::Refused(reason) = got {
        assert!(!reason.is_empty(), "a refusal gives no reason");
    }
    for value in &headers {
        if let Ok(text) = std::str::from_utf8(value) {
            check_parse(text);
        }
    }
    Ok(())
}

/// What the oracle says of an upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    NoOrigin,
    Loopback,
    Allowed,
    Refused,
}

impl Expect {
    fn of(verdict: Verdict) -> Self {
        match verdict {
            Verdict::NoOrigin => Self::NoOrigin,
            Verdict::Loopback => Self::Loopback,
            Verdict::Allowed => Self::Allowed,
            Verdict::Refused(_) => Self::Refused,
        }
    }
}

/// The oracle's verdict on the values of an upgrade's `Origin` headers,
/// against the origins an operator allowed.
fn expect(headers: &[Vec<u8>], allowed: &[Origin]) -> Expect {
    match headers {
        [] => Expect::NoOrigin,
        [value] => match std::str::from_utf8(value).ok().and_then(origin) {
            None => Expect::Refused,
            Some(o) if is_loopback(&o) => Expect::Loopback,
            Some(o) if allowed.contains(&o) => Expect::Allowed,
            Some(_) => Expect::Refused,
        },
        _ => Expect::Refused,
    }
}

/// `AllowedOrigin::parse` of `text`, judged by the oracle: the entry and
/// the origin the oracle reads, when `text` is an origin.
fn check_parse(text: &str) -> Option<(AllowedOrigin, Origin)> {
    let got = AllowedOrigin::parse(text);
    assert_eq!(
        text.parse::<AllowedOrigin>(),
        got,
        "FromStr and parse disagree on {text:?}"
    );
    match (got, origin(text)) {
        (Ok(entry), Some(want)) => {
            let form = entry.as_str();
            assert!(
                is_serialization(form, &want),
                "{text:?} is kept as {form:?}, which is not {want:?} re-serialized"
            );
            assert_eq!(entry.to_string(), form, "Display is not as_str");
            assert_eq!(
                AllowedOrigin::parse(form).as_ref(),
                Ok(&entry),
                "{form:?}, kept for {text:?}, does not parse back to itself"
            );
            assert_eq!(
                origin(form).as_ref(),
                Some(&want),
                "{form:?}, kept for {text:?}, is another origin"
            );
            Some((entry, want))
        }
        (Err(error), None) => {
            let message = error.to_string();
            assert!(
                message.contains("is not an origin") && message.contains("scheme://host[:port]"),
                "the refusal of {text:?} does not say what an origin is: {message}"
            );
            None
        }
        (got, want) => {
            panic!("AllowedOrigin::parse({text:?}) gave {got:?}; the oracle reads {want:?}")
        }
    }
}

// ---------------------------------------------------------------------------
// The oracle.

/// A host as the oracle reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Host {
    /// A name, in lower case.
    Name(String),
    /// An IPv6 address, by value.
    V6([u16; 8]),
}

/// An origin as the oracle reads it: the scheme in lower case, the host,
/// and the port unless it is the scheme's default.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Origin {
    scheme: String,
    host: Host,
    port: Option<u16>,
}

/// The default port of a scheme whose origins drop it.
fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        _ => None,
    }
}

/// A page served from this machine: `http` or `https` on the name
/// `localhost`, the name `127.0.0.1` or the address `::1`, at any port.
fn is_loopback(o: &Origin) -> bool {
    matches!(o.scheme.as_str(), "http" | "https")
        && match &o.host {
            Host::Name(name) => name == "localhost" || name == "127.0.0.1",
            Host::V6(address) => *address == LOOPBACK_V6,
        }
}

/// `text` read as `scheme "://" host [ ":" port ]`, or `None`.
fn origin(text: &str) -> Option<Origin> {
    // scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
    let scheme_len = text
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        .count();
    if !text.bytes().next()?.is_ascii_alphabetic() {
        return None;
    }
    let rest = text[scheme_len..].strip_prefix("://")?;
    let (host, rest) = match rest.strip_prefix('[') {
        Some(inner) => {
            let close = inner.find(']')?;
            (Host::V6(ipv6(&inner[..close])?), &inner[close + 1..])
        }
        None => {
            let len = rest
                .bytes()
                .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
                .count();
            if len == 0 {
                return None;
            }
            (Host::Name(rest[..len].to_ascii_lowercase()), &rest[len..])
        }
    };
    let port = if rest.is_empty() {
        None
    } else {
        let digits = rest.strip_prefix(':')?;
        if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let value = digits
            .bytes()
            .fold(0u32, |n, d| n * 10 + u32::from(d - b'0'));
        Some(u16::try_from(value).ok().filter(|&p| p != 0)?)
    };
    let scheme = text[..scheme_len].to_ascii_lowercase();
    let port = port.filter(|&p| Some(p) != default_port(&scheme));
    Some(Origin { scheme, host, port })
}

/// An IPv6 address in the text forms of RFC 4291 section 2.2 (RFC 3986's
/// `IPv6address`): eight groups of one to four hex digits, one run of one
/// or more zero groups written `::`, the last two groups possibly written
/// as a dotted-decimal IPv4 address; or `None`.
fn ipv6(text: &str) -> Option<[u16; 8]> {
    let mut address = [0u16; 8];
    match text.find("::") {
        None => {
            let groups = groups(text, true)?;
            if groups.len() != 8 {
                return None;
            }
            address.copy_from_slice(&groups);
        }
        Some(at) => {
            let head = groups(&text[..at], false)?;
            let tail = groups(&text[at + 2..], true)?;
            // `::` stands for at least one group.
            if head.len() + tail.len() > 7 {
                return None;
            }
            address[..head.len()].copy_from_slice(&head);
            address[8 - tail.len()..].copy_from_slice(&tail);
        }
    }
    Some(address)
}

/// The groups of one side of `::`, or of a whole address: groups of one to
/// four hex digits separated by `:`, the last of them possibly an IPv4
/// address when this side ends the address; none for an empty side.
fn groups(text: &str, ends: bool) -> Option<Vec<u16>> {
    if text.is_empty() {
        return Some(Vec::new());
    }
    let pieces: Vec<&str> = text.split(':').collect();
    let mut groups = Vec::new();
    for (i, piece) in pieces.iter().enumerate() {
        if ends && i + 1 == pieces.len() && piece.contains('.') {
            let [a, b, c, d] = ipv4(piece)?;
            groups.push(u16::from_be_bytes([a, b]));
            groups.push(u16::from_be_bytes([c, d]));
        } else {
            if piece.is_empty() || piece.len() > 4 {
                return None;
            }
            let mut group = 0u16;
            for digit in piece.chars() {
                group = group * 16 + u16::try_from(digit.to_digit(16)?).ok()?;
            }
            groups.push(group);
        }
    }
    Some(groups)
}

/// RFC 3986's `IPv4address`: four decimal octets of 0 to 255, none with a
/// leading zero.
fn ipv4(text: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = text.split('.').collect();
    let mut octets = [0u8; 4];
    if parts.len() != 4 {
        return None;
    }
    for (octet, part) in octets.iter_mut().zip(parts) {
        let digits_ok = !part.is_empty()
            && part.len() <= 3
            && part.bytes().all(|b| b.is_ascii_digit())
            && !(part.len() > 1 && part.starts_with('0'));
        if !digits_ok {
            return None;
        }
        let value = part.bytes().fold(0u32, |n, d| n * 10 + u32::from(d - b'0'));
        *octet = u8::try_from(value).ok()?;
    }
    Some(octets)
}

/// Whether `form` is `o` re-serialized: `scheme "://" host [ ":" port ]`
/// with the scheme and a name as the oracle keeps them, an IPv6 address in
/// RFC 5952's canonical text (or the mixed notation of its section 5, for
/// an IPv4-mapped address) and the port when it is not the default.
fn is_serialization(form: &str, o: &Origin) -> bool {
    let port = o.port.map(|p| format!(":{p}")).unwrap_or_default();
    let hosts = match &o.host {
        Host::Name(name) => vec![name.clone()],
        Host::V6(v) => {
            let mut hosts = vec![format!("[{}]", rfc5952(v))];
            if v[..6] == [0, 0, 0, 0, 0, 0xffff] {
                let [a, b] = v[6].to_be_bytes();
                let [c, d] = v[7].to_be_bytes();
                hosts.push(format!("[::ffff:{a}.{b}.{c}.{d}]"));
            }
            hosts
        }
    };
    hosts
        .iter()
        .any(|host| form == format!("{}://{host}{port}", o.scheme))
}

/// RFC 5952 section 4's text of an address: groups in lower-case hex
/// without leading zeros, the longest run of two or more zero groups (the
/// first of equal runs) written `::`.
fn rfc5952(v: &[u16; 8]) -> String {
    let (mut best, mut best_len) = (0, 0);
    let (mut start, mut len) = (0, 0);
    for (i, &group) in v.iter().enumerate() {
        if group != 0 {
            len = 0;
            continue;
        }
        if len == 0 {
            start = i;
        }
        len += 1;
        if len > best_len {
            (best, best_len) = (start, len);
        }
    }
    let hex = |groups: &[u16]| {
        groups
            .iter()
            .map(|g| format!("{g:x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    if best_len < 2 {
        hex(v)
    } else {
        format!("{}::{}", hex(&v[..best]), hex(&v[best + best_len..]))
    }
}

// ---------------------------------------------------------------------------
// The input.

/// One `Origin` value: raw bytes, text assembled from parts, or an allowed
/// origin respelled, or nearly.
fn header(u: &mut Unstructured<'_>, allowed: &[Origin]) -> Result<Vec<u8>> {
    Ok(match u.int_in_range(0..=7u8)? {
        1 | 2 if !allowed.is_empty() => {
            let o = &allowed[u.choose_index(allowed.len())?];
            respell(u, o)?.into_bytes()
        }
        3 => take(u, 64)?.to_vec(),
        _ => text(u)?.into_bytes(),
    })
}

/// Text for an origin: now and then arbitrary, otherwise a scheme, a
/// separator, now and then user information, a host, a port and a suffix,
/// mostly well formed and often a look-alike, in cases the input chooses.
fn text(u: &mut Unstructured<'_>) -> Result<String> {
    if rarely(u, 8)? {
        return Ok(u.arbitrary::<&str>()?.to_owned());
    }
    let mut s = String::new();
    s.push_str(match u.int_in_range(0..=15u8)? {
        14 => *u.choose(ODD_SCHEMES)?,
        15 => u.arbitrary::<&str>()?,
        _ => *u.choose(SCHEMES)?,
    });
    s.push_str(if rarely(u, 16)? {
        *u.choose(SEPARATORS)?
    } else {
        "://"
    });
    if rarely(u, 8)? {
        s.push_str(*u.choose(USERINFO)?);
    }
    s.push_str(&host(u)?);
    match u.int_in_range(0..=5u8)? {
        3 | 4 => s.push_str(&number_port(u)?),
        5 => s.push_str(*u.choose(ODD_PORTS)?),
        _ => {}
    }
    if rarely(u, 8)? {
        s.push_str(*u.choose(SUFFIXES)?);
    }
    if rarely(u, 4)? {
        recase(u, &mut s)?;
    }
    Ok(s)
}

/// A host: a look-alike, an IPv6 address in some spelling, a name made of
/// labels, or anything.
fn host(u: &mut Unstructured<'_>) -> Result<String> {
    Ok(match u.int_in_range(0..=7u8)? {
        4 | 5 => {
            let v = v6_value(u)?;
            format!("[{}]", spell_v6(u, v)?)
        }
        6 => {
            let mut labels = Vec::new();
            for _ in 0..u.int_in_range(1..=3)? {
                labels.push(*u.choose(LABELS)?);
            }
            labels.join(".")
        }
        7 => u.arbitrary::<&str>()?.to_owned(),
        _ => (*u.choose(HOSTS)?).to_owned(),
    })
}

/// `:` and a number, with leading zeros now and then.
fn number_port(u: &mut Unstructured<'_>) -> Result<String> {
    let n: u32 = if u.ratio(1, 2)? {
        *u.choose(COMMON_PORTS)?
    } else {
        u.int_in_range(0..=99_999)?
    };
    let zeros = if rarely(u, 4)? {
        u.int_in_range(1..=3)?
    } else {
        0
    };
    Ok(format!(":{}{n}", "0".repeat(zeros)))
}

/// An IPv6 address: `::1`, loopback look-alikes, or groups the input
/// chooses, half of them zero.
fn v6_value(u: &mut Unstructured<'_>) -> Result<[u16; 8]> {
    Ok(match u.int_in_range(0..=7u8)? {
        0 | 1 => LOOPBACK_V6,
        2 => [0, 0, 0, 0, 0, 0xffff, 0x7f00, 1],
        3 => [0; 8],
        4 => [0, 0, 0, 0, 0, 0, 0x7f00, 1],
        _ => {
            let mut v = [0u16; 8];
            for group in &mut v {
                if u.ratio(1, 2)? {
                    *group = u.arbitrary()?;
                }
            }
            v
        }
    })
}

/// `v` in a spelling the input chooses: leading zeros and upper case in
/// any group, any run of zero groups (not only the longest) written `::`,
/// the last two groups as an IPv4 address; and now and then broken.
fn spell_v6(u: &mut Unstructured<'_>, v: [u16; 8]) -> Result<String> {
    let dotted = rarely(u, 4)?;
    let n = if dotted { 6 } else { 8 };
    let mut groups = Vec::with_capacity(n);
    for &group in &v[..n] {
        let mut hex = format!("{group:x}");
        if rarely(u, 4)? {
            let width = u.int_in_range(hex.len()..=4)?;
            hex = format!("{group:0width$x}");
        }
        if rarely(u, 4)? {
            hex = hex.to_ascii_uppercase();
        }
        groups.push(hex);
    }
    let mut runs = Vec::new();
    let mut i = 0;
    while i < n {
        if v[i] == 0 {
            let start = i;
            while i < n && v[i] == 0 {
                i += 1;
            }
            let len = u.int_in_range(1..=i - start)?;
            runs.push((start, len));
        } else {
            i += 1;
        }
    }
    let mut s = if runs.is_empty() || rarely(u, 3)? {
        groups.join(":")
    } else {
        let (start, len) = runs[u.choose_index(runs.len())?];
        format!(
            "{}::{}",
            groups[..start].join(":"),
            groups[start + len..].join(":")
        )
    };
    if dotted {
        let [a, b] = v[6].to_be_bytes();
        let [c, d] = v[7].to_be_bytes();
        if !s.ends_with(':') {
            s.push(':');
        }
        s.push_str(&format!("{a}.{b}.{c}.{d}"));
    }
    if rarely(u, 6)? {
        match u.int_in_range(0..=6u8)? {
            0 => s.insert_str(0, "1:"),
            1 => s.push_str(":1"),
            2 => s = s.replacen("::", ":::", 1),
            3 => s.push_str("%25lo0"),
            4 => s.insert(0, '0'),
            5 => s = s.replacen('.', ".0", 1),
            _ => s = s.replacen("::", "::0:", 1),
        }
    }
    Ok(s)
}

/// An allowed origin as a browser could spell it, or nearly: the scheme
/// and host in any case, the default port written out, leading zeros in
/// the port, an IPv6 address in another spelling; now and then one change
/// that makes it another origin, or not an origin.
fn respell(u: &mut Unstructured<'_>, o: &Origin) -> Result<String> {
    let mut scheme = o.scheme.clone();
    let mut host = match &o.host {
        Host::Name(name) => name.clone(),
        Host::V6(v) => format!("[{}]", spell_v6(u, *v)?),
    };
    let written = match o.port {
        Some(port) => Some(port),
        None if u.ratio(1, 3)? => default_port(&o.scheme),
        None => None,
    };
    let mut port = match written {
        Some(port) => {
            let zeros = if rarely(u, 3)? {
                u.int_in_range(1..=2)?
            } else {
                0
            };
            format!(":{}{port}", "0".repeat(zeros))
        }
        None => String::new(),
    };
    if rarely(u, 3)? {
        match u.int_in_range(0..=6u8)? {
            0 => host.push('.'),
            1 => host.insert_str(0, "a."),
            2 => host.push_str(".evil"),
            3 => port = format!(":{}", o.port.unwrap_or(80).wrapping_add(1)),
            4 => {
                scheme = match scheme.as_str() {
                    "http" => "https".to_owned(),
                    "https" => "http".to_owned(),
                    "ws" => "http".to_owned(),
                    other => format!("{other}s"),
                }
            }
            5 => host.insert_str(0, "user@"),
            _ => port.push('/'),
        }
    }
    let mut s = format!("{scheme}://{host}{port}");
    if rarely(u, 2)? {
        recase(u, &mut s)?;
    }
    Ok(s)
}

/// Swap the case of the ASCII letters the input picks.
fn recase(u: &mut Unstructured<'_>, s: &mut String) -> Result<()> {
    let mut bytes = std::mem::take(s).into_bytes();
    for b in &mut bytes {
        if b.is_ascii_alphabetic() && u.ratio(1, 3)? {
            *b ^= 0x20;
        }
    }
    *s = String::from_utf8(bytes).expect("swapping the case of ASCII letters keeps UTF-8");
    Ok(())
}
