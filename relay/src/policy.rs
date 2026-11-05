use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    pub host: String,
    pub port: u16,
}

pub fn host_valid(host: &str) -> bool {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip.to_string() == host;
    }
    if host.is_empty() || host.len() > 253 || !host.is_ascii() || host.contains(':') {
        return false;
    }
    let labels: Vec<_> = host.split('.').collect();
    // Reject legacy inet_aton forms, including hexadecimal and shortened IPv4.
    if labels
        .iter()
        .all(|s| s.bytes().all(|b| b.is_ascii_digit()) || s.starts_with("0x"))
    {
        return false;
    }
    if labels.iter().any(|s| {
        s.is_empty()
            || s.len() > 63
            || s.starts_with('-')
            || s.ends_with('-')
            || !s
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    }) {
        return false;
    }
    idna::domain_to_ascii_strict(host).is_ok_and(|s| s == host)
}

pub fn destination(path: &str) -> Option<Destination> {
    let parts: Vec<_> = path.strip_prefix("/v1/tcp/")?.split('/').collect();
    if parts.len() != 2
        || !host_valid(parts[0])
        || parts[1].starts_with('0')
        || parts[1].is_empty()
        || !parts[1].bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let port = parts[1].parse::<u16>().ok().filter(|p| *p != 0)?;
    Some(Destination {
        host: parts[0].to_owned(),
        port,
    })
}

// IANA IPv4/IPv6 Special-Purpose Address Registries, both Last Updated 2025-10-09:
// https://www.iana.org/assignments/iana-ipv4-special-registry/
// https://www.iana.org/assignments/iana-ipv6-special-registry/
// Every special-purpose row is denied, even when globally reachable. Nested rows are
// subsumed by their parent prefix. Changes require review; no runtime refresh.
pub const V4_DENY: &[(u32, u32)] = &[
    (0x00000000, 8),
    (0x0a000000, 8),
    (0x64400000, 10),
    (0x7f000000, 8),
    (0xa9fe0000, 16),
    (0xac100000, 12),
    (0xc0000000, 24),
    (0xc0000200, 24),
    (0xc01fc400, 24),
    (0xc034c100, 24),
    (0xc0586300, 24),
    (0xc0a80000, 16),
    (0xc0af3000, 24),
    (0xc6120000, 15),
    (0xc6336400, 24),
    (0xcb007100, 24),
    (0xe0000000, 4),
    (0xf0000000, 4),
];
pub const V6_DENY: &[(u128, u32)] = &[
    (0x2001_0000_0000_0000_0000_0000_0000_0000, 23),
    (0x2001_0db8_0000_0000_0000_0000_0000_0000, 32),
    (0x2002_0000_0000_0000_0000_0000_0000_0000, 16),
    (0x2620_004f_8000_0000_0000_0000_0000_0000, 48),
    (0x3fff_0000_0000_0000_0000_0000_0000_0000, 20),
];

#[derive(Clone, Default)]
pub struct Policy {
    own: HashSet<IpAddr>,
}
impl Policy {
    pub fn new(own: impl IntoIterator<Item = IpAddr>) -> Self {
        Self {
            own: own.into_iter().collect(),
        }
    }
    pub fn admits(&self, ip: IpAddr) -> bool {
        if self.own.contains(&ip) {
            return false;
        }
        match ip {
            IpAddr::V4(ip) => {
                let n = u32::from(ip);
                !V4_DENY
                    .iter()
                    .any(|(base, bits)| n >> (32 - bits) == base >> (32 - bits))
            }
            IpAddr::V6(ip) => {
                let n = u128::from(ip);
                // All remaining registry ranges (mapped, translation, discard, ULA,
                // link-local), multicast and unknown allocations are outside 2000::/3.
                n >> 125 == 1
                    && !V6_DENY
                        .iter()
                        .any(|(base, bits)| n >> (128 - bits) == base >> (128 - bits))
            }
        }
    }
    pub fn select(&self, ips: &[IpAddr], port: u16) -> Option<SocketAddr> {
        if ips.is_empty() || ips.iter().any(|ip| !self.admits(*ip)) {
            return None;
        }
        Some(SocketAddr::new(ips[0], port))
    }
}

/// Enumerate every interface, not merely the address used by the default route.
/// getifaddrs is part of the target's C runtime; there is no C build dependency.
pub fn interfaces() -> std::io::Result<Vec<IpAddr>> {
    let mut first = std::ptr::null_mut();
    // SAFETY: getifaddrs initializes first on success; the list remains owned until freeifaddrs.
    unsafe {
        if libc::getifaddrs(&mut first) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut cursor = first;
        let mut ips = Vec::new();
        while !cursor.is_null() {
            let addr = (*cursor).ifa_addr;
            if !addr.is_null() {
                match (*addr).sa_family as i32 {
                    libc::AF_INET => {
                        let a = &*addr.cast::<libc::sockaddr_in>();
                        ips.push(IpAddr::V4(Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes())));
                    }
                    libc::AF_INET6 => {
                        let a = &*addr.cast::<libc::sockaddr_in6>();
                        ips.push(IpAddr::V6(a.sin6_addr.s6_addr.into()));
                    }
                    _ => {}
                }
            }
            cursor = (*cursor).ifa_next;
        }
        libc::freeifaddrs(first);
        if ips.is_empty() {
            return Err(std::io::Error::other("empty interface inventory"));
        }
        Ok(ips)
    }
}
