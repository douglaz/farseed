//! A bounded stub resolver, using only the configured numeric DNS endpoint. A and
//! AAAA are queried afresh; truncation and unsupported answers fail closed.
use crate::{BoxFuture, Resolver};
use std::{
    io,
    net::{IpAddr, SocketAddr},
};
use tokio::net::UdpSocket;

pub struct Dns {
    pub server: SocketAddr,
}
fn invalid() -> io::Error {
    io::Error::other("DNS response refused")
}
fn number(packet: &[u8], pos: &mut usize) -> io::Result<u16> {
    let b = packet.get(*pos..*pos + 2).ok_or_else(invalid)?;
    *pos += 2;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}
fn name(packet: &[u8], pos: &mut usize) -> io::Result<String> {
    let mut cursor = *pos;
    let mut jumped = false;
    let mut labels = Vec::new();
    for _ in 0..crate::PocLimits::DNS_POINTER_STEPS {
        let len = *packet.get(cursor).ok_or_else(invalid)? as usize;
        cursor += 1;
        if len & 0xc0 == 0xc0 {
            let low = *packet.get(cursor).ok_or_else(invalid)? as usize;
            cursor += 1;
            if !jumped {
                *pos = cursor;
                jumped = true;
            }
            cursor = ((len & 63) << 8) | low;
        } else if len == 0 {
            if !jumped {
                *pos = cursor;
            }
            let host = labels.join(".");
            if host.len() > 253 {
                return Err(invalid());
            }
            return Ok(host);
        } else {
            if len > 63 {
                return Err(invalid());
            }
            let label = packet.get(cursor..cursor + len).ok_or_else(invalid)?;
            labels.push(
                std::str::from_utf8(label)
                    .map_err(|_| invalid())?
                    .to_ascii_lowercase(),
            );
            cursor += len;
        }
    }
    Err(invalid())
}
impl Dns {
    async fn query(&self, host: &str, kind: u16) -> io::Result<Vec<IpAddr>> {
        let mut id = [0; 2];
        getrandom::fill(&mut id).map_err(|_| invalid())?;
        let mut query = vec![id[0], id[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in host.split('.') {
            query.push(label.len() as u8);
            query.extend(label.as_bytes());
        }
        query.push(0);
        query.extend(kind.to_be_bytes());
        query.extend(1u16.to_be_bytes());
        let bind = if self.server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(self.server).await?;
        socket.send(&query).await?;
        let mut buf = [0; crate::PocLimits::DNS_PACKET];
        let n = socket.recv(&mut buf).await?;
        Self::answer(&buf[..n], id, host, kind)
    }
    fn answer(packet: &[u8], id: [u8; 2], host: &str, kind: u16) -> io::Result<Vec<IpAddr>> {
        let mut pos = 0;
        if number(packet, &mut pos)? != u16::from_be_bytes(id) {
            return Err(invalid());
        }
        let flags = number(packet, &mut pos)?;
        if flags & 0xfa0f != 0x8000 || number(packet, &mut pos)? != 1 {
            return Err(invalid());
        }
        let count = number(packet, &mut pos)?;
        if count > crate::PocLimits::DNS_ANSWERS {
            return Err(invalid());
        }
        number(packet, &mut pos)?;
        number(packet, &mut pos)?;
        if name(packet, &mut pos)? != host
            || number(packet, &mut pos)? != kind
            || number(packet, &mut pos)? != 1
        {
            return Err(invalid());
        }
        let mut addresses = Vec::new();
        let mut aliases = Vec::new();
        for _ in 0..count {
            let owner = name(packet, &mut pos)?;
            let typ = number(packet, &mut pos)?;
            let class = number(packet, &mut pos)?;
            pos += 4; // TTL: answers are never cached.
            let len = number(packet, &mut pos)? as usize;
            let end = pos.checked_add(len).ok_or_else(invalid)?;
            let data = packet.get(pos..end).ok_or_else(invalid)?;
            if class != 1 {
                return Err(invalid());
            }
            match (typ, len) {
                (1, 4) => addresses.push((
                    owner,
                    IpAddr::from(<[u8; 4]>::try_from(data).map_err(|_| invalid())?),
                )),
                (28, 16) => addresses.push((
                    owner,
                    IpAddr::from(<[u8; 16]>::try_from(data).map_err(|_| invalid())?),
                )),
                (5, _) => {
                    let target = name(packet, &mut pos)?;
                    if pos != end {
                        return Err(invalid());
                    }
                    aliases.push((owner, target));
                }
                _ => return Err(invalid()),
            }
            pos = end;
        }
        let mut allowed = vec![host.to_string()];
        for _ in 0..aliases.len() {
            for (from, to) in &aliases {
                if allowed.contains(from) && !allowed.contains(to) {
                    allowed.push(to.clone());
                }
            }
        }
        if addresses.iter().any(|(owner, _)| !allowed.contains(owner)) {
            return Err(invalid());
        }
        Ok(addresses.into_iter().map(|(_, ip)| ip).collect())
    }
}
impl Resolver for Dns {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            tokio::time::timeout(crate::PocLimits::DNS, async {
                let mut ips = self.query(host, 1).await?;
                ips.extend(self.query(host, 28).await?);
                Ok(ips)
            })
            .await
            .map_err(|_| invalid())?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn packet() -> Vec<u8> {
        let mut p = vec![1, 2, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        p.extend([1, b'a', 0, 0, 1, 0, 1]);
        p.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 8, 8, 8, 8]);
        p
    }
    #[test]
    fn bounded_dns_response_parser_fails_closed() {
        let p = packet();
        assert_eq!(
            Dns::answer(&p, [1, 2], "a", 1).unwrap(),
            vec!["8.8.8.8".parse::<IpAddr>().unwrap()]
        );
        for length in 0..p.len() {
            assert!(Dns::answer(&p[..length], [1, 2], "a", 1).is_err());
        }
        assert!(Dns::answer(&p, [1, 3], "a", 1).is_err());
        assert!(Dns::answer(&p, [1, 2], "b", 1).is_err());
        assert!(Dns::answer(&p, [1, 2], "a", 28).is_err());
        for flags in [0x83, 0x89, 0x01] {
            let mut p = packet();
            p[2] = flags;
            assert!(Dns::answer(&p, [1, 2], "a", 1).is_err());
        }
        let mut p = packet();
        p[3] = 0x83;
        assert!(Dns::answer(&p, [1, 2], "a", 1).is_err());
        let mut p = packet();
        p[12] = 0xc0;
        p[13] = 12;
        assert!(Dns::answer(&p, [1, 2], "a", 1).is_err());
        let mut p = packet();
        p[13] = b'b';
        assert!(Dns::answer(&p, [1, 2], "a", 1).is_err());
    }
}
