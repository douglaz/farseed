//! Bounded BOLT11 field decoder. This deliberately does not verify/recover the signature.
use super::REFUSED;

const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Invoice {
    pub order: u64,
    pub payment_hash: String,
    pub amount_msat: u64,
    pub timestamp: u64,
    pub expires: u64,
}

fn step(check: u32, value: u8) -> u32 {
    let top = check >> 25;
    let mut next = ((check & 0x1ffffff) << 5) ^ u32::from(value);
    for (i, generator) in [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        .iter()
        .enumerate()
    {
        if (top >> i) & 1 != 0 {
            next ^= generator;
        }
    }
    next
}
fn integer(words: &[u8]) -> Result<u64, String> {
    if words.is_empty() || words.len() > 13 {
        return Err(REFUSED.into());
    }
    words.iter().try_fold(0u64, |n, v| {
        n.checked_mul(32)
            .and_then(|n| n.checked_add(u64::from(*v)))
            .ok_or_else(|| REFUSED.into())
    })
}
fn bytes(words: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(words.len() * 5 / 8);
    let mut acc = 0u32;
    let mut bits = 0;
    for word in words {
        acc = ((acc << 5) | u32::from(*word)) & 0xffff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits >= 5 || (acc & ((1 << bits) - 1)) != 0 {
        return Err(REFUSED.into());
    }
    Ok(out)
}

pub(crate) fn decode(invoice: &str) -> Result<Invoice, String> {
    // BOLT11 explicitly permits more than Bech32's ordinary 90 characters.
    if !(120..=4096).contains(&invoice.len())
        || !invoice.is_ascii()
        || (invoice.bytes().any(|b| b.is_ascii_lowercase())
            && invoice.bytes().any(|b| b.is_ascii_uppercase()))
    {
        return Err(REFUSED.into());
    }
    let lower = zeroize::Zeroizing::new(invoice.to_ascii_lowercase());
    let (hrp, data) = lower.rsplit_once('1').ok_or(REFUSED)?;
    let amount = hrp.strip_prefix("lnbc").ok_or(REFUSED)?;
    let (digits, multiplier) = match amount.as_bytes().last() {
        Some(b'm') => (&amount[..amount.len() - 1], 100_000_000u64),
        Some(b'u') => (&amount[..amount.len() - 1], 100_000u64),
        Some(b'n') => (&amount[..amount.len() - 1], 100u64),
        Some(b'p') => (&amount[..amount.len() - 1], 0u64),
        _ => (amount, 100_000_000_000u64),
    };
    if digits.is_empty()
        || digits.len() > 20
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || digits.starts_with('0')
    {
        return Err(REFUSED.into());
    }
    let n = digits.parse::<u64>().map_err(|_| REFUSED)?;
    let amount_msat = if multiplier == 0 {
        if n % 10 != 0 {
            return Err(REFUSED.into());
        }
        n / 10
    } else {
        n.checked_mul(multiplier).ok_or(REFUSED)?
    };
    if amount_msat == 0 {
        return Err(REFUSED.into());
    }
    let words = zeroize::Zeroizing::new(
        data.bytes()
            .map(|b| {
                CHARSET
                    .iter()
                    .position(|v| *v == b)
                    .map(|n| n as u8)
                    .ok_or_else(|| REFUSED.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?,
    );
    let mut check = 1u32;
    for b in hrp.bytes() {
        check = step(check, b >> 5);
    }
    check = step(check, 0);
    for b in hrp.bytes() {
        check = step(check, b & 31);
    }
    for word in words.iter() {
        check = step(check, *word);
    }
    if check != 1 || words.len() < 7 + 104 + 6 {
        return Err(REFUSED.into());
    }
    let end = words.len() - 104 - 6;
    let signature = zeroize::Zeroizing::new(bytes(&words[end..end + 104])?);
    if signature.len() != 65 || signature[64] > 3 {
        return Err(REFUSED.into());
    }
    let timestamp = integer(&words[..7])?;
    if timestamp == 0 {
        return Err(REFUSED.into());
    }
    let mut at = 7;
    let mut seen = [false; 32];
    let mut payment_hash = None;
    let mut order = None;
    let mut expiry = 3600;
    while at < end {
        if end - at < 3 {
            return Err(REFUSED.into());
        }
        let tag = words[at] as usize;
        let length = usize::from(words[at + 1]) * 32 + usize::from(words[at + 2]);
        at += 3;
        if seen[tag] || length > end - at {
            return Err(REFUSED.into());
        }
        seen[tag] = true;
        let field = &words[at..at + length];
        match tag {
            1 => {
                let hash = bytes(field)?;
                if hash.len() != 32 {
                    return Err(REFUSED.into());
                }
                payment_hash = Some(hex::encode(hash));
            }
            13 => {
                let description = bytes(field)?;
                let description = std::str::from_utf8(&description).map_err(|_| REFUSED)?;
                let n = description.strip_prefix("Order #").ok_or(REFUSED)?;
                if n.is_empty()
                    || n.len() > 20
                    || n.starts_with('0')
                    || !n.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(REFUSED.into());
                }
                order = Some(n.parse::<u64>().map_err(|_| REFUSED)?);
            }
            6 => {
                expiry = integer(field)?;
                if expiry == 0 {
                    return Err(REFUSED.into());
                }
            }
            23 => return Err(REFUSED.into()), // hashed description cannot supply Order #n
            16 => {
                let secret = zeroize::Zeroizing::new(bytes(field)?);
                if secret.len() != 32 {
                    return Err(REFUSED.into());
                }
            }
            19 => {
                let key = bytes(field)?;
                if key.len() != 33 || !matches!(key[0], 2 | 3) {
                    return Err(REFUSED.into());
                }
            }
            24 => {
                if field.len() > 6 || integer(field)? == 0 {
                    return Err(REFUSED.into());
                }
            }
            5 => {
                if field.is_empty() {
                    return Err(REFUSED.into());
                }
            }
            3 => {
                let routes = bytes(field)?;
                if routes.is_empty() || routes.len() % 51 != 0 {
                    return Err(REFUSED.into());
                }
            }
            9 => {
                let (&version, program) = field.split_first().ok_or(REFUSED)?;
                let program = bytes(program)?;
                if !match version {
                    17 | 18 => program.len() == 20,
                    0 => matches!(program.len(), 20 | 32),
                    1..=16 => (2..=40).contains(&program.len()),
                    _ => false,
                } {
                    return Err(REFUSED.into());
                }
            }
            _ => (),
        }
        at += length;
    }
    Ok(Invoice {
        order: order.ok_or(REFUSED)?,
        payment_hash: payment_hash.ok_or(REFUSED)?,
        amount_msat,
        timestamp,
        expires: timestamp.checked_add(expiry).ok_or(REFUSED)?,
    })
}

#[cfg(test)]
pub(crate) fn fake(order: u64, timestamp: u64, amount_hrp: &str, extra: &[u8]) -> String {
    fn words(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut acc = 0u32;
        let mut bits = 0;
        for b in bytes {
            acc = ((acc << 8) | u32::from(*b)) & 0xffff;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(((acc >> bits) & 31) as u8);
            }
        }
        if bits > 0 {
            out.push(((acc << (5 - bits)) & 31) as u8);
        }
        out
    }
    fn tag(data: &mut Vec<u8>, kind: u8, field: &[u8]) {
        data.extend_from_slice(&[kind, (field.len() / 32) as u8, (field.len() % 32) as u8]);
        data.extend_from_slice(field);
    }
    let hrp = format!("lnbc{amount_hrp}");
    let mut data = (0..7)
        .rev()
        .map(|n| ((timestamp >> (n * 5)) & 31) as u8)
        .collect::<Vec<_>>();
    let mut hash = [42; 32];
    hash[..8].copy_from_slice(&order.to_be_bytes());
    tag(&mut data, 1, &words(&hash));
    tag(&mut data, 13, &words(format!("Order #{order}").as_bytes()));
    tag(&mut data, 6, &[28, 4]); // 900 seconds
    data.extend_from_slice(extra);
    data.extend_from_slice(&words(&[0; 65])); // invented, intentionally unsigned
    let mut check = 1;
    for b in hrp.bytes() {
        check = step(check, b >> 5);
    }
    check = step(check, 0);
    for b in hrp.bytes() {
        check = step(check, b & 31);
    }
    for b in &data {
        check = step(check, *b);
    }
    for _ in 0..6 {
        check = step(check, 0);
    }
    check ^= 1;
    for n in (0..6).rev() {
        data.push(((check >> (5 * n)) & 31) as u8);
    }
    format!(
        "{hrp}1{}",
        data.iter()
            .map(|n| CHARSET[*n as usize] as char)
            .collect::<String>()
    )
}
