//! An operator question is a durable proposal, never a command or a secret input.
use crate::goals::Tool;

pub(crate) fn default_choices() -> Vec<String> {
    vec!["Done".into(), "Can't".into()]
}

pub(crate) fn validate(tool: &Tool) -> Result<(), &'static str> {
    let Tool::AskOperator {
        purpose,
        link,
        choices,
    } = tool
    else {
        return Err("No operator question is pending.");
    };
    if !super::files::plain_line(purpose, 160) {
        return Err("The purpose must be one plain line of 1 to 160 printable bytes.");
    }
    if !(2..=4).contains(&choices.len())
        || choices.iter().enumerate().any(|(index, label)| {
            !super::files::plain_line(label, 32) || choices[..index].contains(label)
        })
    {
        return Err("Choose 2 to 4 distinct plain labels of 1 to 32 printable bytes each.");
    }
    if link.as_deref().is_some_and(|link| !valid_link(link)) {
        return Err(
            "The link must be an absolute HTTPS URL of 1 to 2048 bytes with a host, no credentials and no whitespace or control characters.",
        );
    }
    Ok(())
}

pub(super) fn valid_link(link: &str) -> bool {
    if link.is_empty()
        || link.len() > 2048
        || link
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
    {
        return false;
    }
    let Some((scheme, rest)) = link.split_once("://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if !scheme.eq_ignore_ascii_case("https") || authority.is_empty() || authority.contains('@') {
        return false;
    }
    #[cfg(target_arch = "wasm32")]
    {
        // Use the same URL parser as the page, including its ASCII host normalization.
        web_sys::Url::new(link).is_ok_and(|url| {
            url.protocol() == "https:"
                && !url.hostname().is_empty()
                && url.username().is_empty()
                && url.password().is_empty()
        })
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        // Native journal readers need no browser; check authority syntax without decoding it.
        let port = if let Some(rest) = authority.strip_prefix('[') {
            let Some((host, suffix)) = rest.split_once(']') else {
                return false;
            };
            if host.parse::<std::net::Ipv6Addr>().is_err() {
                return false;
            }
            if suffix.is_empty() {
                None
            } else if let Some(port) = suffix.strip_prefix(':') {
                Some(port)
            } else {
                return false;
            }
        } else {
            let (host, port) = authority
                .split_once(':')
                .map_or((authority, None), |(h, p)| (h, Some(p)));
            if host.is_empty() || host.chars().any(|c| "[]<>%\"^|:".contains(c)) {
                return false;
            }
            port
        };
        port.is_none_or(|p| {
            p.is_empty() || p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok()
        })
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn display(tool: &Tool) -> Option<serde_json::Value> {
    validate(tool).ok()?;
    let Tool::AskOperator {
        purpose,
        link,
        choices,
    } = tool
    else {
        return None;
    };
    let url = link.as_deref().map(web_sys::Url::new).transpose().ok()?;
    Some(serde_json::json!({
        "purpose": purpose,
        "link": link,
        "href": url.as_ref().map(|url| url.href()),
        "domain": url.as_ref().map(|url| url.hostname().to_ascii_lowercase()),
        "choices": choices,
    }))
}
