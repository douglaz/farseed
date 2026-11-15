//! One structural description for the offered declaration and its refusal locations.
use serde_json::{Value, json};

enum Shape {
    Object(Vec<(&'static str, Shape)>),
    Array(Box<Shape>),
    Empty,
    Text(Option<(&'static str, &'static str)>),
    Enum(&'static [&'static str]),
    Version,
    Port,
    Boolean,
    Credentials,
}
const SERVICE: (&str, &str) = (
    "^[A-Za-z0-9_][A-Za-z0-9_:.-]*$",
    "Service name: at most 247 bytes; exclude unit suffixes .service, .socket, .timer, .target, .path, .mount, .automount, .swap, .slice, .scope and .device.",
);
const IDENTIFIER: (&str, &str) = ("^[A-Za-z0-9_.:-]+$", "Credential identifier.");
const PATH: (&str, &str) = ("^/[A-Za-z0-9/._-]*$", "Absolute material path.");
fn declaration() -> Shape {
    use Shape::*;
    let protocol = || Enum(&["tcp", "udp"]);
    Object(vec![
        ("version", Version),
        (
            "listeners",
            Object(vec![
                (
                    "inbound",
                    Array(Box::new(Object(vec![
                        ("proto", protocol()),
                        ("port", Port),
                        ("from", Enum(&["any", "peers", "none"])),
                    ]))),
                ),
                (
                    "outbound",
                    Array(Box::new(Object(vec![
                        ("proto", protocol()),
                        ("host", Text(None)),
                        ("port", Port),
                    ]))),
                ),
            ]),
        ),
        (
            "services",
            Array(Box::new(Object(vec![
                ("name", Text(Some(SERVICE))),
                ("scope", Object(vec![("kind", Enum(&["system"]))])),
                (
                    "lifecycle",
                    Enum(&["running-at-delivery", "enabled-survives-reboot"]),
                ),
            ]))),
        ),
        (
            "key_material",
            Object(vec![
                ("spendable", Boolean),
                (
                    "permitted",
                    Array(Box::new(Object(vec![
                        (
                            "kind",
                            Enum(&["public", "watch-only", "private-non-spendable"]),
                        ),
                        ("where", Text(Some(PATH))),
                    ]))),
                ),
            ]),
        ),
        ("required", Empty),
        ("drift_checks", Empty),
        ("default_credentials", Credentials),
    ])
}
impl Shape {
    fn schema(&self) -> Value {
        match self {
            Self::Object(fields) => {
                json!({"type":"object", "properties":fields.iter().map(|(k,v)| ((*k).into(),v.schema())).collect::<serde_json::Map<_,_>>(), "required":fields.iter().map(|(k,_)| k).collect::<Vec<_>>(), "additionalProperties":false})
            }
            Self::Array(item) => json!({"type":"array", "items":item.schema()}),
            Self::Empty => json!({"type":"array", "maxItems":0}),
            Self::Text(pattern) => {
                let mut schema = json!({"type":"string"});
                if let Some((pattern, description)) = pattern {
                    schema["pattern"] = json!(pattern);
                    schema["description"] = json!(description);
                }
                schema
            }
            Self::Enum(values) => json!({"type":"string", "enum":values}),
            Self::Version => json!({"type":"integer", "const":2}),
            Self::Port => json!({"type":"integer", "minimum":1, "maximum":65535}),
            Self::Boolean => json!({"type":"boolean"}),
            Self::Credentials => {
                json!({"oneOf":[{"type":"string","const":"none"}, {"type":"array","items":Self::Text(Some(IDENTIFIER)).schema()}]})
            }
        }
    }

    // Objects: sorted unknown keys first, then required fields in declaration order.
    // Arrays: ascending index. Stop once no further diagnostic can fit the byte bound.
    fn walk(&self, value: &Value, path: &str, faults: &mut Reasons) {
        if faults.full {
            return;
        }
        if value == "unspecified" {
            faults.add(
                path,
                "not stated; unspecified is not supported in this proposal",
            );
            return;
        }
        match self {
            Self::Object(fields) => {
                let Some(object) = value.as_object() else {
                    faults.add(path, "declaration object shape: expected object");
                    return;
                };
                let accepted = fields
                    .iter()
                    .map(|(k, _)| *k)
                    .collect::<Vec<_>>()
                    .join(", ");
                let mut unknown = object
                    .keys()
                    .filter(|key| !fields.iter().any(|(k, _)| k == key))
                    .collect::<Vec<_>>();
                unknown.sort();
                for key in unknown {
                    faults.add(
                        &format!("{path}{}", segment(key)),
                        &format!("unknown field; accepted fields: {accepted}"),
                    );
                    if faults.full {
                        return;
                    }
                }
                for (key, shape) in fields {
                    let child = format!("{path}.{key}");
                    match object.get(*key) {
                        Some(v) => shape.walk(v, &child, faults),
                        None => faults.add(&child, "missing required field"),
                    }
                    if faults.full {
                        return;
                    }
                }
            }
            Self::Array(item) => match value.as_array() {
                Some(entries) => {
                    for (i, v) in entries.iter().enumerate() {
                        item.walk(v, &format!("{path}[{i}]"), faults);
                        if faults.full {
                            break;
                        }
                    }
                }
                None => faults.add(path, "expected array"),
            },
            Self::Empty if !value.is_array() => faults.add(path, "expected empty array"),
            Self::Empty if value.as_array().is_some_and(|v| !v.is_empty()) => faults.add(
                path,
                "expected empty array; no bundle check entries are admitted",
            ),
            Self::Text(_) if !value.is_string() => faults.add(path, "expected string"),
            Self::Enum(values) if !value.as_str().is_some_and(|v| values.contains(&v)) => {
                faults.add(
                    path,
                    &format!(
                        "expected string; allowed values: {}{}",
                        values.join(", "),
                        if path.ends_with(".scope.kind") {
                            "; user-scope services are unsupported"
                        } else {
                            ""
                        }
                    ),
                );
            }
            Self::Version if value.as_u64() != Some(2) => {
                faults.add(path, "expected integer 2 (declaration version)")
            }
            Self::Port if !value.as_u64().is_some_and(|p| (1..=65535).contains(&p)) => {
                faults.add(path, "expected integer port 1–65535")
            }
            Self::Boolean if !value.is_boolean() => faults.add(path, "expected boolean"),
            Self::Credentials if value != "none" => {
                if value.is_array() {
                    Self::Array(Box::new(Self::Text(Some(IDENTIFIER)))).walk(value, path, faults);
                } else {
                    faults.add(
                        path,
                        "expected string none or array of credential identifiers",
                    );
                }
            }
            _ => (),
        }
    }
}

/// Supplied keys are JSON-escaped bracket segments; the entire segment is at most 64 bytes.
pub(super) fn segment(key: &str) -> String {
    if !key.is_empty()
        && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && key.len() < 63
    {
        return format!(".{key}");
    }
    let mut escaped = String::new();
    for c in key.chars() {
        let encoded = json!(c.to_string()).to_string();
        let part = &encoded[1..encoded.len() - 1];
        if escaped.len() + part.len() > 57 {
            escaped.push('…');
            break;
        }
        escaped.push_str(part);
    }
    format!("[\"{escaped}\"]")
}
#[derive(Default)]
struct Reasons {
    text: String,
    full: bool,
}
impl Reasons {
    fn add(&mut self, path: &str, reason: &str) {
        if self.full {
            return;
        }
        let separator = if self.text.is_empty() { "" } else { "; " };
        let remaining = 512usize.saturating_sub(self.text.len() + separator.len());
        let mut path = path;
        while path.len() + reason.len() + 2 > remaining {
            let Some(end) = path.find("[\"").or_else(|| path.rfind(['.', '['])) else {
                self.full = true;
                return;
            };
            path = &path[..end];
        }
        self.text.push_str(separator);
        self.text.push_str(path);
        self.text.push_str(": ");
        self.text.push_str(reason);
        self.full = self.text.len() >= 512;
    }
}

pub fn parameters() -> Value {
    let mut schema = Shape::Object(vec![
        ("machine", Shape::Text(None)),
        ("declaration", declaration()),
    ])
    .schema();
    schema["properties"]["declaration"]["properties"]["listeners"]["properties"]["inbound"]["description"] =
        json!("Preserve every entry of the inbound ad-hoc minimum.");
    schema["properties"]["declaration"]["properties"]["listeners"]["properties"]["outbound"]["items"]
        ["properties"]["host"]["description"] = json!(
        "Host is any, an IPv4/IPv6 CIDR with a valid prefix, or a hostname up to 253 bytes: labels of 1–63 ASCII letters, digits or hyphens, starting and ending with a letter or digit."
    );
    schema
}
pub fn structure(value: &Value) -> Result<(), String> {
    let mut faults = Reasons::default();
    declaration().walk(value, "declaration", &mut faults);
    if faults.text.is_empty() {
        Ok(())
    } else {
        Err(faults.text)
    }
}

/// Semantic admission still runs after the structural walk; none of its rules is replaced.
pub fn semantic(value: &Value, reason: &str) -> String {
    let path = match reason {
        "ad-hoc declaration must preserve signed inbound minimum" => {
            "declaration.listeners.inbound".into()
        }
        "outbound host or port" => indexed(value, "listeners.outbound", "host", |v| {
            !crate::declaration::host(v.as_str().unwrap_or_default())
        }),
        "service name" => indexed(value, "services", "name", |v| {
            !crate::declaration::service_name(v.as_str().unwrap_or_default())
        }),
        "tenant material path" => indexed(value, "key_material.permitted", "where", |v| {
            !v.as_str().is_some_and(|s| {
                s.starts_with('/')
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
            })
        }),
        "default credential identifier" => {
            let i = value["default_credentials"]
                .as_array()
                .and_then(|a| {
                    a.iter().position(|v| {
                        !v.as_str().is_some_and(|s| {
                            !s.is_empty()
                                && s.bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
                        })
                    })
                })
                .unwrap_or(0);
            format!("declaration.default_credentials[{i}]")
        }
        "multi-tenant material" => {
            if value["key_material"]["spendable"] != false {
                "declaration.key_material.spendable".into()
            } else {
                indexed(value, "key_material.permitted", "kind", |v| {
                    v == "private-non-spendable"
                })
            }
        }
        _ => "declaration".into(),
    };
    let mut faults = Reasons::default();
    let detail = match reason {
        "ad-hoc declaration must preserve signed inbound minimum" => {
            "must preserve the inbound ad-hoc minimum"
        }
        "service name" => SERVICE.1,
        "tenant material path" => {
            "tenant material path: expected absolute path using letters, digits, /._-"
        }
        "default credential identifier" => {
            "default credential identifier: expected nonempty string using letters, digits, _.:-"
        }
        "outbound host or port" => {
            "outbound host or port: expected any, numeric CIDR or valid hostname"
        }
        "multi-tenant material" => {
            "multi-tenant material: spendable must be false and permitted kinds must be public or watch-only"
        }
        _ => "declaration semantic admission refused",
    };
    faults.add(&path, detail);
    faults.text
}
fn indexed(value: &Value, parent: &str, field: &str, bad: impl Fn(&Value) -> bool) -> String {
    let entries = parent.split('.').fold(value, |v, k| &v[k]);
    let i = entries
        .as_array()
        .and_then(|a| a.iter().position(|v| bad(&v[field])))
        .unwrap_or(0);
    format!("declaration.{parent}[{i}].{field}")
}

pub fn example() -> Value {
    let mut value =
        serde_json::to_value(crate::declaration::ad_hoc_minimum()).expect("minimum serializes");
    value["services"] = json!([{"name":"example-unit","scope":{"kind":"system"},"lifecycle":"running-at-delivery"}]);
    value["listeners"]["inbound"]
        .as_array_mut()
        .expect("minimum inbound")
        .push(json!({"proto":"tcp","port":8123,"from":"none"}));
    value["listeners"]["outbound"] = json!([{"proto":"tcp","host":"example.invalid","port":8124}]);
    value
}

#[cfg(test)]
mod tests;
