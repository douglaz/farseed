use super::*;
use crate::poc::completion::proposal;

#[test]
fn proposal_description_closes_every_object_and_types_every_leaf() {
    fn inspect(v: &Value) {
        if v["type"] == "object" {
            assert_eq!(v["additionalProperties"], false);
            let props = v["properties"].as_object().unwrap();
            let mut required = v["required"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<Vec<_>>();
            required.sort();
            assert_eq!(
                required,
                props.keys().map(String::as_str).collect::<Vec<_>>()
            );
            for child in props.values() {
                inspect(child);
            }
        } else if v["type"] == "array" {
            assert!(v.get("items").is_some() || v["maxItems"] == 0);
            if let Some(item) = v.get("items") {
                inspect(item);
            }
        } else if let Some(choices) = v["oneOf"].as_array() {
            for child in choices {
                inspect(child);
            }
        } else {
            assert!(v["type"] == "string" || v["type"] == "integer" || v["type"] == "boolean");
        }
    }
    let schema = parameters();
    inspect(&schema);
    let d = &schema["properties"]["declaration"]["properties"];
    assert_eq!(d["version"]["const"], 2);
    assert_eq!(
        d["services"]["items"]["properties"]["lifecycle"]["enum"],
        json!(["running-at-delivery", "enabled-survives-reboot"])
    );
    assert_eq!(
        d["services"]["items"]["properties"]["scope"]["properties"]["kind"]["enum"],
        json!(["system"])
    );
    for direction in ["inbound", "outbound"] {
        let p = &d["listeners"]["properties"][direction]["items"]["properties"];
        assert_eq!(p["proto"]["enum"], json!(["tcp", "udp"]));
        assert_eq!(
            p["port"],
            json!({"type":"integer","minimum":1,"maximum":65535})
        );
    }
    assert_eq!(
        d["listeners"]["properties"]["inbound"]["items"]["properties"]["from"]["enum"],
        json!(["any", "peers", "none"])
    );
    assert_eq!(
        d["key_material"]["properties"]["spendable"]["type"],
        "boolean"
    );
    assert_eq!(
        d["key_material"]["properties"]["permitted"]["items"]["properties"]["kind"]["enum"],
        json!(["public", "watch-only", "private-non-spendable"])
    );
    for k in ["required", "drift_checks"] {
        assert_eq!(d[k]["maxItems"], 0);
    }
    assert!(!schema.to_string().contains("unspecified"));
    assert!(proposal(&example()).is_ok());
}

#[test]
fn proposal_refusals_locate_structure_and_semantics_in_fixed_order() {
    for (pointer, bad, path, expectation) in [
        (
            "/services/0/scope",
            json!("system"),
            "declaration.services[0].scope",
            "expected object",
        ),
        (
            "/services/0/lifecycle",
            json!({"kind":"running"}),
            "declaration.services[0].lifecycle",
            "allowed values",
        ),
        (
            "/required",
            json!(["invented"]),
            "declaration.required",
            "empty array",
        ),
        (
            "/drift_checks",
            json!([{}]),
            "declaration.drift_checks",
            "empty array",
        ),
        (
            "/services",
            json!("unspecified"),
            "declaration.services",
            "not stated",
        ),
        (
            "/services/0/scope/kind",
            json!("user"),
            "declaration.services[0].scope.kind",
            "user-scope",
        ),
        (
            "/listeners/inbound/0/port",
            json!(0),
            "declaration.listeners.inbound[0].port",
            "1–65535",
        ),
        (
            "/listeners/outbound/0/port",
            json!(65536),
            "declaration.listeners.outbound[0].port",
            "1–65535",
        ),
        ("/version", json!(1), "declaration.version", "integer 2"),
        (
            "/key_material/spendable",
            json!("false"),
            "declaration.key_material.spendable",
            "boolean",
        ),
        (
            "/listeners/inbound",
            json!([]),
            "declaration.listeners.inbound",
            "preserve",
        ),
        (
            "/listeners/outbound/0/host",
            json!("bad host"),
            "declaration.listeners.outbound[0].host",
            "hostname",
        ),
        (
            "/services/0/name",
            json!("example.service"),
            "declaration.services[0].name",
            "exclude unit suffixes",
        ),
        (
            "/services/0/name",
            json!("a".repeat(248)),
            "declaration.services[0].name",
            "247 bytes",
        ),
        (
            "/default_credentials",
            json!(["bad identifier"]),
            "declaration.default_credentials[0]",
            "identifier",
        ),
    ] {
        let mut v = example();
        *v.pointer_mut(pointer).unwrap() = bad;
        let why = proposal(&v).unwrap_err();
        assert!(
            why.contains(path) && why.contains(expectation),
            "{pointer}: {why}"
        );
    }
    let mut v = example();
    v["key_material"]["permitted"] = json!([{"kind":"public","where":"relative"}]);
    assert!(
        proposal(&v)
            .unwrap_err()
            .contains("declaration.key_material.permitted[0].where")
    );
    for key in ["listen", "running", "notes"] {
        let mut v = example();
        v["services"][0][key] = json!(true);
        let why = proposal(&v).unwrap_err();
        assert!(
            why.contains(&format!("declaration.services[0].{key}: unknown field"))
                && why.contains("name, scope, lifecycle")
        );
    }
    let mut v = example();
    v["listeners"]["outbound"][0]
        .as_object_mut()
        .unwrap()
        .remove("host");
    v["listeners"]["outbound"][0]["to"] = json!("example.invalid");
    let why = proposal(&v).unwrap_err();
    assert!(
        why.contains("declaration.listeners.outbound[0].to")
            && why.contains("declaration.listeners.outbound[0].host: missing")
    );
    let mut v = example();
    for key in ["notes", "running", "listen"] {
        v["services"][0][key] = json!(true);
    }
    let why = proposal(&v).unwrap_err();
    assert!(
        why.find(".listen:") < why.find(".notes:") && why.find(".notes:") < why.find(".running:")
    );
    assert_eq!(why, proposal(&v).unwrap_err());
    assert!(why.len() <= 512);
    assert!(
        proposal(&json!([]))
            .unwrap_err()
            .contains("declaration: declaration object shape")
    );
}

#[test]
fn proposal_paths_escape_and_bound_supplied_keys_without_values() {
    for key in ["x".repeat(1000), "界".repeat(1000), "\"\n\\".repeat(1000)] {
        let segment = segment(&key);
        assert!(segment.len() <= 64);
        assert!(segment.contains('…'));
        let mut v = example();
        v["services"][0][key] = json!("private-value-never-diagnostic".repeat(100));
        let why = proposal(&v).unwrap_err();
        assert!(why.len() <= 512);
        assert!(!why.contains("private-value"));
        assert!(why.starts_with("declaration.services[0]"));
        assert!(why.contains("unknown field"));
    }
}

#[test]
fn proposal_patterns_and_enums_agree_with_admission() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut samples = vec![];
    for name in [
        "example",
        "_example-2",
        "a:b.c",
        "-example",
        "",
        "has space",
        "é",
        "example\n",
        "example@instance",
    ] {
        samples.push(json!({"pattern":SERVICE.0,"text":name,"accept":crate::declaration::service_name(name)}));
    }
    for (pattern, pointer, strings) in [
        (
            IDENTIFIER.0,
            "/default_credentials",
            vec!["account", "root:login", "_x.y-1", "", "has space", "é"],
        ),
        (
            PATH.0,
            "/key_material/permitted",
            vec!["/", "/var/lib/example.key", "relative", "/has space", "/é"],
        ),
    ] {
        for text in strings {
            let mut v = example();
            *v.pointer_mut(pointer).unwrap() = if pointer == "/default_credentials" {
                json!([text])
            } else {
                json!([{"kind":"public","where":text}])
            };
            samples.push(json!({"pattern":pattern,"text":text,"accept":proposal(&v).is_ok()}));
        }
    }
    let mut child=Command::new("node").args(["-e","let s='';process.stdin.on('data',c=>s+=c);process.stdin.on('end',()=>{for(const v of JSON.parse(s))if(new RegExp(v.pattern).test(v.text)!==v.accept)process.exit(1);});"]).stdin(Stdio::piped()).spawn().expect("pattern checker");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&samples).unwrap())
        .unwrap();
    assert!(child.wait().unwrap().success());
    for proto in ["tcp", "udp"] {
        for from in ["any", "peers", "none"] {
            for port in [1, 65535] {
                let mut v = example();
                v["listeners"]["inbound"][1] = json!({"proto":proto,"port":port,"from":from});
                v["listeners"]["outbound"][0]["proto"] = json!(proto);
                v["listeners"]["outbound"][0]["port"] = json!(port);
                assert!(proposal(&v).is_ok());
            }
        }
    }
    for lifecycle in ["running-at-delivery", "enabled-survives-reboot"] {
        let mut v = example();
        v["services"][0]["lifecycle"] = json!(lifecycle);
        assert!(proposal(&v).is_ok());
    }
    for kind in ["public", "watch-only", "private-non-spendable"] {
        for spendable in [true, false] {
            let mut v = example();
            v["key_material"] =
                json!({"spendable":spendable,"permitted":[{"kind":kind,"where":"/example"}]});
            assert!(proposal(&v).is_ok());
        }
    }
}

#[test]
fn proposal_generated_shape_faults_and_enums_follow_the_description() {
    fn visit(shape: &Shape, value: &Value, pointer: &str, path: &str, root: &Value) {
        let mut bad = root.clone();
        *bad.pointer_mut(pointer).unwrap() = Value::Null;
        assert!(structure(&bad).unwrap_err().starts_with(path), "{path}");
        match shape {
            Shape::Object(fields) => {
                let mut extra = root.clone();
                extra.pointer_mut(pointer).unwrap()["extra"] = json!(true);
                assert!(
                    structure(&extra)
                        .unwrap_err()
                        .starts_with(&format!("{path}.extra: unknown field"))
                );
                for (key, child) in fields {
                    let mut missing = root.clone();
                    missing
                        .pointer_mut(pointer)
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .remove(*key);
                    assert!(
                        structure(&missing)
                            .unwrap_err()
                            .starts_with(&format!("{path}.{key}: missing required field"))
                    );
                    visit(
                        child,
                        &value[*key],
                        &format!("{pointer}/{key}"),
                        &format!("{path}.{key}"),
                        root,
                    );
                }
            }
            Shape::Array(item) => {
                if let Some(first) = value.as_array().unwrap().first() {
                    visit(
                        item,
                        first,
                        &format!("{pointer}/0"),
                        &format!("{path}[0]"),
                        root,
                    );
                }
            }
            Shape::Enum(choices) => {
                for choice in *choices {
                    let mut candidate = root.clone();
                    *candidate.pointer_mut(pointer).unwrap() = json!(choice);
                    assert!(structure(&candidate).is_ok(), "{path}: {choice}");
                }
                let mut candidate = root.clone();
                *candidate.pointer_mut(pointer).unwrap() = json!("outside-set");
                let why = structure(&candidate).unwrap_err();
                assert!(why.starts_with(path) && why.contains("allowed values"));
            }
            _ => (),
        }
    }
    let mut root = example();
    root["key_material"]["permitted"] = json!([{"kind":"public","where":"/example"}]);
    visit(&declaration(), &root, "", "declaration", &root);
    let mut missing_minimum = root.clone();
    missing_minimum["listeners"]["inbound"][0]["from"] = json!("none");
    assert!(structure(&missing_minimum).is_ok());
    assert!(
        proposal(&missing_minimum)
            .unwrap_err()
            .contains("declaration.listeners.inbound")
    );
    for (pointer, value) in [
        ("/services/0/name", json!("example.service")),
        ("/services/0/name", json!("x".repeat(248))),
        ("/listeners/outbound/0/host", json!("example..invalid")),
    ] {
        let mut candidate = root.clone();
        *candidate.pointer_mut(pointer).unwrap() = value;
        assert!(structure(&candidate).is_ok());
        assert!(proposal(&candidate).is_err());
    }
}

#[test]
fn proposal_diagnostic_budget_retains_parents_and_never_overflows() {
    for count in 1..50 {
        let mut candidate = example();
        for index in 0..count {
            candidate["services"][0][format!("unknown_{index:02}_{}", "界".repeat(80))] =
                json!("never-quoted".repeat(80));
        }
        let why = proposal(&candidate).unwrap_err();
        assert!(!why.is_empty() && why.len() <= 512);
        assert!(why.starts_with("declaration.services[0]"));
        assert!(why.contains('…') && why.contains("unknown field"));
        assert!(!why.contains("never-quoted"));
    }
    let mut faults = Reasons::default();
    faults.add(
        &format!("declaration.services[0]{}", segment(&"界".repeat(80))),
        "unknown field",
    );
    faults.add(
        &format!(
            "declaration.services[0]{}",
            segment(&"quoted\"key".repeat(80))
        ),
        &"fault ".repeat(60),
    );
    assert!(faults.text.len() <= 512 && faults.text.contains("declaration.services[0]: fault"));
}

#[test]
fn proposal_semantic_class_refusals_locate_material_without_quoting_it() {
    for (spendable, kind, path) in [
        (true, "public", "declaration.key_material.spendable"),
        (
            false,
            "private-non-spendable",
            "declaration.key_material.permitted[0].kind",
        ),
    ] {
        let mut candidate = example();
        candidate["key_material"] =
            json!({"spendable":spendable,"permitted":[{"kind":kind,"where":"/example"}]});
        let parsed = proposal(&candidate).unwrap();
        let why = parsed
            .validate(crate::dispatch::MachineClass::MultiTenant)
            .unwrap_err();
        let located = semantic(&candidate, &why);
        assert!(located.starts_with(path) && located.contains("multi-tenant material"));
        assert!(!located.contains("/example") && located.len() <= 512);
    }
}
