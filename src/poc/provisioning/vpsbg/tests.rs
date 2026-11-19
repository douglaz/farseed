use super::*;

// Entirely synthetic wire values; no captured response or credential is used.
const PLANS: &[u8] = br#"{"data":[{"id":7,"key":"fake-plan","name":"Fake plan","type":"vps","vcpus":2,"dedicated_cpu":false,"memory":2048,"disk":20,"bandwidth":1000,"network_speed":100,"minimum_billing_cycle":1,"available":true,"price_with_vat":39.01}]}"#;

fn reduce(path: &str, bytes: &[u8]) -> Result<Value, String> {
    Vendor::Vpsbg.reduce_response("GET", path, 200, bytes, |_| Ok(()), |_| true)
}

fn selection() -> Selection {
    let offers = reduce("/v1/servers/plans", PLANS).unwrap();
    let catalogue = json!({"offers":offers});
    let (offer, image) = Vendor::Vpsbg
        .selection_inputs(&catalogue, None, 7, 1)
        .unwrap();
    Selection {
        charge: Vendor::Vpsbg.offer_charge(&offer).unwrap(),
        offer,
        image,
        resources: None,
    }
}

fn assert_selection_refused(selected: &Selection) {
    assert!(Vendor::Vpsbg.validate_selection(selected).is_err());
    let replayed: Selection =
        serde_json::from_slice(&serde_json::to_vec(selected).unwrap()).unwrap();
    assert!(Vendor::Vpsbg.validate_selection(&replayed).is_err());
    // b2a exposes no create recipe, even for otherwise valid terms.
    let request = Vendor::Vpsbg.create(&replayed, 1);
    assert!(Vendor::Vpsbg.request_url(ORIGIN, &request.path).is_err());
    assert!(!Vendor::Vpsbg.request_method_allowed(
        ORIGIN,
        request.method,
        &format!("{ORIGIN}{}", request.path)
    ));
}

#[test]
fn vpsbg_only_one_month_cycle_is_accepted() {
    let selected = selection();
    assert_eq!(selected.offer["billing_cycle"], "1");
    assert_eq!(selected.offer["minimum_billing_cycle"], 1);
    assert_eq!(selected.charge.interval_amount, 1);
    assert_eq!(selected.charge.interval_type, "month");
    Vendor::Vpsbg.validate_selection(&selected).unwrap();
    let replayed: Selection =
        serde_json::from_slice(&serde_json::to_vec(&selected).unwrap()).unwrap();
    Vendor::Vpsbg.validate_selection(&replayed).unwrap();

    for cycle in [json!("3"), json!("6"), json!("12"), json!("24"), json!(1)] {
        let mut invalid = selected.clone();
        invalid.offer["billing_cycle"] = cycle;
        assert_selection_refused(&invalid);
        assert!(
            Vendor::Vpsbg
                .selection_inputs(&json!({"offers":[invalid.offer]}), None, 7, 1)
                .is_err()
        );
    }
    for minimum in [0, 2, 3, 6, 12, 24] {
        let mut invalid = selected.clone();
        invalid.offer["minimum_billing_cycle"] = json!(minimum);
        assert_selection_refused(&invalid);
        assert!(Vendor::Vpsbg.offer_charge(&invalid.offer).is_err());
        assert!(
            Vendor::Vpsbg
                .selection_inputs(&json!({"offers":[invalid.offer]}), None, 7, 1)
                .is_err()
        );
    }
    for months in [0, 3, 6, 12, 24] {
        let mut invalid = selected.clone();
        invalid.charge.interval_amount = months;
        assert_selection_refused(&invalid);
    }
    let mut invalid = selected.clone();
    invalid.charge.interval_type = "year".into();
    assert_selection_refused(&invalid);
    invalid = selected.clone();
    invalid.resources = Some(json!({"vcpus":4}));
    assert_selection_refused(&invalid);
    assert!(
        Vendor::Vpsbg
            .selection_inputs(&json!({"offers":[selected.offer]}), Some(&json!({})), 7, 1)
            .is_err()
    );
    let request = Vendor::Vpsbg.create(&replayed, 1);
    assert!(Vendor::Vpsbg.request_url(ORIGIN, &request.path).is_err());
}

#[test]
fn vpsbg_card_flag_and_payment_plan_reads() {
    let selected = selection();
    assert_eq!(selected.charge.currency, "EUR");
    assert_eq!(selected.charge.amount, 3901);
    let raw = br#"{"data":{"balance":19.98,"minimum_deposit":10.00,"balance_limit":500.00,"currency":"EUR","has_valid_card":false}}"#;
    let mut balance: Balance = serde_json::from_value(reduce("/v1/balance", raw).unwrap()).unwrap();
    assert_eq!(balance.amount, 1998);
    assert_eq!(balance.minimum_deposit, 1000);
    assert_eq!(balance.balance_limit, 50_000);
    assert!(!balance.has_valid_card);
    // This cent value exceeds f64's exact integer range; lexical reduction must retain it.
    let large = reduce(
        "/v1/balance",
        br#"{"balance":90071992547409.93,"minimum_deposit":10,"balance_limit":90071992547410,"currency":"EUR","has_valid_card":false}"#,
    )
    .unwrap();
    assert_eq!(large["amount"].as_u64(), Some(9_007_199_254_740_993));
    assert_eq!(
        PaymentPlan::preview(&balance, &selected, 1234).unwrap(),
        PaymentPlan {
            balance: 1998,
            price: 3901,
            minimum: 1000,
            top_up: 1903,
            first_period: 3901,
            left_as_credit: 0,
            currency: Currency::Eur,
            read_at: 1234,
        }
    );
    balance.amount = 3502;
    let minimum = PaymentPlan::preview(&balance, &selected, 1235).unwrap();
    assert_eq!((minimum.top_up, minimum.left_as_credit), (1000, 601));
    for amount in [3901, 5003] {
        balance.amount = amount;
        let covered = PaymentPlan::preview(&balance, &selected, 1236).unwrap();
        assert_eq!(covered.top_up, 0);
        assert_eq!(covered.first_period, 3901);
        assert_eq!(covered.left_as_credit, amount - 3901);
    }

    let mut value: Value = serde_json::from_slice(raw).unwrap();
    value["data"]["has_valid_card"] = json!(true);
    assert!(
        serde_json::from_value::<Balance>(
            reduce("/v1/balance", &serde_json::to_vec(&value).unwrap()).unwrap()
        )
        .unwrap()
        .has_valid_card
    );
    for flag in [
        Value::Null,
        json!(0),
        json!(1),
        json!("false"),
        json!([]),
        json!({}),
    ] {
        value["data"]["has_valid_card"] = flag;
        assert!(reduce("/v1/balance", &serde_json::to_vec(&value).unwrap()).is_err());
    }
    value["data"]
        .as_object_mut()
        .unwrap()
        .remove("has_valid_card");
    assert!(reduce("/v1/balance", &serde_json::to_vec(&value).unwrap()).is_err());

    // A fractional cent, exponent or overflow must not silently round into approval terms.
    for amount in ["19.981", "1e2", "184467440737095516.16"] {
        let malformed = format!(
            r#"{{"balance":{amount},"minimum_deposit":10,"balance_limit":500,"currency":"EUR","has_valid_card":false}}"#
        );
        assert!(reduce("/v1/balance", malformed.as_bytes()).is_err());
    }
    balance.amount = 1998;
    balance.balance_limit = 3900;
    assert!(PaymentPlan::preview(&balance, &selected, 1237).is_err());
    balance.balance_limit = u64::MAX;
    balance.minimum_deposit = 50_001;
    assert!(PaymentPlan::preview(&balance, &selected, 1237).is_err());
    balance.minimum_deposit = u64::MAX;
    assert!(PaymentPlan::preview(&balance, &selected, 1237).is_err());
}
