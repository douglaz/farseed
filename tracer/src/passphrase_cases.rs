//! Optional local passphrases, isolated from the primary tracer store.
use super::*;

async fn words(run: &Run<'_>, tab: &Tab) -> Result<Value, String> {
    for _ in 0..300 {
        let words = run
            .browser
            .evaluate(
                &tab.session,
                "Array.from(document.querySelectorAll('#tau-seed-backup-words li'), n => n.textContent)",
            )
            .await?;
        if words.as_array().is_some_and(|words| words.len() == 12) {
            return Ok(words);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err("optional passphrase case did not display twelve seed words".into())
}

async fn locked(run: &Run<'_>, tab: &Tab) -> Result<bool, String> {
    Ok(run
        .browser
        .evaluate(
            &tab.session,
            r#"(() => {
                const $ = id => document.getElementById('tau-' + id);
                return $('store').dataset.state === 'locked' && $('passphrase').value === '' &&
                    $('confirm').value === '' && $('confirm-field').hidden === true &&
                    $('passphrase-warning').hidden === true && $('unlock').hidden === false &&
                    $('create').hidden === true && $('seed-backup-words') === null;
            })()"#,
        )
        .await?
        == true)
}

pub(super) async fn run(
    run: &Run<'_>,
    origins: [&str; 2],
    cases: &mut Vec<Case>,
) -> Result<(), String> {
    let _scenario_span = completion::scenario("passphrase_cases.run");
    let mut case = Case::new(
        "passphrase_cases.c001",
        "empty passphrase create, reload, lock and seed re-display; short create in a second fresh origin",
    );
    let (tab, mut worker) = run.open(origins[0], false).await?;
    case.check(
        "passphrase_cases.a001",
        "the fresh origin offers empty Create with its warning and no Confirm",
        run.browser
            .evaluate(
                &tab.session,
                r#"(() => {
                    const $ = id => document.getElementById('tau-' + id);
                    $('passphrase').dispatchEvent(new Event('input', {bubbles: true}));
                    return $('store').dataset.state === 'none' && $('create').hidden === false &&
                        $('passphrase').value === '' && $('confirm').value === '' &&
                        $('confirm-field').hidden === true && $('passphrase-warning').hidden === false &&
                        $('passphrase-warning').textContent.includes('With no passphrase');
                })()"#,
            )
            .await?
            == true,
    );
    let view = run.submit(&tab, "create", "").await?;
    case.check(
        "passphrase_cases.a002",
        "Create with nothing entered creates and unlocks the store",
        view["store"] == "unlocked",
    );
    let original_words = words(run, &tab).await?;
    case.check(
        "passphrase_cases.a003",
        "empty-passphrase creation displays twelve non-empty seed words",
        original_words.as_array().is_some_and(|words| {
            words.len() == 12
                && words
                    .iter()
                    .all(|word| word.as_str().is_some_and(|word| !word.is_empty()))
        }),
    );

    worker = run
        .reload("passphrase_cases.rs::reload#1", &tab, &worker)
        .await?;
    case.check(
        "passphrase_cases.a004",
        "reload waits at Unlock with empty fields, no creation warning and no displayed seed",
        locked(run, &tab).await?,
    );
    let view = run.submit(&tab, "unlock", "").await?;
    case.check(
        "passphrase_cases.a005",
        "Unlock with nothing typed after reload opens the same seed",
        view["store"] == "unlocked" && words(run, &tab).await? == original_words,
    );

    run.browser
        .evaluate(&tab.session, "document.getElementById('tau-lock').click()")
        .await?;
    worker = run.worker(&tab, Some(&worker), false).await?;
    case.check(
        "passphrase_cases.a006",
        "explicit Lock waits at Unlock and removes the seed words",
        locked(run, &tab).await?,
    );
    let view = run.submit(&tab, "unlock", "").await?;
    case.check(
        "passphrase_cases.a007",
        "Unlock with nothing typed after explicit Lock opens the same seed",
        view["store"] == "unlocked" && words(run, &tab).await? == original_words,
    );

    seed_cases::skip("passphrase.empty.seed_skip", run, &tab).await?;
    case.check(
        "passphrase_cases.a008",
        "finishing the initial ceremony offers seed re-display",
        run.browser
            .evaluate(
                &tab.session,
                "document.getElementById('tau-redisplay').hidden === false && document.getElementById('tau-seed-backup').hidden === true",
            )
            .await?
            == true,
    );
    let view = run.settled(&tab, false).await?;
    case.check(
        "passphrase_cases.a014",
        "the fresh store after seed backup shows both VPSBG and LNVPS provider choices",
        view["provider_choice_open"] == true,
    );
    run.browser
        .evaluate(
            &tab.session,
            "document.getElementById('tau-redisplay').click()",
        )
        .await?;
    let _redisplay_worker = run.worker(&tab, Some(&worker), false).await?;
    case.check(
        "passphrase_cases.a009",
        "seed re-display first requires an explicit Unlock press with no words displayed",
        locked(run, &tab).await?,
    );
    let view = run.submit(&tab, "unlock", "").await?;
    case.check(
        "passphrase_cases.a010",
        "an empty Unlock press re-displays the same twelve words",
        view["store"] == "unlocked" && words(run, &tab).await? == original_words,
    );
    run.collect(&tab).await?;
    run.browser
        .call(None, "Target.closeTarget", json!({"targetId":tab.target}))
        .await?;

    let (short_tab, _short_worker) = run.open(origins[1], false).await?;
    case.check(
        "passphrase_cases.a011",
        "the second origin is distinct and has no store or Confirm",
        origins[0] != origins[1]
            && run
                .browser
                .evaluate(
                    &short_tab.session,
                    "document.getElementById('tau-store').dataset.state === 'none' && document.getElementById('tau-passphrase').value === '' && document.getElementById('tau-confirm-field').hidden === true",
                )
                .await?
                == true,
    );
    case.check(
        "passphrase_cases.a012",
        "a short passphrase input event shows Confirm and the short-passphrase warning",
        run.browser
            .evaluate(
                &short_tab.session,
                r#"(() => {
                    const $ = id => document.getElementById('tau-' + id);
                    $('passphrase').value = 'f';
                    $('passphrase').dispatchEvent(new Event('input', {bubbles: true}));
                    const confirmAfterOne = $('confirm-field').hidden === false;
                    $('passphrase').value = 'fifteen chars!!';
                    $('passphrase').dispatchEvent(new Event('input', {bubbles: true}));
                    return confirmAfterOne && $('store').dataset.state === 'none' && $('confirm-field').hidden === false &&
                        $('passphrase-warning').hidden === false &&
                        $('passphrase-warning').textContent.includes('shorter than 16 characters');
                })()"#,
            )
            .await?
            == true,
    );
    let view = run.submit(&short_tab, "create", "fifteen chars!!").await?;
    case.check(
        "passphrase_cases.a013",
        "Create accepts the short passphrase and unlocks the second store",
        view["store"] == "unlocked",
    );
    run.collect(&short_tab).await?;
    run.browser
        .call(
            None,
            "Target.closeTarget",
            json!({"targetId":short_tab.target}),
        )
        .await?;
    case.finish(cases);
    Ok(())
}
