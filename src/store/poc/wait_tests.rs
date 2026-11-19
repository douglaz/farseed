use super::*;

type WaitCheckpoint = (BTreeMap<String, Vec<u8>>, u64, Address, Task);

struct WaitRuntime {
    store: Store<MemoryStorage>,
    reason: String,
    before_wait: Option<WaitCheckpoint>,
}
impl Runtime for WaitRuntime {
    async fn prepare(&mut self, _: &Task, _: &str) -> Result<Task, String> {
        panic!("pending inspection cannot prepare a new action")
    }
    async fn load(&mut self, id: &str) -> Result<Task, String> {
        self.store.poc_task(id)
    }
    async fn authority(&mut self, id: &str, session: &str) -> Result<(), String> {
        self.store.poc_authority(id, session).map(|_| ())
    }
    async fn change(&mut self, task: &Task, change: Change) -> Result<Task, String> {
        if matches!(change, Change::Wait { .. }) {
            self.before_wait = Some((
                self.store.storage.files(),
                self.store.next,
                Address(self.store.previous.0),
                self.store.poc_task(&task.id)?,
            ));
        }
        self.store.poc_change(&task.id, task.revision, change).await
    }
    async fn propose(
        &mut self,
        _: &Task,
        _: &str,
        _: String,
        _: Tool,
        _: Option<BlockOrigin>,
    ) -> Result<Task, String> {
        panic!("Resume must inspect")
    }
    async fn execute(&mut self, _: Binding, _: &Task) -> Result<(), String> {
        panic!("Resume must never launch")
    }
    async fn observe(&mut self, task: &Task, _: &str) -> Result<Observation, String> {
        // Collection's no-outcome reason is produced by the store, including its protection.
        let pending = task.pending.as_ref().unwrap();
        let produced = self.store.poc_collection_reason(pending, &[]);
        if self.reason.starts_with("collection returned no outcome") {
            assert_eq!(self.reason, produced);
            return Ok(Observation::Unknown(produced));
        }
        Ok(Observation::Unknown(self.reason.clone()))
    }
}

#[test]
fn poc_wait_real_collection_producers_reach_resume() {
    // Fix seed, task and job identities for every configuration and continuation assertion.
    let _identifiers = FixedIdentifiers::new();
    for case in 0..16 {
        eprintln!("collection producer case={case}");
        let (fixture, task, session) = Fixture::new();
        let proposed = proposal(&mut fixture.store.borrow_mut(), &task);
        append(&mut fixture.store.borrow_mut(), &proposed, &session);
        let pending_task = fixture.task(&task.id);
        let pending = pending_task.pending.as_ref().unwrap();
        let reports = match case {
            0 => vec![],
            1 => vec![json!({"call":pending.call,"job":"other"})],
            2 => vec![json!({"call":pending.call,"not_journaled":true,"why":"remote detail"})],
            3 => vec![json!({"call":pending.call,"not_read":true})],
            4 => vec![json!({"call":pending.call,"failed":true,"why":"remote detail"})],
            5 => vec![json!({"call":pending.call})],
            14 => vec![
                json!({"call":pending.call,"failed":true,"job_record":null,"why":"remote detail"}),
            ],
            15 => vec![json!({"call":pending.call,"not_read":true,"why":"remote detail"})],
            _ => {
                let observed = match case {
                    6 | 7 => crate::jobs::Record::Missing,
                    8 => crate::jobs::Record::Incomplete {
                        machine: Some(hex::encode("fixture")),
                        command: None,
                    },
                    _ => {
                        let mut r = record(
                            &pending_task,
                            if case == 12 { Some(0) } else { None },
                            "ordinary output",
                        );
                        if let crate::jobs::Record::Present {
                            machine,
                            command,
                            alive,
                            ..
                        } = &mut r
                        {
                            if case == 9 {
                                *machine = hex::encode("foreign");
                            }
                            if case == 10 {
                                *command = hex::encode("different");
                                *alive = false;
                            }
                            if case == 11 {
                                *alive = false;
                            }
                        }
                        r
                    }
                };
                if case == 13 {
                    let report = crate::jobs::Evidence {
                        call: pending.call,
                        job: pending.job.clone(),
                        record: observed,
                    }
                    .report(
                        fixture.store.borrow().next,
                        &task.machine,
                        &hex::encode("install-example-service"),
                    );
                    vec![serde_json::to_value(report).unwrap()]
                } else {
                    evidence(&mut fixture.store.borrow_mut(), &pending_task, observed);
                    let mut report = serde_json::to_value(
                        fixture.store.borrow().poc_committed(pending).unwrap(),
                    )
                    .unwrap();
                    if case == 6 {
                        report["number"] = Value::Null;
                    }
                    vec![report]
                }
            }
        };
        let why = fixture
            .store
            .borrow()
            .poc_collection_reason(pending, &reports);
        let mut store = reopen(&fixture.store.borrow());
        // Rebinding is the actual adoption route, with every retained generation checked.
        let fresh = fresh(&mut store);
        store.poc_authority(&task.id, &fresh).map(|_| ()).unwrap();
        let mut runtime = WaitRuntime {
            store,
            reason: why.clone(),
            before_wait: None,
        };
        let waited = block_on(run::resume(
            &mut runtime,
            &mut Script::default(),
            &task.id,
            &fresh,
        ))
        .unwrap();
        assert_eq!(waited.pause_reason.as_deref(), Some(why.as_str()));
        assert_eq!(waited.pending, pending_task.pending);
        assert_eq!(runtime.store.dispatch.calls.len(), 1);
        assert_eq!(reopen(&runtime.store).poc_task(&task.id).unwrap(), waited);
    }
}
