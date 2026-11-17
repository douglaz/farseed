use super::*;

pub(super) fn unchanged(
    s: &Store<MemoryStorage>,
    files: &BTreeMap<String, Vec<u8>>,
    next: u64,
    previous: [u8; 32],
) {
    assert_eq!(&s.storage.files(), files);
    assert_eq!(s.next, next);
    assert_eq!(s.previous.0, previous);
    assert!(s.failed.is_none());
}

#[test]
fn poc_journal_no_key_store_preserves_seed_account_and_replay() {
    let mut s = ready();
    assert!(s.poc_credential_filters.borrow().is_empty());
    let task = create_task(&mut s);
    let seed = s.seed().unwrap().id();
    let reopened = reopen(&s);
    assert_eq!(reopened.seed().unwrap().id(), seed);
    assert!(reopened.inference.account.is_some());
    assert_eq!(reopened.poc_task(&task.id).unwrap(), task);
    s.next = u64::from(u32::MAX);
    let files = s.storage.files();
    let previous = s.previous.0;
    assert!(
        block_on(s.poc_change(&task.id, task.revision, Change::Abandon))
            .unwrap_err()
            .contains("2^32nd")
    );
    unchanged(&s, &files, u64::from(u32::MAX), previous);
}

#[test]
fn poc_journal_protected_diagnostics_survive_real_storage_failure() {
    use crate::dispatch::{Association, EvidenceDiagnostic, EvidenceProtection, Target};
    for fault in [Fault::Fail(1), Fault::Fail(2), Fault::LandThenFail(3)] {
        let mut s = ready();
        s.storage.fault(fault);
        assert!(
            block_on(s.association_evidence(
                Association {
                    target: Target::VendorMachine("failed-synthetic-target".into()),
                    entry: "fixture".into(),
                },
                EvidenceProtection::default()
            ))
            .is_err()
        );
        assert!(s.failed.is_some());
        assert!(matches!(
            s.uncommitted_evidence(),
            Some(EvidenceDiagnostic::Association {
                committed: false,
                ..
            })
        ));

        use crate::dispatch::{
            Operation, Receipt, ReceiptBinding, ReceiptOperation, ReceiptSource,
        };
        let (_, mut s, _) = crate::dispatch::typed_tests::fresh();
        let mut request = crate::dispatch::typed_tests::request(Operation::Reset);
        request.receipt_binding = Some(ReceiptBinding {
            operation: ReceiptOperation::Restart,
            account: 41,
            signed_request: 73,
        });
        request.approved.as_mut().unwrap().receipt_binding = request.receipt_binding.clone();
        let intent = block_on(s.operation(&request)).unwrap();
        let receipt = Receipt {
            source: ReceiptSource::BrowserVendorTls,
            call: intent.call,
            resource: intent.resource.clone(),
            target: intent.target.clone(),
            binding: intent.receipt_binding.clone().unwrap(),
            validated: true,
            returned_vendor: None,
        };
        s.storage.fault(fault);
        assert!(
            block_on(s.protected_operation_receipt(receipt, EvidenceProtection::default()))
                .is_err()
        );
        assert!(s.failed.is_some());
        assert!(matches!(
            s.uncommitted_evidence(),
            Some(EvidenceDiagnostic::Receipt {
                committed: false,
                ..
            })
        ));
    }
}
