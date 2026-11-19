//! Durable, single-use certificate introductions. All writes use the Store's sole writer.
use super::*;
use crate::dispatch::MachineEntry;
use ssh_key::{
    PrivateKey, PublicKey,
    private::{Ed25519Keypair, KeypairData},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Route {
    #[serde(rename = "attest_certificate")]
    AttestCertificate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Introduction {
    pub machine: String,
    pub route: Route,
    pub ca_public: String,
    pub principal: String,
    pub deadline_unix: u64,
    pub begun_unix: u64,
    pub installation_binding: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acceptance {
    pub machine: String,
    pub route: Route,
    pub inner_key_fingerprint: String,
    pub installation_binding: String,
    pub accepted_unix: u64,
    pub consumed: bool,
}

#[derive(Clone)]
pub(super) struct State {
    introduction: Introduction,
    acceptance: Option<Acceptance>,
}

/// The private authority exists only in the returned, zeroizing user-data input.
pub struct AttestIntroduction {
    pub ca_private_openssh: Zeroizing<String>,
    pub ca_public_openssh: String,
    pub principal: String,
    pub deadline_unix: u64,
}

pub(crate) fn attest_principal(ca: &PublicKey) -> Result<String, String> {
    let wire = ca.to_bytes().map_err(|_| "attest authority encoding")?;
    let digest = hex::encode(Sha256::digest(&wire));
    Ok(format!("tau-attest-{}", &digest[..32]))
}

impl<S: Storage> Store<S> {
    pub fn attest_installation_binding(&self, machine: &str) -> Result<String, String> {
        let approved = self
            .dispatch
            .approved_entries
            .get(machine)
            .ok_or("attest machine missing")?;
        let ordinal = self
            .dispatch
            .current_installations
            .get(machine)
            .ok_or("attest installation missing")?;
        Ok(format!("{:x}-{ordinal}", approved.approved.identity.index))
    }

    /// Resolves certificate pins into the same TargetRecord/StoredPins path as other pins.
    /// The acceptance remains durable even if transport or authentication subsequently fails.
    pub fn attest_target(&self, machine: &str) -> Option<crate::poc::targets::TargetRecord> {
        let mut target = self.poc_target(machine)?.clone();
        if let Some(acceptance) = self
            .attest
            .get(machine)
            .and_then(|state| state.acceptance.as_ref())
            && target.pin.is_empty()
            && self.attest_installation_binding(machine).ok().as_deref()
                == Some(&acceptance.installation_binding)
        {
            target.pin = acceptance.inner_key_fingerprint.clone();
        }
        Some(target)
    }

    fn attest_has_pin(&self, machine: &str) -> bool {
        self.attest_target(machine)
            .is_some_and(|target| !target.pin.is_empty())
    }

    pub fn attest_deadline(&self, machine: &str) -> Option<u64> {
        self.attest
            .get(machine)
            .map(|state| state.introduction.deadline_unix)
    }

    pub fn attest_expired(&self, machine: &str, now: u64) -> bool {
        self.attest.get(machine).is_some_and(|state| {
            state.acceptance.is_none()
                && !self.attest_has_pin(machine)
                && self.attest_installation_binding(machine).ok().as_deref()
                    == Some(&state.introduction.installation_binding)
                && now >= state.introduction.deadline_unix
        })
    }

    pub fn attest_introduction(&self, machine: &str, now: u64) -> Option<&Introduction> {
        if self.failed.is_some() || self.attest_has_pin(machine) {
            return None;
        }
        let state = self.attest.get(machine)?;
        let intro = &state.introduction;
        (state.acceptance.is_none()
            && now >= intro.begun_unix
            && now < intro.deadline_unix
            && self.attest_installation_binding(machine).ok().as_deref()
                == Some(&intro.installation_binding))
        .then_some(intro)
    }

    pub async fn attest_introduction_begin(
        &mut self,
        machine: &MachineEntry,
    ) -> Result<AttestIntroduction, String> {
        self.authority.ordinary()?;
        let approved = self
            .dispatch
            .approved_entries
            .get(&machine.machine)
            .ok_or("attest machine missing")?;
        if approved.approved.entry != *machine {
            return Err("attest machine differs".into());
        }
        let identity = &approved.approved.identity;
        if identity.seed != self.allocation().seed() || identity.family != Family::Machines {
            return Err("attest machine identity differs".into());
        }
        let seed = self
            .seed()
            .ok_or("attest seed missing")?
            .attest_certificate_authority(identity.derivation_version, identity.index)
            .map_err(|e| format!("attest derivation: {e:?}"))?;
        let private = PrivateKey::new(KeypairData::Ed25519(Ed25519Keypair::from_seed(&seed)), "")
            .map_err(|_| "attest authority encoding")?;
        let now = crate::hostcert::now_unix()?;
        let intro = Introduction {
            machine: machine.machine.clone(),
            route: Route::AttestCertificate,
            ca_public: private
                .public_key()
                .to_openssh()
                .map_err(|_| "attest authority encoding")?,
            principal: attest_principal(private.public_key())?,
            deadline_unix: now
                .checked_add(crate::hostcert::ATTEST_CERTIFICATE_DEADLINE_SECONDS)
                .ok_or("attest deadline overflow")?,
            begun_unix: now,
            installation_binding: self.attest_installation_binding(&machine.machine)?,
        };
        self.check_attest_introduction(&intro)?;
        let result = AttestIntroduction {
            ca_private_openssh: private
                .to_openssh(ssh_key::LineEnding::LF)
                .map_err(|_| "attest private encoding")?,
            ca_public_openssh: intro.ca_public.clone(),
            principal: intro.principal.clone(),
            deadline_unix: intro.deadline_unix,
        };
        self.commit(&Event::AttestIntroduction(intro.clone()))
            .await?;
        self.replay_attest_introduction(&intro)?;
        Ok(result)
    }

    fn check_attest_introduction(&self, intro: &Introduction) -> Result<(), String> {
        if self.attest.contains_key(&intro.machine) || self.attest_has_pin(&intro.machine) {
            return Err("attest introduction or active pin already exists".into());
        }
        let ca =
            PublicKey::from_openssh(&intro.ca_public).map_err(|_| "invalid attest authority")?;
        if intro.principal != attest_principal(&ca)?
            || intro.installation_binding != self.attest_installation_binding(&intro.machine)?
            || intro.begun_unix >= intro.deadline_unix
            || intro.deadline_unix > crate::clock::MAX_UTC
        {
            return Err("invalid attest introduction binding or deadline".into());
        }
        let identity = &self.dispatch.approved_entries[&intro.machine]
            .approved
            .identity;
        if identity.seed != self.allocation().seed() || identity.family != Family::Machines {
            return Err("attest identity differs".into());
        }
        let seed = self
            .seed()
            .ok_or("attest seed missing")?
            .attest_certificate_authority(identity.derivation_version, identity.index)
            .map_err(|_| "attest derivation")?;
        let expected = Ed25519Keypair::from_seed(&seed);
        if ca.key_data() != &ssh_key::public::KeyData::Ed25519(expected.public) {
            return Err("attest authority differs from machine identity".into());
        }
        Ok(())
    }

    pub(super) fn replay_attest_introduction(
        &mut self,
        intro: &Introduction,
    ) -> Result<(), String> {
        self.check_attest_introduction(intro)?;
        self.attest.insert(
            intro.machine.clone(),
            State {
                introduction: intro.clone(),
                acceptance: None,
            },
        );
        Ok(())
    }

    /// The caller holds the worker's writer lock through this append. No await releases it.
    pub async fn attest_accept(
        &mut self,
        machine: &str,
        inner_key_fingerprint: &str,
        installation_binding: &str,
    ) -> Result<(), String> {
        self.authority.ordinary()?;
        let record = Acceptance {
            machine: machine.into(),
            route: Route::AttestCertificate,
            inner_key_fingerprint: inner_key_fingerprint.into(),
            installation_binding: installation_binding.into(),
            accepted_unix: crate::hostcert::now_unix()?,
            consumed: true,
        };
        self.check_attest_acceptance(&record)?;
        self.commit(&Event::AttestAcceptance(record.clone()))
            .await?;
        self.replay_attest_acceptance(&record)
    }

    fn check_attest_acceptance(&self, record: &Acceptance) -> Result<(), String> {
        let intro = self
            .attest_introduction(&record.machine, record.accepted_unix)
            .ok_or("attest introduction unavailable, consumed, expired or pinned")?;
        if !record.consumed || record.installation_binding != intro.installation_binding {
            return Err("attest acceptance binding or consumption differs".into());
        }
        let fingerprint: ssh_key::Fingerprint = record
            .inner_key_fingerprint
            .parse()
            .map_err(|_| "invalid attest fingerprint")?;
        if fingerprint.algorithm() != ssh_key::HashAlg::Sha256
            || fingerprint.to_string() != record.inner_key_fingerprint
        {
            return Err("invalid attest fingerprint".into());
        }
        Ok(())
    }

    pub(super) fn replay_attest_acceptance(&mut self, record: &Acceptance) -> Result<(), String> {
        self.check_attest_acceptance(record)?;
        self.attest
            .get_mut(&record.machine)
            .expect("checked introduction")
            .acceptance = Some(record.clone());
        Ok(())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::harness::PinSource;
    struct Fixed;
    impl Kdf for Fixed {
        async fn derive(&self, _: LocalPassphrase, _: &Salt) -> Result<WrappingKey, String> {
            Ok(WrappingKey([9; 32]))
        }
    }
    fn pass() -> LocalPassphrase {
        LocalPassphrase::new(b"attest fixture passphrase".to_vec())
    }
    fn fresh() -> (Store<MemoryStorage>, MachineEntry) {
        let mut store = block_on(create(MemoryStorage::default(), &Fixed, pass())).unwrap();
        block_on(store.seed_backup(allocation::Completion::Skipped)).unwrap();
        let machine = crate::dispatch::fixture_setup().remove(0);
        block_on(store.approve_setup(vec![machine.clone()])).unwrap();
        (store, machine)
    }
    fn reopen(store: &Store<MemoryStorage>) -> Store<MemoryStorage> {
        block_on(unlock(
            MemoryStorage::with_files(store.storage.files()),
            &Fixed,
            pass(),
        ))
        .unwrap()
    }
    fn target(store: &mut Store<MemoryStorage>, machine: &str, pin: &str) {
        // The address publication is supplied by the provisioning adapter. Keep that
        // separate fixture input out of these two-record replay tests.
        let identity = store.dispatch.approved_entries[machine]
            .approved
            .identity
            .clone();
        let record = serde_json::from_value(json!({
            "target": { "machine":machine,"relay":"wss://relay.invalid/","profile":"v1",
                "host":"192.0.2.1","port":22,"user":"nixos","elevation":"none","pin":pin },
            "machine_identity":identity,
            "relay_identity": {"seed":store.allocation().seed(),"derivation_version":1,"family":"passes","index":0},
            "class_answer":"no", "access":crate::dispatch::Access::ad_hoc()
        })).unwrap();
        store.poc_targets.insert(machine.into(), record);
    }
    fn pin() -> String {
        use base64::engine::general_purpose::STANDARD_NO_PAD;
        format!("SHA256:{}", STANDARD_NO_PAD.encode([7; 32]))
    }

    #[test]
    fn attest_records_replay_and_single_consumption() {
        let (mut store, machine) = fresh();
        let returned = block_on(store.attest_introduction_begin(&machine)).unwrap();
        let intro = store.attest[&machine.machine].introduction.clone();
        let private = PrivateKey::from_openssh(returned.ca_private_openssh.as_bytes()).unwrap();
        assert_eq!(
            private.public_key().to_openssh().unwrap(),
            returned.ca_public_openssh
        );
        assert_eq!(intro.ca_public, returned.ca_public_openssh);
        assert_eq!(
            intro.principal,
            attest_principal(private.public_key()).unwrap()
        );
        assert_eq!(intro.principal, returned.principal);
        assert_eq!(intro.deadline_unix, returned.deadline_unix);
        // No new record contains the private half, even inside encryption.
        let mut reader = Store::new(
            store.storage.clone(),
            DataKey(store.key.0),
            store.id.clone(),
        );
        for number in store.records() {
            let bytes = block_on(store.storage.read(&number.to_string())).unwrap();
            let (event, _) = reader.open_record(number, &bytes).unwrap();
            assert!(
                !serde_json::to_string(&event)
                    .unwrap()
                    .contains("PRIVATE KEY")
            );
            reader.previous = Address(Sha256::digest(&bytes).into());
        }
        let mut replayed = reopen(&store);
        assert_eq!(replayed.attest[&machine.machine].introduction, intro);
        let before = replayed.storage.files();
        assert!(block_on(replayed.attest_introduction_begin(&machine)).is_err());
        assert_eq!(before, replayed.storage.files());
        let before_count = replayed.next;
        block_on(replayed.attest_accept(&machine.machine, &pin(), &intro.installation_binding))
            .unwrap();
        assert_eq!(replayed.next, before_count + 1);
        let before = replayed.storage.files();
        assert!(
            block_on(replayed.attest_accept(&machine.machine, &pin(), &intro.installation_binding))
                .is_err()
        );
        assert!(block_on(replayed.attest_introduction_begin(&machine)).is_err());
        assert_eq!(before, replayed.storage.files());
        let mut accepted = reopen(&replayed);
        assert!(
            accepted.attest[&machine.machine]
                .acceptance
                .as_ref()
                .unwrap()
                .consumed
        );
        assert!(
            accepted
                .attest_introduction(&machine.machine, intro.begun_unix)
                .is_none()
        );
        // The persisted acceptance is reduced to an ordinary pin for later contacts.
        target(&mut accepted, &machine.machine, "");
        let (transport, pins) = crate::poc::targets::resolve(&accepted, &machine.machine).unwrap();
        assert_eq!(pins.pin(&machine.machine).unwrap().0, pin());
        assert!(transport.contact_url(Some(&pin())).is_ok());
    }

    #[test]
    fn attest_records_refuse_expired_active_pin_and_duplicate_introduction() {
        let (mut store, machine) = fresh();
        block_on(store.attest_introduction_begin(&machine)).unwrap();
        let mut intro = store.attest[&machine.machine].introduction.clone();
        let before = store.storage.files();
        assert!(store.replay_attest_introduction(&intro).is_err());
        let acceptance = Acceptance {
            machine: machine.machine.clone(),
            route: Route::AttestCertificate,
            inner_key_fingerprint: pin(),
            installation_binding: intro.installation_binding.clone(),
            accepted_unix: intro.deadline_unix,
            consumed: true,
        };
        assert!(store.replay_attest_acceptance(&acceptance).is_err());
        // Drive the same live refusal with an expired recorded deadline, without sleeping.
        intro.begun_unix = 0;
        intro.deadline_unix = crate::hostcert::ATTEST_CERTIFICATE_DEADLINE_SECONDS;
        store.attest.get_mut(&machine.machine).unwrap().introduction = intro.clone();
        assert!(
            block_on(store.attest_accept(&machine.machine, &pin(), &intro.installation_binding))
                .is_err()
        );
        assert!(block_on(store.attest_introduction_begin(&machine)).is_err());
        assert_eq!(before, store.storage.files());
        let mut store = reopen(&store);
        let intro = store.attest[&machine.machine].introduction.clone();
        target(&mut store, &machine.machine, &pin());
        assert!(
            block_on(store.attest_accept(&machine.machine, &pin(), &intro.installation_binding))
                .is_err()
        );
        assert!(
            store
                .replay_attest_acceptance(&Acceptance {
                    accepted_unix: intro.begun_unix,
                    ..acceptance
                })
                .is_err()
        );
        assert!(block_on(store.attest_introduction_begin(&machine)).is_err());
        assert_eq!(before, store.storage.files());
    }

    #[test]
    fn attest_effective_pin_refreshes_after_acceptance_for_current_installation() {
        let (mut store, machine) = fresh();
        target(&mut store, &machine.machine, "");
        block_on(store.attest_introduction_begin(&machine)).unwrap();
        let intro = store.attest[&machine.machine].introduction.clone();
        let (_, mut snapshot) = crate::poc::targets::resolve(&store, &machine.machine).unwrap();
        assert!(snapshot.pin(&machine.machine).is_none());

        block_on(store.attest_accept(&machine.machine, &pin(), &intro.installation_binding))
            .unwrap();
        assert!(snapshot.pin(&machine.machine).is_none());
        assert!(
            store
                .attest_introduction(&machine.machine, intro.begun_unix)
                .is_none()
        );
        assert_eq!(store.attest_target(&machine.machine).unwrap().pin, pin());
        let (transport, refreshed) =
            crate::poc::targets::resolve(&store, &machine.machine).unwrap();
        snapshot = refreshed;
        assert_eq!(snapshot.pin(&machine.machine).unwrap().0, pin());
        assert!(transport.contact_url(Some(&pin())).is_ok());
        assert!(store.attest_target("another-machine").is_none());

        *store
            .dispatch
            .current_installations
            .get_mut(&machine.machine)
            .unwrap() += 1;
        assert!(
            store
                .attest_target(&machine.machine)
                .unwrap()
                .pin
                .is_empty()
        );
        assert!(crate::poc::targets::resolve(&store, &machine.machine).is_err());
    }

    #[test]
    fn attest_expired_requires_unaccepted_unpinned_current_installation() {
        let (mut store, machine) = fresh();
        target(&mut store, &machine.machine, "");
        assert!(!store.attest_expired(&machine.machine, u64::MAX));
        block_on(store.attest_introduction_begin(&machine)).unwrap();
        let intro = store.attest[&machine.machine].introduction.clone();
        assert_eq!(
            store.attest_deadline(&machine.machine),
            Some(intro.deadline_unix)
        );
        assert!(!store.attest_expired(&machine.machine, intro.deadline_unix - 1));
        assert!(store.attest_expired(&machine.machine, intro.deadline_unix));
        assert!(store.attest_expired(&machine.machine, intro.deadline_unix + 1));
        assert!(!store.attest_expired("another-machine", intro.deadline_unix));

        *store
            .dispatch
            .current_installations
            .get_mut(&machine.machine)
            .unwrap() += 1;
        assert!(!store.attest_expired(&machine.machine, intro.deadline_unix));
        *store
            .dispatch
            .current_installations
            .get_mut(&machine.machine)
            .unwrap() -= 1;

        target(&mut store, &machine.machine, &pin());
        assert!(!store.attest_expired(&machine.machine, intro.deadline_unix));
        target(&mut store, &machine.machine, "");
        block_on(store.attest_accept(&machine.machine, &pin(), &intro.installation_binding))
            .unwrap();
        assert!(!store.attest_expired(&machine.machine, intro.deadline_unix));
        store.poc_targets.remove(&machine.machine);
        assert!(!store.attest_has_pin(&machine.machine));
        assert!(!store.attest_expired(&machine.machine, intro.deadline_unix));
    }

    #[test]
    fn attest_expired_empty_pin_target_still_refuses_resolution() {
        let (mut store, machine) = fresh();
        target(&mut store, &machine.machine, "");
        block_on(store.attest_introduction_begin(&machine)).unwrap();
        let intro = &mut store.attest.get_mut(&machine.machine).unwrap().introduction;
        intro.begun_unix = 0;
        intro.deadline_unix = crate::hostcert::ATTEST_CERTIFICATE_DEADLINE_SECONDS;
        let now = crate::hostcert::now_unix().unwrap();

        assert!(
            store
                .attest_target(&machine.machine)
                .unwrap()
                .pin
                .is_empty()
        );
        assert!(crate::poc::targets::resolve(&store, &machine.machine).is_err());
        assert!(store.attest_expired(&machine.machine, now));
        assert!(store.attest_introduction(&machine.machine, now).is_none());
    }

    #[test]
    fn attest_principal_role_6_index_0_known_answer() {
        let seed = Seed::import(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let key = seed
            .attest_certificate_authority(crate::seed::VERSION, 0)
            .unwrap();
        let ca =
            PrivateKey::new(KeypairData::Ed25519(Ed25519Keypair::from_seed(&key)), "").unwrap();
        assert_eq!(
            ca.public_key().to_openssh().unwrap(),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJz0sRd8kEFxFqZjwV3c8la8w3w9YVmCsRTeaGBAyDt3"
        );
        assert_eq!(
            attest_principal(ca.public_key()).unwrap(),
            "tau-attest-db4e2bca4a66b75135fc53d428595c65"
        );
    }

    #[test]
    fn attest_no_pin_without_introduction_refuses() {
        let (mut store, machine) = fresh();
        target(&mut store, &machine.machine, "");
        assert!(
            store
                .attest_introduction(&machine.machine, crate::hostcert::now_unix().unwrap())
                .is_none()
        );
        assert!(crate::poc::targets::resolve(&store, &machine.machine).is_err());
        let count = store.next;
        block_on(store.attest_introduction_begin(&machine)).unwrap();
        let (transport, pins) = crate::poc::targets::resolve(&store, &machine.machine).unwrap();
        assert!(pins.pin(&machine.machine).is_none());
        assert!(transport.contact_url(None).is_err());
        let intro = &store.attest[&machine.machine].introduction;
        assert!(
            transport
                .attest_contact_url(intro, intro.deadline_unix)
                .is_err()
        );
        assert_eq!(store.next, count + 1);
    }
}
