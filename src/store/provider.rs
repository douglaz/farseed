//! Provider custody and memory-only deployment material.
use super::*;
use crate::poc::provisioning::{Account, AccountRecord, AccountSource, provider_origin};

impl<S: Storage> Store<S> {
    pub(crate) fn deployment_relay_present(&self) -> bool {
        self.deployment_relay.is_some()
    }
    pub(crate) fn provider_account(&self) -> Option<&Account> {
        self.provider_account.as_ref()
    }

    pub(crate) fn provider_entry_ready(&self) -> Result<(), String> {
        if self.provider_account.is_some() {
            return Err("Provider account already recorded".into());
        }
        if self.procurement.is_some() || !self.closed_purchases.is_empty() {
            return Err("A purchase prevents provider account entry.".into());
        }
        Ok(())
    }

    pub(crate) async fn provider_generate(&mut self) -> Result<(), String> {
        if self.provider_account.is_some() {
            return Ok(());
        }
        let origin = self.deployment_origin.clone().ok_or(
            "Load valid deployment defaults before creating a provider account, or use an existing account.",
        )?;
        let mut bytes = Zeroizing::new([0; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| "Provider account entropy unavailable.")?;
        let secret = Zeroizing::new(hex::encode(*bytes));
        let account = Account::parse(secret.as_bytes())?;
        self.provider_install(
            &account,
            secret.as_bytes(),
            &origin,
            AccountSource::Generated,
        )
        .await
    }

    pub(crate) async fn provider_install(
        &mut self,
        account: &Account,
        input: &[u8],
        origin: &str,
        source: AccountSource,
    ) -> Result<(), String> {
        self.provider_entry_ready()?;
        self.procurement_account(&account.public())?;
        #[cfg(target_arch = "wasm32")]
        if crate::poc::inference::response_pending() {
            return Err("Provider account entry refused: command response pending; retry after it completes.".into());
        }
        let normalized = provider_origin(origin)?;
        let filter = account.filter(input);
        if !crate::poc::inference::safe(self, &json!([origin, normalized]), &[input]) {
            return Err("Provider origin contains protected or unscannable material.".into());
        }
        for value in [origin, normalized.as_str()] {
            if filter.protect_bytes(value.as_bytes())?.as_slice() != value.as_bytes() {
                return Err("Provider origin contains protected or unscannable material.".into());
            }
        }
        let record = account.record(source, normalized.clone());
        self.commit(&Event::PocProviderAccount(record)).await?;
        // No await or external effect separates committed custody from filter installation.
        self.remember_provider_filter(filter);
        self.provider_origin = normalized;
        self.procurement_selection = None;
        self.provider_account = Some(account.copy());
        Ok(())
    }

    pub(super) fn replay_provider_account(&mut self, record: &AccountRecord) -> Result<(), String> {
        self.provider_entry_ready()?;
        let account = record.account()?;
        let filter = account.filter(record.key.0.as_bytes());
        if filter.protect_bytes(record.origin.as_bytes())?.as_slice() != record.origin.as_bytes() {
            return Err("Provider origin contains protected or unscannable material.".into());
        }
        self.remember_provider_filter(filter);
        self.provider_origin = record.origin.clone();
        self.provider_account = Some(account);
        Ok(())
    }

    pub(super) fn check_provider_material(&self, plaintext: &[u8]) -> Result<(), String> {
        for filter in &self.provider_filters {
            if filter.protect_bytes(plaintext)?.as_slice() != plaintext {
                return Err(
                    "protected provider material refused before encryption or replay".into(),
                );
            }
        }
        Ok(())
    }

    pub(super) fn check_deployment_material(&self, plaintext: &[u8]) -> Result<(), String> {
        if let Some(key) = &self.deployment_relay {
            let filter = deployment_filter(key);
            if filter.protect_bytes(plaintext)?.as_slice() != plaintext {
                return Err("Protected relay material refused before encryption.".into());
            }
        }
        Ok(())
    }
}

pub(super) fn deployment_filter(
    key: &crate::credential::RelayKey,
) -> crate::poc::inference::EchoFilter {
    let hex = Zeroizing::new(hex::encode(key.0));
    let upper = Zeroizing::new(hex.to_uppercase());
    crate::poc::inference::EchoFilter::new(&[&key.0, hex.as_bytes(), upper.as_bytes()])
}

impl<S: Storage + Clone, K: Kdf> Local<S, K> {
    pub(crate) fn deployment_relay_present(&self) -> bool {
        self.deployment_relay.is_some()
    }

    pub(crate) fn deployment_configure(
        &mut self,
        origin: Option<String>,
        input: &[u8],
        public_fields: &str,
    ) -> Result<bool, String> {
        if !matches!(self.state, State::Unopened) {
            return Err("Deployment material must arrive before opening the store.".into());
        }
        let relay = crate::credential::RelayKey::from_deployment(input);
        if let Some(key) = &relay {
            let filter = deployment_filter(key);
            // Refuse the whole defaults object before public fields can reach page sinks.
            // Scan the origin independently too: it becomes worker configuration below.
            for text in [public_fields, origin.as_deref().unwrap_or("")] {
                if !filter
                    .protect_bytes(text.as_bytes())
                    .is_ok_and(|safe| safe.as_slice() == text.as_bytes())
                {
                    self.deployment_origin = None;
                    self.deployment_relay = None;
                    return Ok(false);
                }
            }
        }
        self.deployment_origin = origin.map(|s| provider_origin(&s)).transpose()?;
        self.deployment_relay = relay;
        Ok(true)
    }

    pub(super) fn restore_deployment(&self, store: &mut Store<S>) {
        store.deployment_origin = self.deployment_origin.clone();
        store.deployment_relay = self
            .deployment_relay
            .as_ref()
            .map(|key| crate::credential::RelayKey(key.0));
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
