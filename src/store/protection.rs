//! Memory-only memo partitions for completed, unchanged protection checks.
use super::*;
use crate::poc::inference::{EchoCache, EchoFilter};
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;

type MemoDigest = sha2::digest::Output<Sha256>;

// Both limits include checked-out maps. A map has room for two full request
// working sets (about 65k records each), with another 50% headroom. The shared
// allowance exceeds three times the measured full-request aggregate (~280k).
const MAP_ENTRIES: u32 = 196_608;
const TOTAL_ENTRIES: usize = 917_504;
const BUCKETS: usize = 1_048_576;
const MAX_CHAIN: usize = 64;
const CHUNK_ENTRIES: usize = 4096;
const MAPS: usize = 1024;
const NONE: u32 = u32::MAX;

// Indices, not pointers: the layout is identical on wasm32 and the host. All
// allocation sizes are fixed; growing the pool never copies an existing chunk.
#[derive(Clone, Copy)]
struct Record {
    digest: MemoDigest,
    owner: u32,
    depth: u8,
    bucket_next: u32,
    newer: u32,
    older: u32,
    owner_newer: u32,
    owner_older: u32,
}

const _: () = assert!(std::mem::size_of::<Record>() == 60);

#[derive(Clone, Copy)]
struct RecordMap {
    newest: u32,
    oldest: u32,
    entries: u32,
    active: bool,
}

// Pool payload plus all chunk handles is below 57 MiB on both targets,
// including unused allocated slots. A further MiB covers the bounded partition
// index and handles; checked-out maps do not allocate another pool.
const _: () = assert!(
    TOTAL_ENTRIES * std::mem::size_of::<Record>()
        + BUCKETS * std::mem::size_of::<u32>()
        + MAPS * std::mem::size_of::<RecordMap>()
        + (TOTAL_ENTRIES / CHUNK_ENTRIES) * std::mem::size_of::<Box<[Record]>>()
        < 57 * 1024 * 1024
);

struct RecordPool {
    buckets: Box<[u32]>,
    chunks: Vec<Box<[Record]>>,
    maps: Box<[RecordMap]>,
    newest: u32,
    oldest: u32,
    free: u32,
    entries: usize,
}

impl RecordPool {
    fn new() -> Self {
        Self {
            buckets: vec![NONE; BUCKETS].into_boxed_slice(),
            chunks: Vec::with_capacity(TOTAL_ENTRIES / CHUNK_ENTRIES),
            maps: vec![
                RecordMap {
                    newest: NONE,
                    oldest: NONE,
                    entries: 0,
                    active: false,
                };
                MAPS
            ]
            .into_boxed_slice(),
            newest: NONE,
            oldest: NONE,
            free: NONE,
            entries: 0,
        }
    }

    fn record(&self, index: u32) -> &Record {
        &self.chunks[index as usize / CHUNK_ENTRIES][index as usize % CHUNK_ENTRIES]
    }

    fn record_mut(&mut self, index: u32) -> &mut Record {
        &mut self.chunks[index as usize / CHUNK_ENTRIES][index as usize % CHUNK_ENTRIES]
    }

    fn bucket(owner: u32, digest: &MemoDigest) -> usize {
        let prefix = u32::from_le_bytes(digest[..4].try_into().expect("digest prefix"));
        (prefix ^ owner.wrapping_mul(0x9e37_79b9)) as usize & (BUCKETS - 1)
    }

    fn find(&self, owner: u32, digest: &MemoDigest) -> (u32, usize) {
        let mut probes = 0;
        let mut index = self.buckets[Self::bucket(owner, digest)];
        while index != NONE {
            probes += 1;
            let record = self.record(index);
            if record.owner == owner && record.digest == *digest {
                return (index, probes);
            }
            index = record.bucket_next;
        }
        (NONE, probes)
    }

    fn unlink_recency(&mut self, index: u32) {
        let record = *self.record(index);
        if record.newer == NONE {
            self.newest = record.older;
        } else {
            self.record_mut(record.newer).older = record.older;
        }
        if record.older == NONE {
            self.oldest = record.newer;
        } else {
            self.record_mut(record.older).newer = record.newer;
        }
        if record.owner_newer == NONE {
            self.maps[record.owner as usize].newest = record.owner_older;
        } else {
            self.record_mut(record.owner_newer).owner_older = record.owner_older;
        }
        if record.owner_older == NONE {
            self.maps[record.owner as usize].oldest = record.owner_newer;
        } else {
            self.record_mut(record.owner_older).owner_newer = record.owner_newer;
        }
    }

    fn link_newest(&mut self, index: u32) {
        let owner = self.record(index).owner as usize;
        let newest = self.newest;
        let owner_newest = self.maps[owner].newest;
        let record = self.record_mut(index);
        record.newer = NONE;
        record.older = newest;
        record.owner_newer = NONE;
        record.owner_older = owner_newest;
        if newest == NONE {
            self.oldest = index;
        } else {
            self.record_mut(newest).newer = index;
        }
        if owner_newest == NONE {
            self.maps[owner].oldest = index;
        } else {
            self.record_mut(owner_newest).owner_newer = index;
        }
        self.newest = index;
        self.maps[owner].newest = index;
    }

    fn touch(&mut self, index: u32) {
        self.unlink_recency(index);
        self.link_newest(index);
    }

    fn remove(&mut self, index: u32) -> Record {
        let record = *self.record(index);
        self.unlink_recency(index);
        let bucket = Self::bucket(record.owner, &record.digest);
        let mut cursor = self.buckets[bucket];
        let mut previous = NONE;
        while cursor != index {
            previous = cursor;
            cursor = self.record(cursor).bucket_next;
        }
        if previous == NONE {
            self.buckets[bucket] = record.bucket_next;
        } else {
            self.record_mut(previous).bucket_next = record.bucket_next;
        }
        self.maps[record.owner as usize].entries -= 1;
        self.entries -= 1;
        self.record_mut(index).bucket_next = self.free;
        self.free = index;
        record
    }

    fn remember(&mut self, owner: u32, digest: MemoDigest, depth: u8) {
        let (index, probes) = self.find(owner, &digest);
        if index != NONE {
            // Only remember, after a complete clean check, can increase the depth.
            let record = self.record_mut(index);
            record.depth = record.depth.max(depth);
            self.touch(index);
            return;
        }
        // Even deliberately colliding bucket prefixes cannot make memo work
        // unbounded. Omitting a record only makes its next use recheck it.
        if probes >= MAX_CHAIN {
            return;
        }
        if self.maps[owner as usize].entries == MAP_ENTRIES {
            self.remove(self.maps[owner as usize].oldest);
        }
        if self.entries == TOTAL_ENTRIES {
            self.remove(self.oldest);
        }
        if self.free == NONE {
            let start = self.chunks.len() * CHUNK_ENTRIES;
            let mut chunk = vec![
                Record {
                    digest: MemoDigest::default(),
                    owner: NONE,
                    depth: 0,
                    bucket_next: NONE,
                    newer: NONE,
                    older: NONE,
                    owner_newer: NONE,
                    owner_older: NONE,
                };
                CHUNK_ENTRIES
            ]
            .into_boxed_slice();
            for (offset, record) in chunk.iter_mut().enumerate().take(CHUNK_ENTRIES - 1) {
                record.bucket_next = (start + offset + 1) as u32;
            }
            self.chunks.push(chunk);
            self.free = start as u32;
        }
        let index = self.free;
        self.free = self.record(index).bucket_next;
        let bucket = Self::bucket(owner, &digest);
        *self.record_mut(index) = Record {
            digest,
            owner,
            depth,
            bucket_next: self.buckets[bucket],
            newer: NONE,
            older: NONE,
            owner_newer: NONE,
            owner_older: NONE,
        };
        self.buckets[bucket] = index;
        self.link_newest(index);
        self.maps[owner as usize].entries += 1;
        self.entries += 1;
    }
}

// The single shared pool owns allocation and counts even while maps are checked
// out. Its RefCell is borrowed only for a lookup/insert, never across a check.
#[derive(Default)]
pub(crate) struct MemoBudget {
    pool: RefCell<Option<RecordPool>>,
}

#[derive(Default)]
pub(crate) struct CleanRecords {
    owner: Option<u32>,
    budget: Rc<MemoBudget>,
}

impl CleanRecords {
    pub(crate) fn new(budget: Rc<MemoBudget>) -> Self {
        Self {
            owner: None,
            budget,
        }
    }

    pub(crate) fn contains(&self, digest: &MemoDigest, depth: usize) -> bool {
        let Some(owner) = self.owner else {
            return false;
        };
        let mut pool = self.budget.pool.borrow_mut();
        let pool = pool.as_mut().expect("record owner has a pool");
        let (index, _) = pool.find(owner, digest);
        if index == NONE || depth > usize::from(pool.record(index).depth) {
            return false;
        }
        // A hit refreshes usefulness, without changing its digest or checked depth.
        pool.touch(index);
        true
    }

    pub(crate) fn clear(&mut self) {
        if let Some(owner) = self.owner.take() {
            let mut pool = self.budget.pool.borrow_mut();
            let pool = pool.as_mut().expect("record owner has a pool");
            while pool.maps[owner as usize].oldest != NONE {
                pool.remove(pool.maps[owner as usize].oldest);
            }
            pool.maps[owner as usize].active = false;
        }
    }

    pub(crate) fn remember(&mut self, digest: MemoDigest, depth: usize) {
        let mut pool = self.budget.pool.borrow_mut();
        let pool = pool.get_or_insert_with(RecordPool::new);
        let owner = match self.owner {
            Some(owner) => owner,
            None => {
                let Some(owner) = pool.maps.iter().position(|map| !map.active) else {
                    // Too many simultaneous checkouts only remove reuse.
                    return;
                };
                pool.maps[owner].active = true;
                self.owner = Some(owner as u32);
                owner as u32
            }
        };
        pool.remember(owner, digest, depth as u8);
    }

    pub(crate) fn merge(&mut self, mut other: Self) {
        if self.owner.is_none() && Rc::ptr_eq(&self.budget, &other.budget) {
            std::mem::swap(self, &mut other);
            return;
        }
        // Removing before reinsertion releases the source slot and count. Transfers
        // retain the exact digest/depth; duplicate depths both have clean proofs.
        if let Some(owner) = other.owner {
            loop {
                let record = {
                    let mut pool = other.budget.pool.borrow_mut();
                    let pool = pool.as_mut().expect("record owner has a pool");
                    let index = pool.maps[owner as usize].oldest;
                    if index == NONE {
                        break;
                    }
                    pool.remove(index)
                };
                self.remember(record.digest, usize::from(record.depth));
            }
        }
    }
}

impl Drop for CleanRecords {
    fn drop(&mut self) {
        self.clear();
    }
}

#[derive(Default)]
struct Partition<T> {
    key: Option<MemoDigest>,
    clean: T,
}

impl<T: Default> Partition<T> {
    fn take(&mut self, key: MemoDigest) -> T {
        if self.key.as_ref() != Some(&key) {
            self.key = Some(key);
            self.clean = T::default();
        }
        std::mem::take(&mut self.clean)
    }
}

#[derive(Default)]
pub(super) struct Memo {
    identity: BTreeMap<MemoDigest, EchoCache>,
    identity_order: VecDeque<MemoDigest>,
    decoded: Partition<EchoCache>,
    output: Partition<CleanRecords>,
    budget: Rc<MemoBudget>,
}

impl<S: Storage> Store<S> {
    pub(crate) fn with_identity_memo<T>(
        &self,
        key: MemoDigest,
        check: impl FnOnce(&mut EchoCache) -> T,
    ) -> T {
        let mut cache = {
            let mut memo = self.protection_memo.borrow_mut();
            memo.identity_order.retain(|previous| *previous != key);
            memo.identity
                .remove(&key)
                .unwrap_or_else(|| EchoCache::new(memo.budget.clone()))
        };
        cache.bind(key);
        // No memo borrow crosses a check or any callback into the store.
        let result = check(&mut cache);
        let mut memo = self.protection_memo.borrow_mut();
        // Evict only the least recently used resident filter partition.
        memo.identity_order.retain(|previous| *previous != key);
        if memo.identity.len() >= 64
            && !memo.identity.contains_key(&key)
            && let Some(oldest) = memo.identity_order.pop_front()
        {
            memo.identity.remove(&oldest);
        }
        memo.identity_order.push_back(key);
        let budget = memo.budget.clone();
        memo.identity
            .entry(key)
            .or_insert_with(|| EchoCache::new(budget))
            .merge(cache);
        result
    }

    fn scan_context(&self, hash: &mut Sha256) {
        // References::install and ::clear advance revision on every material change
        // (src/scan.rs); identities also cover replacement of the required inventory.
        hash.update(self.scans.revision().to_be_bytes());
        let identities = self.scans.identities();
        hash.update((identities.len() as u64).to_be_bytes());
        for identity in identities {
            hash.update((identity.len() as u64).to_be_bytes());
            hash.update(identity.as_bytes());
        }
    }

    pub(crate) fn with_decoded_memo<T>(
        &self,
        filter: &EchoFilter,
        check: impl FnOnce(&mut EchoCache) -> T,
    ) -> T {
        if self.scan_readiness().is_err() {
            return check(&mut EchoCache::default());
        }
        let Ok(held) = self.held_credentials() else {
            // A failed enumeration must never authorize a hit.
            return check(&mut EchoCache::default());
        };
        let mut hash = Sha256::new();
        hash.update(b"protection/echo/decoded/v1");
        hash.update(filter.pattern_digest());
        self.scan_context(&mut hash);
        hash.update(held.digest());
        drop(held);
        let key = hash.finalize();
        let mut cache = {
            let mut memo = self.protection_memo.borrow_mut();
            let mut cache = memo.decoded.take(key);
            cache.share_budget(memo.budget.clone());
            cache
        };
        cache.bind(key);
        let result = check(&mut cache);
        let mut memo = self.protection_memo.borrow_mut();
        // Reentrant work may replace the partition; never merge into a different key.
        if memo.decoded.key.as_ref() == Some(&key) {
            let mut shared = EchoCache::new(memo.budget.clone());
            shared.merge(std::mem::take(&mut memo.decoded.clean));
            shared.merge(cache);
            memo.decoded.clean = shared;
        }
        result
    }

    fn output_context(&self) -> Result<MemoDigest, String> {
        let mut hash = Sha256::new();
        hash.update(b"protection/output-bytes/v1");
        self.scan_context(&mut hash);
        let filters = self.poc_credential_filters.borrow();
        for filters in [filters.as_slice(), self.provider_filters.as_slice()] {
            hash.update((filters.len() as u64).to_be_bytes());
            for filter in filters {
                hash.update(filter.pattern_digest());
            }
        }
        hash.update([u8::from(self.deployment_relay.is_some())]);
        if let Some(key) = &self.deployment_relay {
            hash.update(super::provider::deployment_filter(key).pattern_digest());
        }
        hash.update(self.held_credentials()?.digest());
        Ok(hash.finalize())
    }

    pub(super) fn with_output_memo<T>(&self, check: impl FnOnce(&mut CleanRecords) -> T) -> T {
        let Ok(key) = self.output_context() else {
            return check(&mut CleanRecords::default());
        };
        let mut clean = {
            let mut memo = self.protection_memo.borrow_mut();
            let mut clean = memo.output.take(key);
            let mut shared = CleanRecords::new(memo.budget.clone());
            shared.merge(std::mem::take(&mut clean));
            shared
        };
        let result = check(&mut clean);
        let mut memo = self.protection_memo.borrow_mut();
        if memo.output.key.as_ref() == Some(&key) {
            let mut shared = CleanRecords::new(memo.budget.clone());
            shared.merge(std::mem::take(&mut memo.output.clean));
            shared.merge(clean);
            memo.output.clean = shared;
        }
        result
    }
}
