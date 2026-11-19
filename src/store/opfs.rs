//! The local store's browser half, in the harness worker: its directory in the origin-private
//! file system, and WebCrypto's PBKDF2. wasm32 only.

use super::{DIRECTORY, ITERATIONS, Kdf, ReplayReader, Salt, Storage};
use crate::credential::{LocalPassphrase, WrappingKey};
use js_sys::{Array, ArrayBuffer, Function, Promise, Reflect, Uint8Array};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::poll_fn;
use std::rc::Rc;
use std::task::{Poll, Waker};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    Blob, CryptoKey, FileSystemDirectoryHandle, FileSystemFileHandle,
    FileSystemGetDirectoryOptions, FileSystemGetFileOptions, FileSystemWritableFileStream,
    Pbkdf2Params, WorkerGlobalScope,
};

#[cfg(feature = "read-hooks")]
pub mod read_hooks;

const READ_WINDOW: u64 = 32;
const READ_CAP: u64 = 8 * 1024 * 1024;

#[derive(Default)]
struct Outstanding {
    count: usize,
    waiters: Vec<Waker>,
}

thread_local! {
    static OUTSTANDING: RefCell<Outstanding> = RefCell::default();
}

fn register(waiters: &mut Vec<Waker>, waker: &Waker) {
    if !waiters.iter().any(|old| old.will_wake(waker)) {
        waiters.push(waker.clone());
    }
}

fn wake(waiters: Vec<Waker>) {
    for waiter in waiters {
        waiter.wake();
    }
}

/// Called under local() before an unlock can acquire another reader. No polling timer.
pub async fn drain_reads() {
    poll_fn(|cx| {
        OUTSTANDING.with_borrow_mut(|outstanding| {
            if outstanding.count == 0 {
                Poll::Ready(())
            } else {
                register(&mut outstanding.waiters, cx.waker());
                Poll::Pending
            }
        })
    })
    .await;
}

struct Task;

impl Task {
    fn start() -> Self {
        OUTSTANDING.with_borrow_mut(|outstanding| outstanding.count += 1);
        #[cfg(feature = "read-hooks")]
        read_hooks::outstanding();
        Self
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        let waiters = OUTSTANDING.with_borrow_mut(|outstanding| {
            outstanding.count -= 1;
            if outstanding.count == 0 {
                std::mem::take(&mut outstanding.waiters)
            } else {
                Vec::new()
            }
        });
        #[cfg(feature = "read-hooks")]
        read_hooks::outstanding();
        wake(waiters);
    }
}

enum Directory {
    Pending,
    Ready(FileSystemDirectoryHandle),
    Failed,
}

struct ReadState {
    abandoned: bool,
    directory: Directory,
    next_admission: u64,
    oldest: u64,
    reserved: u64,
    waiters: Vec<Waker>,
}

struct Shared(RefCell<ReadState>);

impl Shared {
    fn abandoned(&self) -> bool {
        self.0.borrow().abandoned
    }

    fn notify(&self) {
        let waiters = std::mem::take(&mut self.0.borrow_mut().waiters);
        wake(waiters);
    }

    async fn stage(&self, _number: u64, _stage: &str) -> bool {
        if self.abandoned() {
            return false;
        }
        #[cfg(feature = "read-hooks")]
        if !read_hooks::gate(self, _number, _stage).await {
            return false;
        }
        if self.abandoned() {
            return false;
        }
        #[cfg(feature = "read-hooks")]
        read_hooks::started(self, _number, _stage);
        true
    }

    async fn directory(
        &self,
        #[cfg(feature = "read-hooks")] number: u64,
    ) -> Option<FileSystemDirectoryHandle> {
        #[cfg(feature = "read-hooks")]
        let mut waited = false;
        poll_fn(|cx| {
            let mut state = self.0.borrow_mut();
            if state.abandoned {
                return Poll::Ready(None);
            }
            match &state.directory {
                Directory::Ready(directory) => Poll::Ready(Some(directory.clone())),
                Directory::Failed => Poll::Ready(None),
                Directory::Pending => {
                    #[cfg(feature = "read-hooks")]
                    if !waited {
                        waited = true;
                        read_hooks::event("directory-wait", Some(number));
                    }
                    register(&mut state.waiters, cx.waker());
                    Poll::Pending
                }
            }
        })
        .await
    }

    fn abandon(&self) {
        let was_abandoned = {
            let mut state = self.0.borrow_mut();
            std::mem::replace(&mut state.abandoned, true)
        };
        if !was_abandoned {
            #[cfg(feature = "read-hooks")]
            read_hooks::event("abandoned", None);
        }
        self.notify();
    }

    async fn admit(self: &Rc<Self>, number: u64, size: u64) -> Option<Reservation> {
        #[cfg(feature = "read-hooks")]
        let mut waited = false;
        poll_fn(|cx| {
            let mut state = self.0.borrow_mut();
            if state.abandoned {
                return Poll::Ready(None);
            }
            let fits = if size > READ_CAP {
                number == state.oldest && state.reserved == 0
            } else {
                state.reserved <= READ_CAP - size
            };
            if number == state.next_admission && fits {
                state.reserved += size;
                state.next_admission += 1;
                #[cfg(feature = "read-hooks")]
                read_hooks::reserved(state.reserved, state.oldest, number, size);
                drop(state);
                self.notify();
                Poll::Ready(Some(Reservation {
                    shared: self.clone(),
                    size,
                }))
            } else {
                #[cfg(feature = "read-hooks")]
                if !waited {
                    waited = true;
                    read_hooks::event("admission-wait", Some(number));
                }
                register(&mut state.waiters, cx.waker());
                Poll::Pending
            }
        })
        .await
    }
}

struct Reservation {
    shared: Rc<Shared>,
    size: u64,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut state = self.shared.0.borrow_mut();
        state.reserved -= self.size;
        #[cfg(feature = "read-hooks")]
        read_hooks::released(state.reserved);
        drop(state);
        self.shared.notify();
    }
}

struct Buffered {
    bytes: ArrayBuffer,
    _reservation: Reservation,
    #[cfg(feature = "read-hooks")]
    _retained: read_hooks::Retained,
}

#[derive(Default)]
struct Slot {
    result: RefCell<Option<Result<Buffered, String>>>,
    waiter: RefCell<Option<Waker>>,
}

/// One replay's directory and at most W started-but-unused slots. No handle survives replay.
pub struct Reader {
    shared: Rc<Shared>,
    slots: VecDeque<Rc<Slot>>,
    issued: u64,
    end: u64,
}

impl Reader {
    fn new(numbers: &[u64]) -> Self {
        // The first gap is known before issuance. The gap check itself remains in replay.
        let end = (0u64..)
            .zip(numbers)
            .take_while(|(expected, number)| expected == *number)
            .count() as u64;
        let shared = Rc::new(Shared(RefCell::new(ReadState {
            abandoned: false,
            directory: Directory::Pending,
            next_admission: 0,
            oldest: 0,
            reserved: 0,
            waiters: Vec::new(),
        })));
        #[cfg(feature = "read-hooks")]
        read_hooks::reader(&shared);
        Self {
            shared,
            slots: VecDeque::new(),
            issued: 0,
            end,
        }
    }

    fn fill(&mut self) {
        while self.issued < self.end && self.slots.len() < READ_WINDOW as usize {
            if self.shared.abandoned() {
                return;
            }
            let number = self.issued;
            self.issued += 1;
            let slot = Rc::new(Slot::default());
            self.slots.push_back(slot.clone());
            let shared = self.shared.clone();
            let task = Task::start();
            #[cfg(feature = "read-hooks")]
            read_hooks::event("issued", Some(number));
            wasm_bindgen_futures::spawn_local(async move {
                let _task = task;
                let result = read_one(&shared, number).await;
                if !shared.abandoned() {
                    let result = match result {
                        Ok(Some(buffer)) => Some(Ok(buffer)),
                        Ok(None) => None,
                        Err(error) => Some(Err(error)),
                    };
                    *slot.result.borrow_mut() = result;
                    if let Some(waiter) = slot.waiter.borrow_mut().take() {
                        waiter.wake();
                    }
                }
                // Dropped late buffers release their reservations before Task decrements.
            });
        }
    }

    pub(super) async fn read(&mut self, number: u64) -> Result<Vec<u8>, String> {
        // Refill only on the next read, after replay has used the preceding record.
        self.fill();
        let slot = self.slots.front().expect("replay checked the gap").clone();
        let result = poll_fn(|cx| {
            if self.shared.abandoned() {
                return Poll::Ready(Err("replay reader was abandoned".to_string()));
            }
            if let Some(result) = slot.result.borrow_mut().take() {
                Poll::Ready(result)
            } else {
                *slot.waiter.borrow_mut() = Some(cx.waker().clone());
                register(&mut self.shared.0.borrow_mut().waiters, cx.waker());
                Poll::Pending
            }
        })
        .await?;
        if !self.shared.stage(number, "copy").await {
            return Err("replay reader was abandoned".into());
        }
        // Only this record's turn can allocate its bytes in wasm.
        let bytes = Uint8Array::new(&result.bytes).to_vec();
        drop(result);
        self.slots.pop_front();
        self.shared.0.borrow_mut().oldest = number + 1;
        self.shared.notify();
        Ok(bytes)
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        self.shared.abandon();
        // Release completed slots now; tasks holding browser calls release on settlement.
        self.slots.clear();
    }
}

fn not_found(error: &JsValue) -> bool {
    Reflect::get(error, &"name".into()).ok() == Some("NotFoundError".into())
}

/// Construct and immediately await each promise inside its spawned task, including rejects.
async fn call(
    shared: &Shared,
    number: u64,
    stage: &str,
    start: impl FnOnce() -> Promise,
) -> Option<Result<JsValue, JsValue>> {
    if !shared.stage(number, stage).await {
        return None;
    }
    let result = JsFuture::from(start()).await;
    #[cfg(feature = "read-hooks")]
    read_hooks::settled(shared, number, stage);
    if shared.abandoned() {
        None
    } else {
        Some(result)
    }
}

/// Same classification as Opfs::directory(false), scoped to this reader and hookable.
async fn read_directory(
    shared: &Shared,
    number: u64,
    fallback: bool,
) -> Result<Option<FileSystemDirectoryHandle>, String> {
    let root_stage = if fallback { "fallback-root" } else { "root" };
    let Some(root) = call(shared, number, root_stage, || {
        scope().navigator().storage().get_directory()
    })
    .await
    else {
        return Ok(None);
    };
    let root: FileSystemDirectoryHandle = root
        .map_err(why(crate::poc::wait::OPFS_CONTEXT))?
        .unchecked_into();
    let options = FileSystemGetDirectoryOptions::new();
    options.set_create(false);
    let stage = if fallback {
        "fallback-directory"
    } else {
        "directory"
    };
    let Some(directory) = call(shared, number, stage, || {
        root.get_directory_handle_with_options(DIRECTORY, &options)
    })
    .await
    else {
        return Ok(None);
    };
    match directory {
        Ok(directory) => Ok(Some(directory.unchecked_into())),
        Err(error) if not_found(&error) => Err(crate::poc::wait::directory_missing()),
        Err(error) => Err(why(DIRECTORY)(error)),
    }
}

async fn read_file(
    shared: &Shared,
    number: u64,
    directory: &FileSystemDirectoryHandle,
    fallback: bool,
) -> Option<Result<Blob, FileError>> {
    let name = number.to_string();
    let options = FileSystemGetFileOptions::new();
    options.set_create(false);
    let stage = if fallback {
        "fallback-file-handle"
    } else {
        "file-handle"
    };
    let handle = match call(shared, number, stage, || {
        directory.get_file_handle_with_options(&name, &options)
    })
    .await?
    {
        Ok(handle) => handle.unchecked_into::<FileSystemFileHandle>(),
        Err(error) => return Some(Err(FileError::at(&name, error))),
    };
    let stage = if fallback { "fallback-file" } else { "file" };
    Some(
        call(shared, number, stage, || handle.get_file())
            .await?
            .map(JsCast::unchecked_into)
            .map_err(|error| FileError::at(&name, error)),
    )
}

struct FileError {
    missing: bool,
    message: String,
}

impl FileError {
    fn at(name: &str, error: JsValue) -> Self {
        Self {
            missing: not_found(&error),
            message: why(name)(error),
        }
    }
}

async fn read_one(shared: &Rc<Shared>, number: u64) -> Result<Option<Buffered>, String> {
    let directory = if number == 0 {
        let result = read_directory(shared, number, false).await;
        match &result {
            Ok(Some(directory)) => {
                shared.0.borrow_mut().directory = Directory::Ready(directory.clone());
            }
            _ => shared.0.borrow_mut().directory = Directory::Failed,
        }
        shared.notify();
        result?
    } else {
        shared
            .directory(
                #[cfg(feature = "read-hooks")]
                number,
            )
            .await
    };
    let Some(directory) = directory else {
        return Ok(None);
    };
    let name = number.to_string();
    let Some(file) = read_file(shared, number, &directory, false).await else {
        return Ok(None);
    };
    let file = match file {
        Ok(file) => file,
        Err(error) if error.missing => {
            // Re-resolve root -> directory -> file on the error path, keeping today's
            // directory-missing / OPFS / record-name diagnostic precedence.
            let Some(directory) = read_directory(shared, number, true).await? else {
                return Ok(None);
            };
            let Some(file) = read_file(shared, number, &directory, true).await else {
                return Ok(None);
            };
            file.map_err(|error| error.message)?
        }
        Err(error) => return Err(error.message),
    };
    if !shared.stage(number, "file-ready").await {
        return Ok(None);
    }
    let size = file.size() as u64;
    if !shared.stage(number, "admission").await {
        return Ok(None);
    }
    let Some(reservation) = shared.admit(number, size).await else {
        return Ok(None);
    };
    if !shared.stage(number, "array-buffer").await {
        return Ok(None);
    }
    // Independently measure pending and retained JS bytes, starting at the actual call.
    #[cfg(feature = "read-hooks")]
    let retained = read_hooks::Retained::new(shared, number, size);
    let result = JsFuture::from(file.array_buffer()).await;
    #[cfg(feature = "read-hooks")]
    read_hooks::settled(shared, number, "array-buffer");
    let bytes = match result {
        Ok(bytes) if !shared.abandoned() => bytes.unchecked_into(),
        Ok(_) => return Ok(None),
        Err(error) => {
            // Do not hold capacity until the failed record's consumption turn.
            drop(reservation);
            return Err(why(&name)(error));
        }
    };
    let buffer = Buffered {
        bytes,
        _reservation: reservation,
        #[cfg(feature = "read-hooks")]
        _retained: retained,
    };
    if !shared.stage(number, "array-buffer-ready").await {
        return Ok(None);
    }
    Ok(Some(buffer))
}

fn scope() -> WorkerGlobalScope {
    js_sys::global().unchecked_into()
}

fn why(context: &str) -> impl Fn(JsValue) -> String + '_ {
    move |e| match e.dyn_ref::<js_sys::Error>() {
        Some(error) => crate::poc::wait::storage_error(context, &String::from(error.message())),
        None => crate::poc::wait::storage_error(context, &format!("{e:?}")),
    }
}

async fn wait(promise: Promise, context: &str) -> Result<JsValue, String> {
    JsFuture::from(promise).await.map_err(why(context))
}

/// The store's directory in OPFS.
#[derive(Clone, Default)]
pub struct Opfs {
    /// The tracer's `fail_append`: the next move is made to a name OPFS rejects, so the real
    /// append fails at a storage call.
    #[cfg(feature = "tracer")]
    pub fail_next_move: std::rc::Rc<std::cell::Cell<bool>>,
}

impl Opfs {
    /// The directory, or `None` if it does not exist and `create` is not set.
    async fn directory(&self, create: bool) -> Result<Option<FileSystemDirectoryHandle>, String> {
        let root = wait(
            scope().navigator().storage().get_directory(),
            crate::poc::wait::OPFS_CONTEXT,
        )
        .await?;
        let root: FileSystemDirectoryHandle = root.unchecked_into();
        let options = FileSystemGetDirectoryOptions::new();
        options.set_create(create);
        match JsFuture::from(root.get_directory_handle_with_options(DIRECTORY, &options)).await {
            Ok(directory) => Ok(Some(directory.unchecked_into())),
            Err(e)
                if !create
                    && Reflect::get(&e, &"name".into()).ok() == Some("NotFoundError".into()) =>
            {
                Ok(None)
            }
            Err(e) => Err(why(DIRECTORY)(e)),
        }
    }

    async fn file(&self, name: &str, create: bool) -> Result<FileSystemFileHandle, String> {
        let directory = self
            .directory(create)
            .await?
            .ok_or_else(crate::poc::wait::directory_missing)?;
        let options = FileSystemGetFileOptions::new();
        options.set_create(create);
        let file = wait(directory.get_file_handle_with_options(name, &options), name).await?;
        Ok(file.unchecked_into())
    }
}

impl Storage for Opfs {
    fn reader(&self, numbers: &[u64]) -> ReplayReader {
        ReplayReader::Opfs(Reader::new(numbers))
    }

    async fn list(&self) -> Result<Vec<String>, String> {
        let Some(directory) = self.directory(false).await? else {
            return Ok(Vec::new());
        };
        let names = directory.keys();
        let mut found = Vec::new();
        loop {
            let next = wait(names.next().map_err(why("list"))?, "list").await?;
            if Reflect::get(&next, &"done".into()).map_err(why("list"))? == JsValue::TRUE {
                return Ok(found);
            }
            let name = Reflect::get(&next, &"value".into()).map_err(why("list"))?;
            found.push(
                name.as_string()
                    .ok_or("list: a name that is not a string")?,
            );
        }
    }

    async fn read(&self, name: &str) -> Result<Vec<u8>, String> {
        let file = wait(self.file(name, false).await?.get_file(), name).await?;
        let bytes = wait(file.unchecked_into::<Blob>().array_buffer(), name).await?;
        Ok(Uint8Array::new(&bytes).to_vec())
    }

    async fn write(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        let file = self.file(name, true).await?;
        let stream = wait(file.create_writable(), name).await?;
        let stream: FileSystemWritableFileStream = stream.unchecked_into();
        wait(stream.write_with_u8_array(bytes).map_err(why(name))?, name).await?;
        wait(stream.close(), name).await?;
        Ok(())
    }

    /// `FileSystemHandle.move()`, which web-sys does not bind.
    async fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        #[cfg(feature = "tracer")]
        let to = if self.fail_next_move.replace(false) {
            ".."
        } else {
            to
        };
        #[cfg(feature = "tracer")]
        crate::testonly::hold_move().await?;
        let file = self.file(from, false).await?;
        let move_to: Function = Reflect::get(&file, &"move".into())
            .map_err(why(crate::poc::wait::MOVE_CONTEXT))?
            .dyn_into()
            .map_err(|_| crate::poc::wait::MOVE_UNAVAILABLE.to_string())?;
        let promise = move_to
            .call1(&file, &to.into())
            .map_err(why(crate::poc::wait::MOVE_CONTEXT))?;
        wait(
            promise.unchecked_into(),
            &crate::poc::wait::move_context(from, to),
        )
        .await?;
        Ok(())
    }
}

/// WebCrypto's PBKDF2-HMAC-SHA-256 (credential format v1: "This uses WebCrypto's native KDF").
pub struct WebCrypto;

impl Kdf for WebCrypto {
    async fn derive(
        &self,
        passphrase: LocalPassphrase,
        salt: &Salt,
    ) -> Result<WrappingKey, String> {
        // JavaScript's garbage collector clears nothing, so the copy handed to `importKey` and the
        // buffer `deriveBits` returns are zero-filled here (`SEC-5` rows 18 and 19).
        let bytes = Uint8Array::from(&passphrase.0[..]);
        let derived = async {
            let subtle = scope().crypto().map_err(why("crypto"))?.subtle();
            let usages = Array::of1(&"deriveBits".into());
            let imported = subtle
                .import_key_with_str("raw", &bytes, "PBKDF2", false, &usages)
                .map_err(why("importKey"))?;
            let key: CryptoKey = wait(imported, "importKey").await?.unchecked_into();
            let params = Pbkdf2Params::new_with_str(
                "PBKDF2",
                "SHA-256",
                ITERATIONS,
                &Uint8Array::from(&salt.0[..]),
            );
            let bits = subtle
                .derive_bits_with_object(&params, &key, 256)
                .map_err(why("deriveBits"))?;
            wait(bits, "deriveBits").await
        }
        .await;
        bytes.fill(0, 0, bytes.length());
        drop(passphrase);
        let bits = Uint8Array::new(&derived?.unchecked_into::<ArrayBuffer>());
        let mut key = WrappingKey([0; 32]);
        if bits.length() != 32 {
            bits.fill(0, 0, bits.length());
            return Err(format!("deriveBits: {} bytes, not 32", bits.length()));
        }
        bits.copy_to(&mut key.0);
        bits.fill(0, 0, 32);
        Ok(key)
    }
}
