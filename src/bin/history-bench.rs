//! Offline fixture benchmark. This allocator counts requested live bytes, not RSS.
#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub struct Counting;
    static LIVE: AtomicUsize = AtomicUsize::new(0);
    static PEAK: AtomicUsize = AtomicUsize::new(0);

    fn added(bytes: usize) {
        let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
        PEAK.fetch_max(live, Ordering::Relaxed);
    }

    // SAFETY: every request is forwarded unchanged to System, including alignment and
    // realloc failure semantics. Counters allocate nothing and never inspect memory.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let pointer = unsafe { System.alloc(layout) };
            if !pointer.is_null() {
                added(layout.size());
            }
            pointer
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            let pointer = unsafe { System.alloc_zeroed(layout) };
            if !pointer.is_null() {
                added(layout.size());
            }
            pointer
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            unsafe { System.dealloc(pointer, layout) };
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            let result = unsafe { System.realloc(pointer, layout, size) };
            if !result.is_null() {
                if size >= layout.size() {
                    added(size - layout.size());
                } else {
                    LIVE.fetch_sub(layout.size() - size, Ordering::Relaxed);
                }
            }
            result
        }
    }

    pub fn run() -> Result<(), &'static str> {
        tau_web::store::history_bench::run(tau_web::store::history_bench::MemoryMeter {
            live: || LIVE.load(Ordering::Relaxed),
            peak: || PEAK.load(Ordering::Relaxed),
            reset_peak: || PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed),
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[global_allocator]
static ALLOCATOR: native::Counting = native::Counting;

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    std::panic::set_hook(Box::new(|_| eprintln!("benchmark_panic 1")));
    if let Err(name) = native::run() {
        // Only a fixed stage name escapes; product errors may contain journal values.
        eprintln!("{name} 1");
        std::process::exit(1);
    }
}

#[cfg(target_arch = "wasm32")]
fn main() {}
