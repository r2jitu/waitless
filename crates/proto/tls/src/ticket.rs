// TLS 1.3 session-ticket envelope.
//
// Seals an opaque resumption blob under a process-wide AES-128-GCM
// key, using a 16-byte key name as both routing tag (for future key
// rotation) and AEAD AAD. The plaintext schema is fixed: version byte,
// resumption_master_secret, ticket_age_add, issued_at_cycles,
// cipher_suite. `open_ticket` enforces a freshness window via
// `now_cycles - issued_at_cycles` against a caller-supplied
// `max_age_cycles` (caller computes that from a wall-clock-ish
// duration via `kernel::time::cycles_per_us`).
//
// Single-key, no rotation: the key is generated lazily from kernel
// RNG on first use and lives for the rest of the process. Real
// rotation (a 2-key ring with an "old key still accepts" window) is a
// separate follow-up — the binders / ticket-emission machinery is
// independent of how many keys we keep around.
//
// SAFETY: the `OnceTicketKey` cell uses an `UnsafeCell<MaybeUninit<T>>`
// behind an `AtomicU8` state machine (0=empty, 1=writing, 2=ready).
// Only the thread that wins the 0→1 CAS writes the value; readers
// observe state==2 via Acquire and only then read the value. The
// state==1 spin window covers two `getrandom` calls — microseconds —
// so contention on the very first handshake is bounded.
//
// `seal_under_key` / `open_under_key` are the key-injectable inner
// forms of the seal/open primitives, exercised by the in-module test
// suite; production paths use the global-key wrappers.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::aead::{KEY_LEN, NONCE_LEN, TAG_LEN, open, seal};
use crate::schedule::secure_zero;

/// Plaintext schema version. Bumped whenever the field layout below
/// changes incompatibly; `open_ticket` rejects any other value so
/// stale tickets after a code change can't be confused with current
/// ones.
pub const TICKET_VERSION: u8 = 1;

/// Length of the routing/key-identifier prefix prepended to every
/// sealed ticket. Lets a future key-rotation pass keep multiple
/// active keys around without re-deriving on every accept.
pub const KEY_NAME_LEN: usize = 16;

/// Encoded length of `TicketPlaintext`:
///   1 (version) + 32 (rms) + 4 (age_add) + 8 (issued_at) + 2 (suite).
pub const PLAINTEXT_LEN: usize = 1 + 32 + 4 + 8 + 2;

/// Total bytes a sealed ticket occupies on the wire.
/// Layout: `key_name(16) || nonce(12) || ciphertext(47) || tag(16)`.
pub const SEALED_LEN: usize = KEY_NAME_LEN + NONCE_LEN + PLAINTEXT_LEN + TAG_LEN;

/// `ticket_lifetime` we advertise to clients in NewSessionTicket
/// (RFC 8446 §4.6.1 — clients SHOULD discard a ticket older than this).
/// The hard server-side freshness window is enforced separately by
/// `open_ticket` via `max_age_cycles`. Capped at the spec's 7-day max.
pub const TICKET_LIFETIME_SECONDS: u32 = 7 * 24 * 3600;

/// Wall-style monotonic counter used by `seal_ticket` for the
/// `issued_at_cycles` field, and by `open_ticket` for the freshness
/// check. Cycles, not seconds — `cycles_per_us` calibration is the
/// kernel's responsibility. On bare-metal this is `CNTVCT_EL0` (or
/// the x86 equivalent); native builds don't have a unified clock
/// yet so they return 0, which effectively disables the freshness
/// window — tickets still seal/open correctly, just don't expire.
///
/// Public so the QUIC handshake driver can call it without
/// duplicating the cfg dance.
#[cfg(target_os = "none")]
pub fn now_cycles() -> u64 {
    kernel_bare::time::now_cycles()
}
#[cfg(not(target_os = "none"))]
pub fn now_cycles() -> u64 {
    0
}

/// Microseconds since boot. Companion to `now_cycles` for callers
/// that want a wall-clock-ish duration rather than raw cycles —
/// idle-timeout deadlines, rate-limit windows, RTT estimates. On
/// bare-metal this is `kernel::time::since_boot_us`. Native builds
/// return 0 for the same reason `now_cycles` does (no unified
/// monotonic clock yet); callers that depend on actual elapsed
/// microseconds will see "no timeout ever" on native, which is
/// fine for the integration tests we run there today.
#[cfg(target_os = "none")]
pub fn now_us() -> u64 {
    kernel_bare::time::since_boot_us()
}
#[cfg(not(target_os = "none"))]
pub fn now_us() -> u64 {
    0
}

/// Decoded ticket payload — what `seal_ticket` consumes and
/// `open_ticket` produces. `version` is always `TICKET_VERSION` after
/// a successful open; we surface it for symmetry with the wire layout.
pub struct TicketPlaintext {
    pub version: u8,
    pub resumption_master_secret: [u8; 32],
    pub ticket_age_add: u32,
    pub issued_at_cycles: u64,
    pub cipher_suite: u16,
}

impl Drop for TicketPlaintext {
    fn drop(&mut self) {
        secure_zero(&mut self.resumption_master_secret);
    }
}

/// Process-wide AEAD key + identifier. Generated lazily; never rotated.
pub struct TicketKey {
    pub name: [u8; KEY_NAME_LEN],
    pub key: [u8; KEY_LEN],
}

impl Drop for TicketKey {
    fn drop(&mut self) {
        secure_zero(&mut self.key);
    }
}

// ── Race-safe lazy global ──────────────────────────────────────────────

/// State values for `OnceTicketKey.state`.
const ONCE_EMPTY: u8 = 0;
const ONCE_WRITING: u8 = 1;
const ONCE_READY: u8 = 2;

struct OnceTicketKey {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<TicketKey>>,
}

// SAFETY: `state` synchronises access. Only the CAS winner writes;
// readers acquire `state == ONCE_READY` and treat `value` as immutable.
unsafe impl Sync for OnceTicketKey {}

impl OnceTicketKey {
    const fn new() -> Self {
        OnceTicketKey {
            state: AtomicU8::new(ONCE_EMPTY),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn get(&self) -> Option<&TicketKey> {
        if self.state.load(Ordering::Acquire) == ONCE_READY {
            // SAFETY: state==ONCE_READY synchronises with the Release
            // store after the value write.
            Some(unsafe { (*self.value.get()).assume_init_ref() })
        } else {
            None
        }
    }

    fn get_or_init<F: FnOnce() -> TicketKey>(&self, f: F) -> &TicketKey {
        loop {
            match self.state.load(Ordering::Acquire) {
                ONCE_READY => {
                    return unsafe { (*self.value.get()).assume_init_ref() };
                }
                ONCE_EMPTY => {
                    if self
                        .state
                        .compare_exchange(
                            ONCE_EMPTY,
                            ONCE_WRITING,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        let v = f();
                        // SAFETY: we hold the WRITING claim; no other
                        // writer races and no reader will dereference
                        // until we publish ONCE_READY.
                        unsafe {
                            (*self.value.get()).write(v);
                        }
                        self.state.store(ONCE_READY, Ordering::Release);
                        return unsafe { (*self.value.get()).assume_init_ref() };
                    }
                }
                _ => core::hint::spin_loop(),
            }
        }
    }
}

static GLOBAL_TICKET_KEY: OnceTicketKey = OnceTicketKey::new();

/// Get (and on first call, generate) the process-wide ticket key.
/// Generation pulls 48 bytes from the kernel RNG (16 for the name,
/// 32 for the AEAD key). The bare-metal RNG is wired up before
/// `uni_init` runs, so the first handshake always sees a usable
/// entropy source.
pub fn current_ticket_key() -> &'static TicketKey {
    GLOBAL_TICKET_KEY.get_or_init(|| {
        let mut name = [0u8; KEY_NAME_LEN];
        let mut key = [0u8; KEY_LEN];
        getrandom::getrandom(&mut name).expect("ticket key: rng (name)");
        getrandom::getrandom(&mut key).expect("ticket key: rng (key)");
        TicketKey { name, key }
    })
}

// ── Public API ────────────────────────────────────────────────────────

/// Seal `pt` under the global ticket key, writing `SEALED_LEN` bytes
/// to the front of `out`. Returns the number of bytes written, or
/// `None` if the buffer is too small or RNG fails.
pub fn seal_ticket(pt: &TicketPlaintext, out: &mut [u8]) -> Option<usize> {
    seal_under_key(current_ticket_key(), pt, out)
}

/// Open a previously-sealed ticket. Returns `None` if:
/// - the wire length is wrong,
/// - the global ticket key was never initialised (we never sealed),
/// - the embedded `key_name` doesn't match the current ticket key,
/// - the AEAD tag fails (tampering / wrong key),
/// - the embedded `version` byte is unknown,
/// - the ticket is older than `max_age_cycles`.
///
/// `now_cycles` and `max_age_cycles` are caller-supplied so this
/// module doesn't depend on `kernel::time` (it lives in `tls`,
/// which compiles on native too). Caller derives `max_age_cycles`
/// from a wall-clockish duration via `cycles_per_us`.
pub fn open_ticket(sealed: &[u8], now_cycles: u64, max_age_cycles: u64) -> Option<TicketPlaintext> {
    open_under_key(GLOBAL_TICKET_KEY.get()?, sealed, now_cycles, max_age_cycles)
}

// ── Key-injectable inner forms (used by tests + the public wrappers) ──

pub(super) fn seal_under_key(
    tk: &TicketKey,
    pt: &TicketPlaintext,
    out: &mut [u8],
) -> Option<usize> {
    if out.len() < SEALED_LEN {
        return None;
    }

    // Encode the plaintext into a stack buffer.
    let mut plain = [0u8; PLAINTEXT_LEN];
    plain[0] = pt.version;
    plain[1..33].copy_from_slice(&pt.resumption_master_secret);
    plain[33..37].copy_from_slice(&pt.ticket_age_add.to_be_bytes());
    plain[37..45].copy_from_slice(&pt.issued_at_cycles.to_be_bytes());
    plain[45..47].copy_from_slice(&pt.cipher_suite.to_be_bytes());

    // Random 96-bit nonce per ticket (collision risk with 2^32 tickets
    // under one key is far below acceptable for a dev key).
    let mut nonce = [0u8; NONCE_LEN];
    if getrandom::getrandom(&mut nonce).is_err() {
        secure_zero(&mut plain);
        return None;
    }

    // Frame: [name(16) | nonce(12) | ciphertext(47) | tag(16)]
    let ct_start = KEY_NAME_LEN + NONCE_LEN;
    out[..KEY_NAME_LEN].copy_from_slice(&tk.name);
    out[KEY_NAME_LEN..ct_start].copy_from_slice(&nonce);
    out[ct_start..ct_start + PLAINTEXT_LEN].copy_from_slice(&plain);
    secure_zero(&mut plain);

    // AAD = key name. Guards against a tag from another key being
    // pasted onto a name belonging to this one (defence in depth —
    // the key would also have to match for AEAD to succeed).
    let tag = seal(
        &tk.key,
        &nonce,
        &tk.name,
        &mut out[ct_start..ct_start + PLAINTEXT_LEN],
    );
    out[ct_start + PLAINTEXT_LEN..ct_start + PLAINTEXT_LEN + TAG_LEN].copy_from_slice(&tag);

    Some(SEALED_LEN)
}

pub(super) fn open_under_key(
    tk: &TicketKey,
    sealed: &[u8],
    now_cycles: u64,
    max_age_cycles: u64,
) -> Option<TicketPlaintext> {
    if sealed.len() != SEALED_LEN {
        return None;
    }
    // Constant-time-ish key-name compare (length is fixed).
    if sealed[..KEY_NAME_LEN] != tk.name[..] {
        return None;
    }

    let nonce: [u8; NONCE_LEN] = sealed[KEY_NAME_LEN..KEY_NAME_LEN + NONCE_LEN]
        .try_into()
        .ok()?;
    let ct_start = KEY_NAME_LEN + NONCE_LEN;
    let mut buf = [0u8; PLAINTEXT_LEN];
    buf.copy_from_slice(&sealed[ct_start..ct_start + PLAINTEXT_LEN]);
    let tag: [u8; TAG_LEN] = sealed[ct_start + PLAINTEXT_LEN..ct_start + PLAINTEXT_LEN + TAG_LEN]
        .try_into()
        .ok()?;

    if open(&tk.key, &nonce, &tk.name, &mut buf, &tag).is_err() {
        return None;
    }

    let version = buf[0];
    if version != TICKET_VERSION {
        secure_zero(&mut buf);
        return None;
    }

    let mut rms = [0u8; 32];
    rms.copy_from_slice(&buf[1..33]);
    let age_add = u32::from_be_bytes([buf[33], buf[34], buf[35], buf[36]]);
    let issued = u64::from_be_bytes([
        buf[37], buf[38], buf[39], buf[40], buf[41], buf[42], buf[43], buf[44],
    ]);
    let suite = u16::from_be_bytes([buf[45], buf[46]]);
    secure_zero(&mut buf);

    // Freshness window. `wrapping_sub` keeps us correct across the
    // u64 cycle counter wrap (~200 years at 3 GHz, but cheap to do).
    let age = now_cycles.wrapping_sub(issued);
    if age > max_age_cycles {
        secure_zero(&mut rms);
        return None;
    }

    Some(TicketPlaintext {
        version,
        resumption_master_secret: rms,
        ticket_age_add: age_add,
        issued_at_cycles: issued,
        cipher_suite: suite,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> TicketKey {
        TicketKey {
            name: [0xAA; KEY_NAME_LEN],
            key: [0xBB; KEY_LEN],
        }
    }

    fn sample_pt() -> TicketPlaintext {
        TicketPlaintext {
            version: TICKET_VERSION,
            resumption_master_secret: [0xCC; 32],
            ticket_age_add: 0xdead_beef,
            issued_at_cycles: 1_000_000,
            cipher_suite: 0x1303, // TLS_AES_128_GCM_SHA256
        }
    }

    #[test]
    fn seal_open_round_trip() {
        let tk = test_key();
        let pt = sample_pt();
        let mut out = [0u8; SEALED_LEN];
        let n = seal_under_key(&tk, &pt, &mut out).unwrap();
        assert_eq!(n, SEALED_LEN);
        // Two seals must produce different ciphertext (random nonce).
        let mut out2 = [0u8; SEALED_LEN];
        seal_under_key(&tk, &pt, &mut out2).unwrap();
        assert_ne!(&out[KEY_NAME_LEN..], &out2[KEY_NAME_LEN..]);

        let opened = open_under_key(&tk, &out, 1_500_000, 1_000_000).expect("open");
        assert_eq!(opened.version, TICKET_VERSION);
        assert_eq!(opened.resumption_master_secret, [0xCC; 32]);
        assert_eq!(opened.ticket_age_add, 0xdead_beef);
        assert_eq!(opened.issued_at_cycles, 1_000_000);
        assert_eq!(opened.cipher_suite, 0x1303);
    }

    #[test]
    fn open_rejects_tampered_tag() {
        let tk = test_key();
        let pt = sample_pt();
        let mut out = [0u8; SEALED_LEN];
        seal_under_key(&tk, &pt, &mut out).unwrap();
        out[SEALED_LEN - 1] ^= 0x80; // flip a bit in the AEAD tag
        assert!(open_under_key(&tk, &out, 1_500_000, 1_000_000).is_none());
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let tk = test_key();
        let pt = sample_pt();
        let mut out = [0u8; SEALED_LEN];
        seal_under_key(&tk, &pt, &mut out).unwrap();
        let ct_offset = KEY_NAME_LEN + NONCE_LEN + 5; // somewhere in rms
        out[ct_offset] ^= 0x01;
        assert!(open_under_key(&tk, &out, 1_500_000, 1_000_000).is_none());
    }

    #[test]
    fn open_rejects_tampered_nonce() {
        let tk = test_key();
        let pt = sample_pt();
        let mut out = [0u8; SEALED_LEN];
        seal_under_key(&tk, &pt, &mut out).unwrap();
        out[KEY_NAME_LEN] ^= 0x01;
        assert!(open_under_key(&tk, &out, 1_500_000, 1_000_000).is_none());
    }

    #[test]
    fn open_rejects_wrong_key_name() {
        let tk1 = test_key();
        let mut tk2 = test_key();
        tk2.name = [0xDD; KEY_NAME_LEN]; // different name, same key
        let pt = sample_pt();
        let mut out = [0u8; SEALED_LEN];
        seal_under_key(&tk1, &pt, &mut out).unwrap();
        // Opening with a different-name key fails on the name compare
        // before we even get to AEAD.
        assert!(open_under_key(&tk2, &out, 1_500_000, 1_000_000).is_none());
    }

    #[test]
    fn open_rejects_wrong_aead_key() {
        let tk1 = test_key();
        let mut tk2 = test_key();
        tk2.key = [0x11; KEY_LEN]; // same name, different AEAD key
        let pt = sample_pt();
        let mut out = [0u8; SEALED_LEN];
        seal_under_key(&tk1, &pt, &mut out).unwrap();
        // AAD compares clean (same name), but the AEAD key differs so
        // tag verification must fail.
        assert!(open_under_key(&tk2, &out, 1_500_000, 1_000_000).is_none());
    }

    #[test]
    fn open_rejects_expired_ticket() {
        let tk = test_key();
        let pt = sample_pt(); // issued_at = 1_000_000
        let mut out = [0u8; SEALED_LEN];
        seal_under_key(&tk, &pt, &mut out).unwrap();
        // now=10_000_000, issued=1_000_000 → age=9_000_000.
        // max_age=1_000_000 → expired.
        assert!(open_under_key(&tk, &out, 10_000_000, 1_000_000).is_none());
    }

    #[test]
    fn open_rejects_wrong_length() {
        let tk = test_key();
        let short = [0u8; SEALED_LEN - 1];
        let long = [0u8; SEALED_LEN + 1];
        assert!(open_under_key(&tk, &short, 0, u64::MAX).is_none());
        assert!(open_under_key(&tk, &long, 0, u64::MAX).is_none());
    }

    #[test]
    fn sealed_layout_constants_match() {
        // Tripwire if anyone changes the schema without updating SEALED_LEN.
        assert_eq!(PLAINTEXT_LEN, 1 + 32 + 4 + 8 + 2);
        assert_eq!(
            SEALED_LEN,
            KEY_NAME_LEN + NONCE_LEN + PLAINTEXT_LEN + TAG_LEN
        );
        assert_eq!(SEALED_LEN, 91);
    }
}
