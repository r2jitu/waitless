// tools/hvf-runner/src/terminal.rs
//
// Terminal raw-mode helpers. Mirrors the Swift `enableRawInput` /
// `restoreTerminal` pair from tools/run-vz/run-vz.swift.
//
// In raw mode: no echo, no line buffering, no signal processing
// (Ctrl-C becomes byte 0x03 forwarded to the guest's serial RX).

use std::sync::OnceLock;

static SAVED: OnceLock<libc::termios> = OnceLock::new();

/// Switch stdin to raw mode. Saves the original termios for restore.
/// No-op if stdin is not a TTY.
pub fn enable_raw() {
    unsafe {
        if libc::isatty(libc::STDIN_FILENO) == 0 {
            return;
        }
        let mut orig: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(libc::STDIN_FILENO, &mut orig) != 0 {
            return;
        }
        let _ = SAVED.set(orig);

        let mut raw = orig;
        raw.c_lflag &= !(libc::ISIG | libc::ICANON | libc::ECHO | libc::IEXTEN);
        raw.c_iflag &= !(libc::ICRNL | libc::IXON);
        raw.c_oflag &= !libc::OPOST;
        libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &raw);
    }
}

/// Restore the original terminal settings. No-op if `enable_raw` was
/// never called or stdin is not a TTY.
pub fn restore() {
    if let Some(orig) = SAVED.get() {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, orig);
        }
    }
}
