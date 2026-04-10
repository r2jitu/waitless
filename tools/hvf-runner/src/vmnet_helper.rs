// tools/hvf-runner/src/vmnet_helper.rs
//
// vmnet.framework helper subprocess. Runs in a forked child process to
// avoid GCD thread starvation from hv_vcpu_run in the parent.
//
// Protocol: Unix datagram socket pair. Each datagram = one Ethernet frame.
// Parent sends TX frames, child sends RX frames.

/// Fork a vmnet helper subprocess. The child creates the vmnet interface
/// and sends the MAC address back to the parent via the socket.
/// Returns (mac, parent_fd). The child never returns.
pub fn spawn() -> Result<([u8; 6], i32), String> {
    // Create Unix datagram socket pair.
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(format!("socketpair: {}", std::io::Error::last_os_error()));
    }

    // Enlarge socket buffers (4 MB each direction).
    let buf_size: i32 = 4 * 1024 * 1024;
    for &fd in &fds {
        unsafe {
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF,
                &buf_size as *const _ as *const _, 4);
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF,
                &buf_size as *const _ as *const _, 4);
        }
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }

    if pid > 0 {
        // Parent: close child's end, read MAC from child.
        unsafe { libc::close(fds[1]); }
        let mut mac = [0u8; 6];
        let n = unsafe { libc::recv(fds[0], mac.as_mut_ptr() as *mut _, 6, 0) };
        if n != 6 {
            return Err("failed to receive MAC from helper child".into());
        }
        return Ok((mac, fds[0]));
    }

    // ── Child process: create vmnet + event loop ─────────────────────

    unsafe { libc::close(fds[0]); }
    let child_fd = fds[1];

    // Create vmnet interface in the child (after fork).
    let mut iface = vmnet::Interface::new(
        vmnet::mode::Mode::Host(Default::default()),
        Default::default(),
    ).expect("vmnet::Interface::new failed in helper child");

    // Extract and send MAC to parent.
    let params: Vec<vmnet::parameters::Parameter> = iface.parameters().into();
    let mut mac = [0u8; 6];
    for p in &params {
        if let vmnet::parameters::Parameter::MACAddress(ref s) = p {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() == 6 {
                for (i, part) in parts.iter().enumerate() {
                    mac[i] = u8::from_str_radix(part, 16).unwrap_or(0);
                }
            }
        }
    }
    for p in &params {
        eprintln!("(vmnet-helper) {p:?}");
    }
    unsafe { libc::send(child_fd, mac.as_ptr() as *const _, 6, 0); }

    // Set child fd non-blocking for TX reads.
    unsafe { libc::fcntl(child_fd, libc::F_SETFL, libc::O_NONBLOCK); }

    // Main loop: poll vmnet + socket.
    let mut buf = [0u8; 2048];
    loop {
        // 1. Read from vmnet → send to parent.
        loop {
            match iface.read(&mut buf) {
                Ok(n) if n > 0 => {
                    unsafe { libc::send(child_fd, buf.as_ptr() as *const _, n, 0); }
                }
                _ => break,
            }
        }

        // 2. Read from parent (TX frames) → write to vmnet.
        loop {
            let n = unsafe {
                libc::recv(child_fd, buf.as_mut_ptr() as *mut _, buf.len(), 0)
            };
            if n <= 0 { break; }
            let _ = iface.write(&buf[..n as usize]);
        }

        std::thread::sleep(std::time::Duration::from_micros(50));
    }
}

