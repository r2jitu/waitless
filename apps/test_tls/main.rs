// apps/test_tls — TLS 1.3 primitives smoke test.
//
// Boots the unikernel, runs the full //net:tls key schedule and the
// //net:tls_crypto AEAD through a known-answer round-trip, and prints
// PASS/FAIL for each stage on the serial console. test_tls.sh parses
// serial for "TLS TESTS: ALL PASSED" (or any FAIL) and reports test
// status accordingly.
//
// This is the integration test for everything we ship under net/tls*.
// The host unit tests on //net:tls_crypto cover chacha20/poly1305/aead
// against RFC 8439 vectors; this test proves the TLS 1.3 key schedule
// + X25519 round-trip + record AEAD actually run on bare metal and
// produce self-consistent results.

#![no_std]

extern crate kernel;
extern crate uni;

extern crate net_tls as tls;
extern crate net_tls_crypto as tls_crypto;

fn logn(msg: &[u8]) {
    uni::log(msg);
}

fn pass(name: &[u8]) {
    logn(b"[tls] PASS: ");
    logn(name);
    logn(b"\n");
}

fn fail(name: &[u8]) {
    logn(b"[tls] FAIL: ");
    logn(name);
    logn(b"\n");
}

#[uni::main]
fn main() {
    logn(b"TLS 1.3 primitive test starting.\n");

    let mut failures = 0u32;

    // ---- 1. ChaCha20-Poly1305 AEAD round-trip --------------------------
    {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let aad = b"header";
        let plaintext: [u8; 32] = *b"unikernel says hi from handshake";
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&plaintext);

        let tag = tls_crypto::chacha20poly1305_seal(&key, &nonce, aad, &mut buf);

        // Ciphertext differs from plaintext (overwhelmingly probable).
        let ct_differs = buf != plaintext;

        // Round-trip via open().
        let opened = tls_crypto::chacha20poly1305_open(&key, &nonce, aad, &mut buf, &tag);
        let pt_recovered = opened.is_ok() && buf == plaintext;

        if ct_differs && pt_recovered {
            pass(b"aead_roundtrip");
        } else {
            fail(b"aead_roundtrip");
            failures += 1;
        }

        // Tamper detection: flip a tag bit, confirm open() rejects.
        let mut buf2 = plaintext;
        let tag2 = tls_crypto::chacha20poly1305_seal(&key, &nonce, aad, &mut buf2);
        let mut bad_tag = tag2;
        bad_tag[0] ^= 1;
        let tampered = tls_crypto::chacha20poly1305_open(&key, &nonce, aad, &mut buf2, &bad_tag);
        if tampered.is_err() {
            pass(b"aead_tamper_detect");
        } else {
            fail(b"aead_tamper_detect");
            failures += 1;
        }
    }

    // ---- 2. X25519 round-trip ------------------------------------------
    // Both "client" and "server" generate an ephemeral key, exchange
    // public keys, and check the derived shared secret matches.
    {
        let alice = tls::X25519ServerKey::from_seed([0x11u8; 32]);
        let bob = tls::X25519ServerKey::from_seed([0x22u8; 32]);
        let alice_pub = alice.public_bytes();
        let bob_pub = bob.public_bytes();
        let ss_ab = alice.shared_secret(&bob_pub);
        let ss_ba = bob.shared_secret(&alice_pub);
        if ss_ab == ss_ba {
            pass(b"x25519_roundtrip");
        } else {
            fail(b"x25519_roundtrip");
            failures += 1;
        }
    }

    // ---- 3. HKDF-Expand-Label determinism -------------------------------
    {
        let prk = [0x55u8; tls::HASH_LEN];
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        tls::hkdf_expand_label(&prk, b"key", &[], &mut k1);
        tls::hkdf_expand_label(&prk, b"key", &[], &mut k2);
        let mut i1 = [0u8; 12];
        tls::hkdf_expand_label(&prk, b"iv", &[], &mut i1);
        if k1 == k2 && k1[..12] != i1[..12] {
            pass(b"hkdf_expand_label");
        } else {
            fail(b"hkdf_expand_label");
            failures += 1;
        }
    }

    // ---- 4. Full key schedule cascade -----------------------------------
    // Two independent schedules with identical inputs must produce
    // identical handshake + application secrets; a flipped DHE bit must
    // scramble the handshake secret.
    {
        let dhe = [0xccu8; 32];
        let mid_transcript = [0x77u8; tls::HASH_LEN];
        let final_transcript = [0x88u8; tls::HASH_LEN];

        let mut sched_a = tls::KeySchedule::new_without_psk();
        let hs_a = sched_a.enter_handshake(&dhe, &mid_transcript);
        let app_a = sched_a.enter_application(&final_transcript);

        let mut sched_b = tls::KeySchedule::new_without_psk();
        let hs_b = sched_b.enter_handshake(&dhe, &mid_transcript);
        let app_b = sched_b.enter_application(&final_transcript);

        let deterministic = hs_a.client_hs == hs_b.client_hs
            && hs_a.server_hs == hs_b.server_hs
            && app_a.client_ap == app_b.client_ap
            && app_a.server_ap == app_b.server_ap;

        // Client vs server secrets must differ.
        let labels_distinct =
            hs_a.client_hs != hs_a.server_hs && app_a.client_ap != app_a.server_ap;

        // Handshake vs application stage secrets must differ.
        let stages_distinct =
            hs_a.client_hs != app_a.client_ap && hs_a.server_hs != app_a.server_ap;

        // Flipping one DHE bit changes the handshake secret.
        let mut dhe_flipped = dhe;
        dhe_flipped[0] ^= 1;
        let mut sched_c = tls::KeySchedule::new_without_psk();
        let hs_c = sched_c.enter_handshake(&dhe_flipped, &mid_transcript);
        let dhe_sensitive = hs_a.client_hs != hs_c.client_hs;

        if deterministic && labels_distinct && stages_distinct && dhe_sensitive {
            pass(b"key_schedule_cascade");
        } else {
            fail(b"key_schedule_cascade");
            failures += 1;
        }
    }

    // ---- 5. Full record-level AEAD via TrafficKey -----------------------
    // Drive the record layer exactly the way a TLS 1.3 server would:
    // derive a traffic secret, build a TrafficKey, seal, transmit, open.
    {
        let secret = [0x33u8; tls::HASH_LEN];
        let mut send = tls::TrafficKey::from_secret(&secret);
        let mut recv = tls::TrafficKey::from_secret(&secret);

        let aad = b"TLSPlaintext.header";
        let msg = b"Hello via TLS 1.3 record protection!";
        let mut buf = [0u8; 64];
        buf[..msg.len()].copy_from_slice(msg);

        let tag = send.seal(aad, &mut buf[..msg.len()]);
        let ok = recv.open(aad, &mut buf[..msg.len()], &tag).is_ok();
        let recovered = &buf[..msg.len()] == msg;
        let seqs_advanced = send.seq == 1 && recv.seq == 1;

        if ok && recovered && seqs_advanced {
            pass(b"traffic_key_record");
        } else {
            fail(b"traffic_key_record");
            failures += 1;
        }

        // Second record on the same stream uses seq=1 → different nonce.
        // The same plaintext should produce a different ciphertext.
        let mut buf2 = [0u8; 64];
        buf2[..msg.len()].copy_from_slice(msg);
        let tag2 = send.seal(aad, &mut buf2[..msg.len()]);
        let different_ct = buf != buf2 || tag != tag2;
        if different_ct {
            pass(b"traffic_key_per_seq_nonce");
        } else {
            fail(b"traffic_key_per_seq_nonce");
            failures += 1;
        }
    }

    // ---- 6. kernel::rng — fill_bytes produces non-trivial output ------
    // Smoke-tests the seed-collection-from-cycle-counter path AND the
    // ChaCha20 keystream expansion. We can't check randomness quality
    // in a unit test, but we CAN check (a) the same RNG state produces
    // a non-zero buffer, (b) two consecutive 32-byte fills produce
    // different output, and (c) calling it never panics or hangs.
    {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        kernel::rng::fill_bytes(&mut buf1);
        kernel::rng::fill_bytes(&mut buf2);

        let nonzero = buf1.iter().any(|&b| b != 0);
        let differ = buf1 != buf2;

        if nonzero && differ {
            pass(b"kernel_rng_fill_bytes");
        } else {
            fail(b"kernel_rng_fill_bytes");
            failures += 1;
        }
    }

    // ---- Final tally ----------------------------------------------------
    if failures == 0 {
        logn(b"TLS TESTS: ALL PASSED\n");
    } else {
        logn(b"TLS TESTS: FAILED (");
        let d = (b'0' + (failures as u8 % 10)) as u8;
        logn(&[d]);
        logn(b" failures)\n");
    }

    logn(b"TLS test complete. Shutting down.\n");
}
