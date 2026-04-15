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

    // ---- 1b. Large-plaintext AEAD round-trip ---------------------------
    // Live handshake Certificate records are ~580 bytes of plaintext,
    // way past the 32-byte smoke test above. Any data-length-dependent
    // bug in the SIMD path (e.g. wrong block-count handling at a
    // specific size threshold) wouldn't show up in the small test but
    // would cripple the real handshake — which is exactly what we saw
    // on x86_64-unknown-none TCG after enabling `+avx,+avx2`. This
    // test seals a 600-byte buffer and verifies the round-trip is
    // byte-exact, catching any corruption from AVX emulation /
    // length-gating bugs at its source.
    {
        let key = [0x77u8; 32];
        let nonce = [0x33u8; 12];
        let aad = b"5-byte";
        let mut original = [0u8; 600];
        // Fill with a non-trivial pattern so any XOR-then-XOR-back bug
        // (where the stream is all-zero for parts of the buffer) is
        // visible as a position-dependent mismatch.
        for (i, b) in original.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(1);
        }
        let mut buf = [0u8; 600];
        buf.copy_from_slice(&original);

        let tag = tls_crypto::chacha20poly1305_seal(&key, &nonce, aad, &mut buf);

        // Ciphertext must differ from plaintext at >90% of positions
        // (probabilistically certain for any real stream cipher).
        let mut differ = 0usize;
        for i in 0..600 {
            if buf[i] != original[i] { differ += 1; }
        }
        let ct_looks_encrypted = differ > 540;

        // Round-trip.
        let opened = tls_crypto::chacha20poly1305_open(&key, &nonce, aad, &mut buf, &tag);
        let pt_recovered = opened.is_ok() && buf == original;

        if ct_looks_encrypted && pt_recovered {
            pass(b"aead_roundtrip_large");
        } else {
            fail(b"aead_roundtrip_large");
            failures += 1;
        }
    }

    // ---- 1c. AEAD known-answer vector (RFC 8439 §2.8.2) ---------------
    // The round-trip tests above only prove seal(open(x)) == x — a bug
    // that produces consistent-but-wrong ciphertext (e.g. XOR with the
    // wrong stream) would still pass. This test pins seal() output
    // against the RFC 8439 known-answer vector so we catch that case.
    // If this fails but the round-trip passes, something in the chacha20
    // or poly1305 SIMD path is producing a self-consistent but
    // incorrect keystream.
    {
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00,
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
            0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ct: [u8; 114] = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc,
            0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
            0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e,
            0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
            0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
            0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
            0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
            0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65,
            0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16,
        ];
        let expected_tag: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
            0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
        ];

        let mut buf = [0u8; 114];
        buf.copy_from_slice(plaintext);
        let tag = tls_crypto::chacha20poly1305_seal(&key, &nonce, &aad, &mut buf);

        let ct_ok = buf == expected_ct;
        let tag_ok = tag == expected_tag;

        if ct_ok && tag_ok {
            pass(b"aead_rfc8439_known_answer");
        } else {
            fail(b"aead_rfc8439_known_answer");
            logn(b"      ct_ok=");
            logn(if ct_ok { b"true " } else { b"false " });
            logn(b"tag_ok=");
            logn(if tag_ok { b"true\n" } else { b"false\n" });
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

    // ---- 7. RFC 8448 §3 known-answer test for TLS 1.3 key schedule ----
    // RFC 8448 publishes a complete TLS 1.3 handshake trace with all
    // intermediate secrets exposed. We feed the published ECDHE
    // private keys + transcript hash through our key schedule and
    // check that the derived handshake_traffic_secrets match the
    // RFC's expected outputs byte-for-byte.
    //
    // This is the strongest correctness signal we have for the
    // HKDF-Expand-Label / Derive-Secret cascade: a single bug in
    // the label format, the transcript-hash-as-context wiring, or
    // the salt/PRK ordering in HKDF-Extract would produce a
    // different-but-internally-consistent secret, which our
    // self-roundtrip tests can't catch but RFC 8448 catches
    // immediately.
    {
        // Inputs from RFC 8448 §3 "Simple 1-RTT Handshake":
        //
        // Client ephemeral X25519 private key:
        let client_priv: [u8; 32] = [
            0x49, 0xaf, 0x42, 0xba, 0x7f, 0x79, 0x94, 0x85,
            0x2d, 0x71, 0x3e, 0xf2, 0x78, 0x4b, 0xcb, 0xca,
            0xa7, 0x91, 0x1d, 0xe2, 0x6a, 0xdc, 0x56, 0x42,
            0xcb, 0x63, 0x45, 0x40, 0xe7, 0xea, 0x50, 0x05,
        ];
        // Server ephemeral X25519 private key:
        let server_priv: [u8; 32] = [
            0xb1, 0x58, 0x0e, 0xea, 0xdf, 0x6d, 0xd5, 0x89,
            0xb8, 0xef, 0x4f, 0x2d, 0x56, 0x52, 0x57, 0x8c,
            0xc8, 0x10, 0xe9, 0x98, 0x01, 0x91, 0xec, 0x8d,
            0x05, 0x83, 0x08, 0xce, 0xa2, 0x16, 0xa2, 0x1e,
        ];
        // Transcript hash after ClientHello..ServerHello (exact
        // bytes of these records are in the RFC; our test trusts
        // SHA-256 to be correct and starts from the published
        // hash output):
        let expected_transcript_after_sh: [u8; 32] = [
            0x86, 0x0c, 0x06, 0xed, 0xc0, 0x78, 0x58, 0xee,
            0x8e, 0x78, 0xf0, 0xe7, 0x42, 0x8c, 0x58, 0xed,
            0xd6, 0xb4, 0x3f, 0x2c, 0xa3, 0xe6, 0xe9, 0x5f,
            0x02, 0xed, 0x06, 0x3c, 0xf0, 0xe1, 0xca, 0xd8,
        ];
        // Expected outputs from the RFC:
        let expected_client_hs_traffic: [u8; 32] = [
            0xb3, 0xed, 0xdb, 0x12, 0x6e, 0x06, 0x7f, 0x35,
            0xa7, 0x80, 0xb3, 0xab, 0xf4, 0x5e, 0x2d, 0x8f,
            0x3b, 0x1a, 0x95, 0x07, 0x38, 0xf5, 0x2e, 0x96,
            0x00, 0x74, 0x6a, 0x0e, 0x27, 0xa5, 0x5a, 0x21,
        ];
        let expected_server_hs_traffic: [u8; 32] = [
            0xb6, 0x7b, 0x7d, 0x69, 0x0c, 0xc1, 0x6c, 0x4e,
            0x75, 0xe5, 0x42, 0x13, 0xcb, 0x2d, 0x37, 0xb4,
            0xe9, 0xc9, 0x12, 0xbc, 0xde, 0xd9, 0x10, 0x5d,
            0x42, 0xbe, 0xfd, 0x59, 0xd3, 0x91, 0xad, 0x38,
        ];

        // Compute ECDHE shared secret via our X25519 wrapper. Use
        // server side (priv + client public derived from client priv);
        // the result is symmetric so this matches what the RFC would
        // see on either end.
        let client_kp = tls::X25519ServerKey::from_seed(client_priv);
        let server_kp = tls::X25519ServerKey::from_seed(server_priv);
        let client_pub = client_kp.public_bytes();
        let shared = server_kp.shared_secret(&client_pub);

        // Run the cascade.
        let mut sched = tls::KeySchedule::new_without_psk();
        let secrets =
            sched.enter_handshake(&shared, &expected_transcript_after_sh);

        let client_ok = secrets.client_hs == expected_client_hs_traffic;
        let server_ok = secrets.server_hs == expected_server_hs_traffic;

        if client_ok && server_ok {
            pass(b"rfc8448_handshake_secrets");
        } else {
            fail(b"rfc8448_handshake_secrets");
            if !client_ok {
                logn(b"  client_hs mismatch\n");
            }
            if !server_ok {
                logn(b"  server_hs mismatch\n");
            }
            failures += 1;
        }

        // ---- 7b. enter_application produces the RFC's app traffic secrets
        // The transcript is now hashed through ServerFinished (RFC §3
        // gives this hash directly); enter_application internally
        // does derive→Master Secret→derive client/server app secrets.
        let expected_transcript_after_sfin: [u8; 32] = [
            0x96, 0x08, 0x10, 0x2a, 0x0f, 0x1c, 0xcc, 0x6d,
            0xb6, 0x25, 0x0b, 0x7b, 0x7e, 0x41, 0x7b, 0x1a,
            0x00, 0x0e, 0xaa, 0xda, 0x3d, 0xaa, 0xe4, 0x77,
            0x7a, 0x76, 0x86, 0xc9, 0xff, 0x83, 0xdf, 0x13,
        ];
        let expected_client_ap_traffic: [u8; 32] = [
            0x9e, 0x40, 0x64, 0x6c, 0xe7, 0x9a, 0x7f, 0x9d,
            0xc0, 0x5a, 0xf8, 0x88, 0x9b, 0xce, 0x65, 0x52,
            0x87, 0x5a, 0xfa, 0x0b, 0x06, 0xdf, 0x00, 0x87,
            0xf7, 0x92, 0xeb, 0xb7, 0xc1, 0x75, 0x04, 0xa5,
        ];
        let expected_server_ap_traffic: [u8; 32] = [
            0xa1, 0x1a, 0xf9, 0xf0, 0x55, 0x31, 0xf8, 0x56,
            0xad, 0x47, 0x11, 0x6b, 0x45, 0xa9, 0x50, 0x32,
            0x82, 0x04, 0xb4, 0xf4, 0x4b, 0xfb, 0x6b, 0x3a,
            0x4b, 0x4f, 0x1f, 0x3f, 0xcb, 0x63, 0x16, 0x43,
        ];

        let app = sched.enter_application(&expected_transcript_after_sfin);
        let cap_ok = app.client_ap == expected_client_ap_traffic;
        let sap_ok = app.server_ap == expected_server_ap_traffic;
        if cap_ok && sap_ok {
            pass(b"rfc8448_application_secrets");
        } else {
            fail(b"rfc8448_application_secrets");
            if !cap_ok {
                logn(b"  client_ap mismatch\n");
            }
            if !sap_ok {
                logn(b"  server_ap mismatch\n");
            }
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
