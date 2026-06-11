// tools/hvf-runner/src/userspace_net/outbound_fsm.rs
//
// State machine for GUEST-INITIATED outbound TCP flows — the toy-peer
// half of the userspace proxy's client-connect bridging, kept pure
// (no sockets, no virtio, no libc) so it can be unit-tested on the
// host exactly like `decoder.rs`. The I/O glue in `outbound_tcp.rs`
// feeds it events (guest segments, host connect results, host
// EOF/error) and executes the returned host-socket operations +
// queues the returned control frames toward the guest.
//
// Semantics are deliberately toy, mirroring the inbound `ProxyConn`
// peer: no retransmission, no window management beyond the fixed
// 64 KiB advertisement, no options in the SYN-ACK (same as the
// inbound path's optionless SYN — the guest then keeps its local
// MSS, see `receive::handle_syn_sent`'s `syn_mss: None` arm). The
// proxy↔guest link is a lossless in-memory ring; the guest's real
// stack handles its own side.
//
// Guest-stack facts this FSM is written against (crates/net/tcp):
//   * SYN-ACK must carry `ack == ISS+1` exactly or the guest RSTs
//     (`handle_syn_sent` first check).
//   * A connection-refused RST in SynSent is judged by its ACK
//     field, not seq: RST|ACK with `ack == ISS+1` (RFC 9293
//     §3.10.7.3 / `receive.rs` RST handling).
//   * An established-state RST must have `seq == rcv_nxt`
//     (RFC 5961 §3.2) — i.e. our `my_seq`.

use std::time::Duration;

/// TCP flag bits (subset the FSM cares about).
pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const ACK: u8 = 0x10;

/// How long an outbound flow may sit with no guest segment and no
/// host I/O before the periodic sweep reaps it. The inbound `conns`
/// sweep has no time threshold — it relies on the toy peer driving
/// each conn to a terminal `Closed` state — but outbound flows have
/// states that legitimately never advance on their own when the
/// counterparty goes silent (`SynAckSent`: guest never ACKs the
/// handshake and we deliberately don't poll it; `GuestClosed`: host
/// peer holds its read side open forever; `FinWait`: guest abandons
/// without a FIN). Without a reaper those leak toward the per-vCPU
/// `MAX_OUTBOUND_TCP` cap and then RST every new connect. 60 s is
/// far longer than any real request/response exchange through the
/// toy proxy, so a busy long-lived flow (refreshed on every segment
/// and every host I/O event) is never reaped, while a stranded one
/// is freed within a sweep interval of the deadline.
pub const OUTBOUND_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Pure expiry predicate for the periodic outbound-TCP sweep, kept
/// here (with the FSM it reasons about) so it's unit-testable
/// standalone like the rest of this module. `idle` is how long the
/// flow has gone with no guest segment and no host I/O — see
/// `OUTBOUND_IDLE_TIMEOUT` for the rationale and the refresh points.
///
/// Every live state is reaped once idle past the deadline; the
/// distinction is only documentary (the leak-prone states never
/// refresh on their own once the peer is silent, whereas a healthy
/// `Established`/`Connecting` flow keeps its timer fresh through
/// normal activity). A flow with recent activity (`idle <` deadline)
/// always survives.
pub fn flow_expired(_state: FsmState, idle: Duration) -> bool {
    idle >= OUTBOUND_IDLE_TIMEOUT
}

/// Flow state. `Closed` has no variant — a closed flow is removed
/// from the map (`SegOut::remove`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FsmState {
    /// Host `connect(2)` in flight; nothing sent to the guest yet.
    Connecting,
    /// Host connected; SYN-ACK sent; awaiting the guest's handshake
    /// ACK. The host fd is deliberately NOT read in this state —
    /// data segments injected ahead of the SYN-ACK would be dropped
    /// by the guest (still SynSent) and the toy peer never resends.
    SynAckSent,
    Established,
    /// Guest sent FIN (half-close): host write side is shut down,
    /// host→guest data still flows. Mirrors a real peer's CloseWait.
    GuestClosed,
    /// We sent our FIN (host EOF) before the guest sent its own —
    /// the flow is kept alive so the guest's eventual FIN gets its
    /// ACK and the guest's LastAck completes instead of stranding
    /// (same lesson as the inbound path's FinWait state).
    FinWait,
}

/// A control segment to synthesize toward the guest.
#[derive(Debug, PartialEq, Eq)]
pub struct Ctl {
    pub flags: u8,
    pub seq: u32,
    pub ack: u32,
}

/// Host-socket side effect the caller must perform.
#[derive(Debug, PartialEq, Eq)]
pub enum HostOp {
    None,
    /// `shutdown(fd, SHUT_WR)` — guest half-closed.
    ShutdownWrite,
    /// Plain `close(fd)`.
    Close,
    /// `SO_LINGER{1,0}` + `close(fd)` so the host side sees an RST,
    /// mirroring the RST the guest just sent us.
    CloseRst,
}

/// Everything one FSM event asks the I/O glue to do.
#[derive(Debug, PartialEq, Eq)]
pub struct SegOut {
    /// Forward the guest segment's payload to the host socket
    /// (before any `host_op` — write-then-shutdown ordering).
    pub write_payload: bool,
    pub host_op: HostOp,
    pub ctl: Option<Ctl>,
    /// Remove the flow from the map (terminal).
    pub remove: bool,
}

impl SegOut {
    pub fn none() -> Self {
        SegOut {
            write_payload: false,
            host_op: HostOp::None,
            ctl: None,
            remove: false,
        }
    }

    fn ctl_only(ctl: Ctl) -> Self {
        SegOut {
            ctl: Some(ctl),
            ..SegOut::none()
        }
    }
}

/// Refusal reply for a SYN we never open a flow for (dst port 0, the
/// proxy's own listener, flow-cap overflow, socket failure): RST|ACK
/// acking the SYN, which is exactly what the guest's SynSent RST
/// check requires (`ack == ISS+1`; seq is ignored in that state).
pub fn refuse_syn(guest_isn: u32) -> Ctl {
    Ctl {
        flags: RST | ACK,
        seq: 0,
        ack: guest_isn.wrapping_add(1),
    }
}

/// The per-flow sequence bookkeeping + state. `my_seq` is the next
/// sequence number we send (== the guest's `rcv_nxt` when nothing is
/// buffered); `peer_ack` is the next guest byte we expect (== the
/// value of every ACK field we emit).
pub struct OutboundFsm {
    pub state: FsmState,
    pub my_seq: u32,
    pub peer_ack: u32,
}

impl OutboundFsm {
    /// New flow for a guest SYN with initial sequence `guest_isn`.
    /// `my_isn` is our (fixed, toy) initial sequence number.
    pub fn new(guest_isn: u32, my_isn: u32) -> Self {
        OutboundFsm {
            state: FsmState::Connecting,
            my_seq: my_isn,
            peer_ack: guest_isn.wrapping_add(1),
        }
    }

    /// Host `connect(2)` resolved. `ok` ⇒ SYN-ACK; otherwise a
    /// connection-refused RST|ACK and the flow is dropped.
    pub fn on_connect_result(&mut self, ok: bool) -> SegOut {
        if self.state != FsmState::Connecting {
            return SegOut::none();
        }
        if ok {
            let ctl = Ctl {
                flags: SYN | ACK,
                seq: self.my_seq,
                ack: self.peer_ack,
            };
            // The SYN occupies one sequence number.
            self.my_seq = self.my_seq.wrapping_add(1);
            self.state = FsmState::SynAckSent;
            SegOut::ctl_only(ctl)
        } else {
            SegOut {
                host_op: HostOp::Close,
                ctl: Some(refuse_syn(self.peer_ack.wrapping_sub(1))),
                remove: true,
                ..SegOut::none()
            }
        }
    }

    /// A guest segment for this flow (already matched by 4-tuple).
    pub fn on_guest_segment(&mut self, seq: u32, flags: u8, payload_len: usize) -> SegOut {
        if flags & RST != 0 {
            // Guest reset — propagate as RST to the host socket and
            // drop the flow, mirroring the inbound RST branch.
            return SegOut {
                host_op: HostOp::CloseRst,
                remove: true,
                ..SegOut::none()
            };
        }
        match self.state {
            // connect(2) still in flight; the guest can't have
            // anything but a retransmitted SYN here, and our
            // SYN-ACK comes when the connect resolves.
            FsmState::Connecting => SegOut::none(),
            FsmState::SynAckSent => {
                if flags & SYN != 0 {
                    // SYN retransmit — the guest missed our SYN-ACK;
                    // resend it (ISN = my_seq - 1, nothing else has
                    // consumed sequence space yet).
                    return SegOut::ctl_only(Ctl {
                        flags: SYN | ACK,
                        seq: self.my_seq.wrapping_sub(1),
                        ack: self.peer_ack,
                    });
                }
                if flags & ACK == 0 {
                    return SegOut::none();
                }
                // Handshake ACK — possibly carrying the first data
                // bytes (or even a FIN); process them in this pass.
                self.state = FsmState::Established;
                self.established_segment(seq, flags, payload_len)
            }
            FsmState::Established => self.established_segment(seq, flags, payload_len),
            FsmState::GuestClosed => {
                // Guest already FINed; data/FIN retransmits just get
                // re-ACKed at the current edge.
                if payload_len > 0 || flags & FIN != 0 {
                    return SegOut::ctl_only(Ctl {
                        flags: ACK,
                        seq: self.my_seq,
                        ack: self.peer_ack,
                    });
                }
                SegOut::none()
            }
            FsmState::FinWait => {
                // Our FIN is out (host EOF); the host socket is gone,
                // so guest data is acknowledged but dropped (same
                // lossy toy guarantee as the inbound path).
                if flags & FIN != 0 {
                    self.peer_ack = seq.wrapping_add(payload_len as u32).wrapping_add(1);
                    return SegOut {
                        ctl: Some(Ctl {
                            flags: ACK,
                            seq: self.my_seq,
                            ack: self.peer_ack,
                        }),
                        remove: true,
                        ..SegOut::none()
                    };
                }
                if payload_len > 0 {
                    self.peer_ack = seq.wrapping_add(payload_len as u32);
                    return SegOut::ctl_only(Ctl {
                        flags: ACK,
                        seq: self.my_seq,
                        ack: self.peer_ack,
                    });
                }
                SegOut::none()
            }
        }
    }

    fn established_segment(&mut self, seq: u32, flags: u8, payload_len: usize) -> SegOut {
        let mut out = SegOut::none();
        if payload_len > 0 {
            self.peer_ack = seq.wrapping_add(payload_len as u32);
            out.write_payload = true;
            out.ctl = Some(Ctl {
                flags: ACK,
                seq: self.my_seq,
                ack: self.peer_ack,
            });
        }
        if flags & FIN != 0 {
            // The ACK must cover data + FIN when they ride the same
            // segment (the under-ack variant of this strands the
            // guest in FinWait — see the inbound path's data+FIN
            // comment).
            self.peer_ack = seq.wrapping_add(payload_len as u32).wrapping_add(1);
            self.state = FsmState::GuestClosed;
            out.host_op = HostOp::ShutdownWrite;
            out.ctl = Some(Ctl {
                flags: ACK,
                seq: self.my_seq,
                ack: self.peer_ack,
            });
        }
        out
    }

    /// Host socket hit EOF (after all buffered host→guest data has
    /// been delivered — the caller defers this while data is still
    /// pending, so the FIN sequences after the last byte).
    pub fn on_host_eof(&mut self) -> SegOut {
        let ctl = Ctl {
            flags: FIN | ACK,
            seq: self.my_seq,
            ack: self.peer_ack,
        };
        self.my_seq = self.my_seq.wrapping_add(1);
        match self.state {
            // Both directions now closed; the guest ACKs our FIN on
            // its own (it's in FIN_WAIT_2 → TIME_WAIT) and we don't
            // need to see that ACK — drop the flow.
            FsmState::GuestClosed => SegOut {
                host_op: HostOp::Close,
                ctl: Some(ctl),
                remove: true,
                ..SegOut::none()
            },
            // Guest still owes its FIN — park in FinWait so it gets
            // acknowledged (LastAck completion).
            _ => {
                self.state = FsmState::FinWait;
                SegOut {
                    host_op: HostOp::Close,
                    ctl: Some(ctl),
                    ..SegOut::none()
                }
            }
        }
    }

    /// Host socket terminal read error (e.g. ECONNRESET): reset the
    /// guest side. In a synchronized state the guest accepts an RST
    /// only at `seq == rcv_nxt` — that is `my_seq`.
    pub fn on_host_error(&mut self) -> SegOut {
        SegOut {
            host_op: HostOp::Close,
            ctl: Some(Ctl {
                flags: RST,
                seq: self.my_seq,
                ack: self.peer_ack,
            }),
            remove: true,
            ..SegOut::none()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const G_ISN: u32 = 0x1234_5678;
    const M_ISN: u32 = 1000;

    fn connected() -> OutboundFsm {
        let mut f = OutboundFsm::new(G_ISN, M_ISN);
        let out = f.on_connect_result(true);
        assert_eq!(
            out.ctl,
            Some(Ctl {
                flags: SYN | ACK,
                seq: M_ISN,
                ack: G_ISN.wrapping_add(1),
            })
        );
        assert!(!out.remove);
        assert_eq!(f.state, FsmState::SynAckSent);
        f
    }

    fn established() -> OutboundFsm {
        let mut f = connected();
        // Bare handshake ACK.
        let out = f.on_guest_segment(G_ISN.wrapping_add(1), ACK, 0);
        assert_eq!(out, SegOut::none());
        assert_eq!(f.state, FsmState::Established);
        f
    }

    #[test]
    fn happy_path_connect_data_close() {
        let mut f = established();

        // Guest sends 5 payload bytes → forwarded + ACKed.
        let out = f.on_guest_segment(G_ISN.wrapping_add(1), ACK, 5);
        assert!(out.write_payload);
        assert_eq!(
            out.ctl,
            Some(Ctl {
                flags: ACK,
                seq: M_ISN + 1,
                ack: G_ISN.wrapping_add(6),
            })
        );

        // Guest FIN → half-close + ACK covering the FIN.
        let out = f.on_guest_segment(G_ISN.wrapping_add(6), ACK | FIN, 0);
        assert_eq!(out.host_op, HostOp::ShutdownWrite);
        assert_eq!(
            out.ctl,
            Some(Ctl {
                flags: ACK,
                seq: M_ISN + 1,
                ack: G_ISN.wrapping_add(7),
            })
        );
        assert_eq!(f.state, FsmState::GuestClosed);
        assert!(!out.remove);

        // Host EOF after the guest's FIN → our FIN, flow done.
        let out = f.on_host_eof();
        assert_eq!(out.host_op, HostOp::Close);
        assert_eq!(
            out.ctl,
            Some(Ctl {
                flags: FIN | ACK,
                seq: M_ISN + 1,
                ack: G_ISN.wrapping_add(7),
            })
        );
        assert!(out.remove);
    }

    #[test]
    fn connect_refused_rst_acks_the_syn() {
        let mut f = OutboundFsm::new(G_ISN, M_ISN);
        let out = f.on_connect_result(false);
        assert_eq!(out.host_op, HostOp::Close);
        assert!(out.remove);
        // The guest's SynSent RST check requires ack == ISS+1.
        assert_eq!(
            out.ctl,
            Some(Ctl {
                flags: RST | ACK,
                seq: 0,
                ack: G_ISN.wrapping_add(1),
            })
        );
    }

    #[test]
    fn host_eof_first_then_guest_fin_completes_last_ack() {
        let mut f = established();

        // Host closes first → our FIN, flow parks in FinWait.
        let out = f.on_host_eof();
        assert_eq!(
            out.ctl,
            Some(Ctl {
                flags: FIN | ACK,
                seq: M_ISN + 1,
                ack: G_ISN.wrapping_add(1),
            })
        );
        assert!(!out.remove);
        assert_eq!(f.state, FsmState::FinWait);

        // Guest data while we're FinWait is ACKed (and dropped by
        // the glue — no host socket left).
        let out = f.on_guest_segment(G_ISN.wrapping_add(1), ACK, 3);
        assert_eq!(
            out.ctl,
            Some(Ctl {
                flags: ACK,
                seq: M_ISN + 2,
                ack: G_ISN.wrapping_add(4),
            })
        );
        assert!(!out.remove);

        // The guest's own FIN must be ACKed or its LastAck strands.
        let out = f.on_guest_segment(G_ISN.wrapping_add(4), ACK | FIN, 0);
        assert_eq!(
            out.ctl,
            Some(Ctl {
                flags: ACK,
                seq: M_ISN + 2,
                ack: G_ISN.wrapping_add(5),
            })
        );
        assert!(out.remove);
    }

    #[test]
    fn syn_retransmit_resends_syn_ack() {
        let mut f = connected();
        let out = f.on_guest_segment(G_ISN, SYN, 0);
        assert_eq!(
            out.ctl,
            Some(Ctl {
                flags: SYN | ACK,
                seq: M_ISN,
                ack: G_ISN.wrapping_add(1),
            })
        );
        assert_eq!(f.state, FsmState::SynAckSent);
    }

    #[test]
    fn syn_while_connecting_is_ignored() {
        let mut f = OutboundFsm::new(G_ISN, M_ISN);
        let out = f.on_guest_segment(G_ISN, SYN, 0);
        assert_eq!(out, SegOut::none());
        assert_eq!(f.state, FsmState::Connecting);
    }

    #[test]
    fn guest_rst_tears_down_with_host_rst() {
        let mut f = established();
        let out = f.on_guest_segment(G_ISN.wrapping_add(1), RST, 0);
        assert_eq!(out.host_op, HostOp::CloseRst);
        assert!(out.remove);
        assert_eq!(out.ctl, None);
    }

    #[test]
    fn data_plus_fin_acked_together() {
        let mut f = established();
        let out = f.on_guest_segment(G_ISN.wrapping_add(1), ACK | FIN, 10);
        assert!(out.write_payload);
        assert_eq!(out.host_op, HostOp::ShutdownWrite);
        // ACK must cover payload AND the FIN's phantom byte:
        // seq (ISN+1) + 10 data bytes + 1 FIN = ISN+12.
        assert_eq!(
            out.ctl,
            Some(Ctl {
                flags: ACK,
                seq: M_ISN + 1,
                ack: G_ISN.wrapping_add(12),
            })
        );
        assert_eq!(f.state, FsmState::GuestClosed);
    }

    #[test]
    fn dup_fin_in_guest_closed_is_reacked() {
        let mut f = established();
        f.on_guest_segment(G_ISN.wrapping_add(1), ACK | FIN, 0);
        let out = f.on_guest_segment(G_ISN.wrapping_add(1), ACK | FIN, 0);
        assert_eq!(
            out.ctl,
            Some(Ctl {
                flags: ACK,
                seq: M_ISN + 1,
                ack: G_ISN.wrapping_add(2),
            })
        );
        assert!(!out.remove);
    }

    #[test]
    fn data_riding_handshake_ack_establishes_and_forwards() {
        let mut f = connected();
        let out = f.on_guest_segment(G_ISN.wrapping_add(1), ACK, 7);
        assert_eq!(f.state, FsmState::Established);
        assert!(out.write_payload);
        assert_eq!(
            out.ctl,
            Some(Ctl {
                flags: ACK,
                seq: M_ISN + 1,
                ack: G_ISN.wrapping_add(8),
            })
        );
    }

    #[test]
    fn host_error_resets_at_my_seq() {
        let mut f = established();
        let out = f.on_host_error();
        assert!(out.remove);
        // In-window RST: the guest only accepts seq == rcv_nxt.
        assert_eq!(
            out.ctl,
            Some(Ctl {
                flags: RST,
                seq: M_ISN + 1,
                ack: G_ISN.wrapping_add(1),
            })
        );
    }

    #[test]
    fn sequence_wraparound() {
        let g_isn = u32::MAX - 2;
        let mut f = OutboundFsm::new(g_isn, M_ISN);
        f.on_connect_result(true);
        // peer_ack wrapped to u32::MAX - 1.
        assert_eq!(f.peer_ack, u32::MAX - 1);
        let out = f.on_guest_segment(u32::MAX - 1, ACK, 8);
        assert_eq!(f.state, FsmState::Established);
        // u32::MAX - 1 + 8 wraps to 6.
        assert_eq!(out.ctl.unwrap().ack, 6);
    }

    #[test]
    fn refuse_syn_shape() {
        assert_eq!(
            refuse_syn(u32::MAX),
            Ctl {
                flags: RST | ACK,
                seq: 0,
                ack: 0,
            }
        );
    }

    #[test]
    fn idle_flow_past_deadline_expires() {
        // A flow whose counterparty went silent — idle past the
        // deadline — is reaped in every leak-prone (and every other)
        // state. These are exactly the states that never advance on
        // their own once the peer stops talking.
        let just_over = OUTBOUND_IDLE_TIMEOUT + Duration::from_secs(1);
        for state in [
            FsmState::SynAckSent,
            FsmState::GuestClosed,
            FsmState::FinWait,
            FsmState::Established,
            FsmState::Connecting,
        ] {
            assert!(
                flow_expired(state, just_over),
                "{state:?} idle past the deadline should expire"
            );
        }
    }

    #[test]
    fn active_flow_within_deadline_survives() {
        // A flow with recent activity (idle well under the deadline)
        // is never reaped, no matter the state — the busy long-lived
        // flow must survive the sweep.
        let recent = Duration::from_secs(1);
        for state in [
            FsmState::SynAckSent,
            FsmState::GuestClosed,
            FsmState::FinWait,
            FsmState::Established,
            FsmState::Connecting,
        ] {
            assert!(
                !flow_expired(state, recent),
                "{state:?} with recent activity should survive"
            );
        }
        // Exactly at the deadline is treated as expired (>=), one tick
        // under is not.
        assert!(flow_expired(FsmState::Established, OUTBOUND_IDLE_TIMEOUT));
        assert!(!flow_expired(
            FsmState::Established,
            OUTBOUND_IDLE_TIMEOUT - Duration::from_nanos(1)
        ));
    }
}
