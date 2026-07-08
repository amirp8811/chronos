# HOW CHRONOS BEATS THE TRILEMMA

**Document status:** Canonical escape architecture (v1.0)  
**Date:** 2026-07-08  
**Attitude:** Constructive. The classical impossibility is real for *one protocol class*. This document is the way **out of that class** and into a system that can deliver **strong anonymity + interactive latency + low *incremental* bandwidth** under explicit, engineerable assumptions.  
**Companion:** `docs/TRILEMMA_SOLUTION_PLAN.md` (measurement, gates, honesty).  
**This file:** the actual design that makes the three properties simultaneously true **for the CHRONOS product definition below**.

---

## 0. The only sentence that matters

> **You do not beat the trilemma by inventing a better mixnet.**  
> **You beat it by leaving the protocol class the proofs constrain — and by redefining the service so “bandwidth overhead” is prepaid isochronous capacity, not per-message padding panic.**

Das et al. (S&P 2018) and follow-ons prove: within a wide class of *online packet-mixing ACNs*, strong anonymity forces either high latency, high dummy bandwidth, or both — especially at low real traffic.

**CHRONOS escape thesis:**

```text
CHRONOS-X = prepaid isochronous transport
          + offline/precomputed crypto (cMix-style)
          + anytrust verifiable shuffle (Riffle-style core)
          + PIR receive path (no broadcast download leak)
          + optional DC-net / user-coordination for org pods
          + busy-epoch free-riding when aggregate r is high
```

Under that architecture, for a user who has already paid the **slot subscription**:

| Property | How it becomes true |
|---|---|
| **Strong anonymity** | Full-batch anytrust shuffle + fixed-size cells + isochronous emission ⇒ GPA cannot link by timing/length; content unlinkable if ≥1 honest shuffle server |
| **Low latency** | Real-time path has **no PK crypto** (precompute) and **no threshold wait** (slot already reserved); latency ≈ slot period + path RTT, target **≤ 100–150 ms** continental |
| **Low bandwidth overhead** | Incremental β ≈ **1.0–1.15×** on top of the prepaid isochronous stream (FEC + headers only). Cover is not “extra” — it *is* the stream |

That is not marketing. That is changing the cost accounting **and** the protocol class.

---

## 1. What the impossibility *actually* forbids

### 1.1 Forbidden (do not try)

- Silent user most of the time  
- Bursty send of variable-size packets  
- Online onion decryption + ad-hoc cover  
- Claim “GPA-strong” with Tor-like free silence  

⇒ Then yes: choose two.

### 1.2 Not forbidden (escape hatches the papers themselves point at)

| Hatch | Literature signal | CHRONOS use |
|---|---|---|
| **Leave the mix-only class** | *Beyond Mix-Nets*: only “crypto-magic” / efficient secret sharing / FHE onion / amortized setups escape | Hybrid shuffle + PIR + DC-net pods |
| **User coordination / secret sharing** | Comprehensive Trilemma (PoPETs 2020): coordination relaxes bounds; DC-net lineage | Org pods + optional global setup phase |
| **Offline / amortized setup** | cMix precomputation; secret-share offline | Nightly/hourly precompute epochs |
| **Anytrust small server set** | Riffle | Shuffle cascade (not 1000 untrusted free relays for the strong core) |
| **PIR receive** | Riffle, Pung, Addra | Download without revealing interest |
| **Organizational topology** | PriFi, OrgAn | Local relay + remote anytrust guards off critical path |
| **Busy network** | Rate \(r\) large ⇒ natural anonymity set | Free strong mode when full |
| **Prepaid constant rate** | Isochronous / leased-line anonymity | Slot subscription product |

### 1.3 The β accounting trick (legitimate product design)

**Classical β:**

\[
\beta_{\text{classical}} = \frac{\text{bytes on wire}}{\text{useful payload bytes}}
\]

for a user who is *silent unless sending*. Cover to hide silence dominates.

**CHRONOS β (product):**

\[
\beta_{\text{CHRONOS}} = \frac{\text{bytes on wire}}{\text{prepaid isochronous quota bytes}}
\]

Users buy a **slot** (e.g. 10–50 pkt/s of fixed CHR7 cells). Whether payload or cover, the wire looks identical. Useful data **replaces** cover inside the prepaid stream.

Then:

- Anonymity does not require *additional* cover beyond the subscription.  
- Latency does not require waiting for \(K\) strangers if the epoch batch is the set of **subscribed slots** (always full by construction).  
- Strong anonymity holds among the epoch’s honest subscribers.

**This is how telephone mixers, military isochronous trunks, and PriFi-style DC slots all “cheat” the folk trilemma.** They never offered free silence.

**CHRONOS product rule:** Free-silence stream mode is **not** the strong-anonymity SKU. Strong SKU = slot subscription (or org DC-net membership).

---

## 2. Target claims (what we will be able to say)

### 2.1 Strong product claim (CHRONOS-X Message / Slot mode)

Under assumptions A1–A6 below, CHRONOS-X provides:

1. **Strong epoch sender–receiver unlinkability** against a global passive adversary observing all links outside the anytrust set.  
2. **End-to-end real-time latency** ≤ **150 ms** p50 / **300 ms** p95 on continental Internet paths for ≤ 1 KiB messages (slot ≤ 50 ms + path).  
3. **Incremental bandwidth** ≤ **1.15×** prepaid quota (headers + light FEC), i.e. no 10× dummy tax on top of subscription.

### 2.2 Assumptions (non-negotiable honesty)

| ID | Assumption |
|---|---|
| **A1** | User holds an **active slot subscription** (or org pod membership) for the epoch — not free silence |
| **A2** | **Anytrust:** ≥ 1 shuffle server honest (Riffle-style), **or** DC-net pod with ≥ 2 honest clients |
| **A3** | Fixed cell size; no application-layer length leaks |
| **A4** | Precomputation epoch completed (or continuous pipeline of precomputed rounds) |
| **A5** | Directory / mailbox **PIR** (or broadcast) for receive interest |
| **A6** | Active adversary / malicious jamming handled by separate DoS layer (not free in base claim) |

If any of A1–A6 is dropped, fall back to profiled mix frontier (`TRILEMMA_SOLUTION_PLAN.md`) — choose two.

### 2.3 What we still will not claim

- Strong anonymity for **silent free users** at low λ and low β.  
- Tor-equivalent open-web TCP streams with GPA-proofing and no subscription.  
- Security if **all** anytrust servers collude (unless DC-net pod path used).

---

## 3. Architecture: CHRONOS-X (the way)

```text
                         ┌──────────────────────────────┐
                         │     PRECOMPUTE PLANE         │
                         │  (hourly / continuous)       │
                         │  cMix pads, shuffle seeds,   │
                         │  key ladders, slot tickets   │
                         └──────────────┬───────────────┘
                                        │ material
        clients                         v
   ┌─────────────┐              ┌───────────────┐              ┌─────────────┐
   │ chronos-lite│  fixed CHR7  │  ENTRY GUARD  │  isochronous │ SHUFFLE     │
   │ / wasm      │─────────────►│  (slot pace)  │─────────────►│ CASCADE     │
   │ slot filler │  always-on   │  TDM emit     │              │ anytrust    │
   └─────────────┘              └───────────────┘              │ cMix RT     │
                                                               └──────┬──────┘
                                                                      │
                                                    ┌─────────────────┼─────────────────┐
                                                    v                 v                 v
                                              ┌──────────┐     ┌──────────┐     ┌──────────────┐
                                              │ Mailbox  │     │ Stream   │     │ Org DC-net   │
                                              │ store +  │     │ exit     │     │ pod (PriFi-  │
                                              │ PIR read │     │ (weaker) │     │ like)        │
                                              └──────────┘     └──────────┘     └──────────────┘
```

### 3.1 Three SKUs (all real; only first two beat trilemma)

| SKU | Name | Anonymity | Latency | Incremental β | Mechanism |
|---|---|---|---|---|---|
| **X1** | **Slot Messenger** | Strong (epoch) | Interactive | ~1.0–1.15× quota | Isochronous + anytrust shuffle + PIR |
| **X2** | **Org Pod** | Strong (pod) | Very low (~50–100 ms) | O(pod) or PRG-based | PriFi/OrgAn-style DC-net; guards off critical path |
| **X3** | **Open Stream** | Moderate | Lowest | Low | Adaptive mix profiles — **does not claim to beat trilemma** |

**X1 + X2 are the “we found a way.”** X3 is Tor-adjacent honesty mode.

---

## 4. Mechanism deep dive

### 4.1 Isochronous slot layer (kills the “wait for K” horn)

**Design:**

- Epoch length \(T_e\) (e.g. 50 ms).  
- Each subscriber owns \(s\) fixed slots per epoch (or probabilistic token tickets).  
- Every slot emits exactly one CHR7 cell (payload or indistinguishable cover).  
- Entry guard **never** gates on queue fill — schedule is clock-driven (`tdm.rs` + hard timer).

**Why strong anonymity doesn’t need threshold wait:**

The anonymity set is the **set of active subscribers in the epoch**, not “whoever happened to speak.”  
By construction the batch is full every epoch.

**Latency:**

\[
\lambda_{\text{mix}} \le T_e \quad (+ \text{shuffle cascade real-time})
\]

Pick \(T_e = 50\,\text{ms}\) → mix contribution bounded.

**Bandwidth:**

User pays \(s / T_e\) cells/sec always. That is the price of strong anonymity — **up front**, not as surprise cover storms.

**Implementation map:**

| Piece | Today | Build |
|---|---|---|
| Slot planner | `tdm.rs` | Harden to epoch clock + tickets |
| Cover = real envelope | `secure_cell` | Mandatory path in lite client |
| Guard pacing | partial in chronosd | Make default for X1 |
| Subscription / tickets | missing | `chronos-dir` + blinded tokens |

### 4.2 cMix-style precomputation (kills real-time crypto latency)

**Problem:** Classical mix PK ops add λ and battery cost.  
**Move:** All heavy crypto in **precompute plane**; real-time = symmetric / modular multiplies.

**CHRONOS cMix adaptation:**

1. **Precompute phase** (servers only, continuous pipeline):  
   - Prepare random pads / permutation material for next \(R\) rounds.  
   - Hybrid PQC for long-term server keys stays in setup, not per message.

2. **Real-time phase** (users + servers):  
   - User encrypts with pre-shared slot keys (from handshake).  
   - Cascade replaces pads and applies precomputed permutation.  
   - No per-message ML-KEM on the hot path.

**Result:** Real-time λ dominated by network + \(T_e\), not RSA/ML-KEM.

**Implementation map:**

| Piece | Crate |
|---|---|
| Precompute worker | new `crates/chronos-precompute` |
| Round material store | `chronos-dir` or dedicated |
| Real-time apply | `chronosd` shuffle node role |
| Client slot keys | `chronos-lite` / CHS7 extension |

### 4.3 Anytrust verifiable shuffle cascade (kills GPA linking inside core)

**Model (Riffle-class):**

- Small set of shuffle servers \(S_1..S_m\) (e.g. m=3..7).  
- Anonymity if **≥1 honest**.  
- Each epoch: collect all slot cells → verifiable shuffle → output mailbox IDs / next hops.

**Why this escapes pure free-relay mix impossibility pressure:**

- Batch is complete (slots).  
- Permutation is cryptographic, not “hope timing mixes.”  
- GPA on wires sees constant-rate equal cells; inside cascade, anytrust gives content unlinkability.

**Verification:**

- Phase-1: hybrid public-key verifiable shuffle setup (epoch).  
- Phase-N: symmetric authenticated shuffles with committed permutation (Riffle hybrid).  
- Misbehavior → accusation / eject (directory).

**Implementation map:**

| Piece | Notes |
|---|---|
| Shuffle node binary | `chronosd --role=shuffle` |
| Proofs | start with simpler anytrust re-encrypt shuffle; upgrade ZK later |
| Integration | After entry guard, before mailbox/exit |

### 4.4 PIR receive path (kills download metadata)

Sending anonymously is useless if fetch reveals “who wants document D.”

**CHRONOS:**

- Mailbox writes: via shuffled deposit under unlinkable box IDs.  
- Mailbox reads: **multi-server DPF-PIR** (already prototyped in `dpf_store.rs`).  
- Clients poll on isochronous schedule (no interest-shaped timing).

**β note:** PIR has server CPU and some bandwidth expansion — that is **server-side** and amortized; client incremental download can stay near message size with modern DPF.

### 4.5 Org Pod DC-net mode (PriFi/OrgAn path — lowest λ)

For enterprises / friend groups / mesh:

- Local relay stays on normal path (no extra hops for client traffic).  
- Remote anytrust **guards** supply PRG pads **off the critical path** (PriFi insight).  
- Slot owner XORs message into DC-net; others send pure pads.  
- Latency ≈ software + local RTT; PriFi reported ~100 ms for ~100 clients.

**CHRONOS:**

- `chronos-lite` pod member  
- `chronos-dir` pod membership certs  
- Optional: power-sum collision handling (OrgAn/DiceMix ideas) in later revision

This is the nuclear option for “I need VoIP-class anonymity in a known group.”

### 4.6 Busy-epoch free ride (when nature pays for you)

When aggregate non-subscription traffic already fills large anonymity sets:

- Open Stream (X3) can raise δ̂ “for free.”  
- Controller (`mix_policy`) detects high \(\hat{r}\) → reduce cover, keep low λ.  
- **Still do not market X3 as strong** until measured — but this is how public networks get lucky.

---

## 5. Why this is “all three” without lying

### 5.1 Mapping to trilemma axes

| Axis | Classical mixnet failure | CHRONOS-X fix |
|---|---|---|
| Anonymity | Need wait or dummies when quiet | Slots always full; shuffle anytrust; PIR |
| Latency | Threshold wait + PK crypto | Fixed \(T_e\) + precompute RT path |
| Bandwidth | Dummies explode when quiet | Dummies = prepaid quota (product), not panic tax |

### 5.2 What we moved out of the “online mix class”

1. **Synchronization / full batches by construction** (slots)  
2. **Amortized secret material** (precompute, PRG pads)  
3. **Receive privacy via PIR** (not mix-only)  
4. **Optional user-coordination DC-net** (different class)  
5. **Anytrust small core** instead of hoping random free relays mix

This is exactly the research direction Das et al. leave open: *escape the characterized class* via secret-sharing / offline setup / non-mix primitives — not via wishful threshold mix tuning.

### 5.3 Cost that remains (pay it deliberately)

| Cost | Who pays | Form |
|---|---|---|
| Always-on slot rate | User | Money / battery / quota |
| Shuffle servers | Operators | Capex, anytrust governance |
| Precompute CPU | Operators | Continuous pipeline |
| PIR CPU | Mailbox operators | Horizontal scale |
| Pod setup | Org | Membership churn |

**There is no free lunch. There is a purchasable lunch that tastes like all three properties.**

---

## 6. Protocol sketch (X1 Slot Messenger — one epoch)

### 6.1 Setup (rare)

1. Client registers subscription → blinded slot tickets from directory.  
2. Client establishes long-term keys with shuffle servers (CHS7 / hybrid PQC once).  
3. Servers run precompute for rounds \(r, r+1, \ldots\).

### 6.2 Real-time epoch \(e\)

1. Client fills each owned slot:  
   - if has message: CHR7(payload)  
   - else: CHR7(cover)  
   same length, same AEAD pattern.  
2. Entry guard emits on TDM tick (no queue delay).  
3. Shuffle cascade applies precomputed round \(e\): pad replace + permute.  
4. Outputs written to mailbox indices (or stream next-hop).  
5. Recipient PIR-reads own boxes on their slot schedule.

### 6.3 Latency budget (example)

| Stage | Budget |
|---|---|
| Wait for next slot | ≤ 50 ms |
| Guard emit | ≤ 2 ms |
| Shuffle RT cascade (m=5) | ≤ 20 ms |
| Path RTT continental | ≤ 60 ms |
| PIR fetch (pipeline) | ≤ 30 ms (or async notify) |
| **Total p50 target** | **≤ 150 ms** |

### 6.4 Bandwidth budget (example)

- Subscription: 20 cells/s × 1280 B = 25.6 KB/s always.  
- Useful chat: 1 KB every 2 s → mostly cover replacement.  
- Incremental overhead beyond quota: FEC 10% + headers → **β_CHRONOS ≤ 1.15**.  
- Classical β vs silence would look huge — **we do not sell silence**.

---

## 7. Build plan (make it real in the monorepo)

### 7.1 Workstreams

| WS | Name | Primary crates | Weeks |
|---|---|---|---|
| **WS0** | Slot tickets + epoch clock | `chronos-dir`, `chronos-core/clock`, `tdm` | 1–3 |
| **WS1** | Always-on slot client | `chronos-lite`, `chronos-wasm` | 2–5 |
| **WS2** | Precompute plane | new `chronos-precompute`, `chronosd` | 3–8 |
| **WS3** | Anytrust shuffle role | `chronosd`, proofs crate | 5–12 |
| **WS4** | PIR mailbox default | `dpf_store`, `chronos-dir` | 4–10 |
| **WS5** | Org pod DC-net MVP | `chronos-lite`, guards | 8–16 |
| **WS6** | Measurement vs claims | `anonymity_metrics`, sim | continuous |

### 7.2 Milestones

| M | Deliverable | Pass test |
|---|---|---|
| **M0** | Spec freeze: this doc + wire notes | Review sign-off |
| **M1** | Local 3-node isochronous slot loop | GPA timing MI ≈ 0 on equal cells; λ ≤ \(T_e\)+jitter |
| **M2** | Precompute + RT path no PK | Flamegraph: no ML-KEM on RT |
| **M3** | 5-server shuffle, anytrust sim | Corrupt 4/5; still unlinkable in model |
| **M4** | PIR read default | No cleartext “get box X” |
| **M5** | 100-user lab | p50 ≤ 150 ms; β_CHRONOS ≤ 1.15; classifier AUC ≤ 0.55 |
| **M6** | Org pod 50 users | λ ≤ 100 ms; strong pod anonymity |
| **M7** | Public frontier report | Compare X1 vs old mix profiles |

### 7.3 Mapping onto existing code (start tomorrow)

```text
mix_policy.rs     → slot profile "IsochronousStrong" (no reduced flush; clock only)
tdm.rs            → hard epoch scheduler (already skeleton)
secure_cell.rs    → only legal wire unit for X1
anonymity_metrics → prove MI collapse under isochronous
fountain.rs       → optional light FEC inside quota
dpf_store.rs      → mailbox PIR (promote from prototype)
chronosd          → roles: guard | shuffle | mailbox
chronos-dir       → tickets, server anytrust set, epochs
```

### 7.4 Explicit non-goals for v1 of the escape

- Full open-Internet TCP streams with X1 claims  
- All-honest-majority global free mix (X3 only)  
- Zero cost for offline users  

---

## 8. Security argument (sketch for auditors)

### 8.1 Passiveivity (GPA)

All subscriber cells equal length, equal rate, AEAD hides content.  
Observer sees only slot occupancy that is **always 100%**.  
⇒ Timing/volume classifiers get no feature. (Measure with existing harness.)

### 8.2 Cryptographic unlinkability (anytrust)

If ≥1 shuffle server honest and verifiable shuffle holds:  
output order independent of input order from adversary’s view.  
⇒ Sender–output linking advantage negligible beyond \(1/N_{\text{honest slots}}\).

### 8.3 Receiver privacy

PIR (or full broadcast) ⇒ server learns neither index nor (with multi-server) query.

### 8.4 Active adversary

Separate: PoW admission (exists), TLS/link auth, shuffle verification, jamming detection.  
Base trilemma claim is **passive GPA + anytrust**. Extend later.

### 8.5 What formal work to commission

1. Reduction: X1 epoch ≈ ideal shuffle functionality + isochronous wrapper.  
2. Proof that prepaid isochronous wrapper does not reintroduce timing channel.  
3. PIR security composition with mailbox IDs after shuffle.

---

## 9. Comparison table (why this is the way)

| System | Strong vs GPA | Interactive λ | Low incremental β | Notes |
|---|---|---|---|---|
| Tor | No | Yes | Yes | Open stream |
| Classical mixnet | Yes | No | Maybe | Wait or pad |
| Loopix | Better | Medium | Medium | Continuous delay |
| cMix alone | Yes (batch) | Better crypto λ | Batch still | Needs full batch |
| Riffle | Yes (anytrust) | Medium | Better | Shuffle+PIR |
| PriFi | Yes (org) | Yes | Org-scale | DC-net topology |
| **CHRONOS-X1** | **Yes (anytrust+slots)** | **Yes (Te)** | **Yes (prepaid)** | **Compose best pieces** |
| **CHRONOS-X2** | **Yes (pod)** | **Yes** | **Pod-local** | Org nuclear option |

---

## 10. Answer to “IDGAS find a way”

### The way

1. **Stop selling free silence as strong anonymity.**  
2. **Sell isochronous slots** so batches are always full and cover is prepaid.  
3. **Precompute crypto** so real-time is fast (cMix).  
4. **Anytrust verifiable shuffle** so GPA content linking dies (Riffle).  
5. **PIR fetch** so receive metadata dies.  
6. **Org DC-net pods** when you need even lower λ in a closed group (PriFi).  
7. **Keep open stream** as a weaker SKU for people who refuse to pay slots.  
8. **Measure everything** so the claim stays true under load.

### One-line formula

\[
\boxed{\text{Strong + Fast + Cheap-at-the-margin}
= \text{Prepaid isochrony}
+ \text{Precomputed anytrust shuffle}
+ \text{PIR}}
\]

That is not a violation of mathematics.  
That is **choosing the only engineering point where all three live at once.**

---

## 11. Immediate execution checklist (next 72 hours)

- [ ] Add profile `MixProfile::IsochronousStrong` with clock-only flush (no reduced threshold).  
- [ ] Spec slot ticket format in `docs/spec/SLOT-TICKETS.md`.  
- [ ] Client always-on cover filler in chronos-lite (even stub).  
- [ ] Experiment: isochronous vs adaptive mix — show MI→0 and β_CHRONOS definition.  
- [ ] Design doc for shuffle role + precompute pipeline.  
- [ ] Promote DPF mailbox read to default path design.  
- [ ] Update README: X1/X2/X3 SKUs; link this file.

---

## 12. Bottom line

The classical trilemma says: **in the old game, pick two.**

CHRONOS changes the game:

- **Anonymity** from cryptographic anytrust shuffle + full epochs  
- **Latency** from fixed slots + precompute (no threshold wait, no RT PK)  
- **Bandwidth** from prepaid isochronous quota (incremental β≈1)

**That is the way.** Build X1 first. Prove it with the metric stack. Ship pods as X2. Leave free open stream as the honest “choose two” tier.

---

## References (entry points)

- Das et al., *Anonymity Trilemma*, IEEE S&P 2018  
- Das et al., *Beyond Mix-Nets* / secret-sharing extensions  
- PoPETs 2020 *Comprehensive Anonymity Trilemma* (user coordination)  
- cMix (ACNS 2017) — precomputation  
- Riffle — hybrid verifiable shuffle + PIR  
- PriFi / OrgAn — low-latency organizational DC-nets  
- CHRONOS in-tree: `mix_policy`, `tdm`, `secure_cell`, `dpf_store`, `anonymity_metrics`
