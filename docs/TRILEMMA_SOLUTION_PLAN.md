# CHRONOS Plan to Truly Address the Anonymity Trilemma

**Document status:** Living engineering plan (v1.0)  
**Escape architecture:** see also [`HOW_TO_BEAT_THE_TRILEMMA.md`](HOW_TO_BEAT_THE_TRILEMMA.md) for the constructive “all three” design.  
**Date:** 2026-07-08  
**Audience:** Protocol designers, implementers, auditors  
**Scope:** How CHRONOS moves from a hardened prototype toward *honest*, *measurable*, and (where possible) *formally justified* performance on the anonymity–latency–bandwidth frontier  

---

## 0. Executive result (read this first)

### 0.1 The honest answer

You **cannot** “solve” the classical Anonymity Trilemma in the absolute sense claimed by marketing language:

> simultaneously achieve **strong** anonymity, **low** latency, and **low** bandwidth overhead, against a **global passive adversary**, with **no** extra assumptions, for **arbitrary** traffic patterns.

That statement is contradicted by impossibility results for a wide class of mix-style anonymous communication networks (ACNs) (Das, Meiser, Mohammadi, Kate — *Anonymity Trilemma: Strong Anonymity, Low Bandwidth Overhead, Low Latency — Choose Two*, IEEE S&P 2018; extensions in *Beyond Mix-Nets*).

So the **true** goal is not a magic protocol that violates information-theoretic bounds. The true goal is:

1. **State the adversary and success metrics precisely** (so claims are falsifiable).  
2. **Escape or relax the model assumptions** where the impossibility proofs rely on them (synchronization class, observation model, traffic model, trust model).  
3. **Operate on the achievable frontier** with quantitative targets (e.g. “GPA success ≤ δ at latency ≤ λ and overhead ≤ β”).  
4. **Prove or measure** every claim with formal tools *and* large-scale experiments.  
5. **Ship a system** that is better than Tor-like low-latency overlays under GPA *and* better than classical high-latency mixnets under interactive latency budgets — under **documented** assumptions.

That is what “solving the trilemma” means for CHRONOS: **dominate the practical Pareto frontier under stated models**, not deny mathematics.

### 0.2 What “success” means for CHRONOS (definition of done)

CHRONOS will claim a **trilemma-competitive win** only when **all** of the following hold:

| ID | Requirement | Pass criterion |
|---|---|---|
| **S1** | Threat model published | `docs/threat-model.md` with GPA / partial GPA / ISP / AS / malicious relay fractions; no silent assumptions |
| **S2** | Formal bounds | Published mapping of CHRONOS parameters \((K, \lambda_{\max}, \beta, n_{\text{users}}, r)\) to anonymity notions (entropy / distinguishing advantage / δ-GPA success) with proofs *or* cited reduction to known theorems |
| **S3** | Empirical GPA resistance | Simulator + testnet: mutual information / classifier AUC / Bayesian success below target δ for ≥ 10⁵ packet epochs |
| **S4** | Latency budget | Interactive profile: median RTT ≤ 150 ms on continental paths; p95 ≤ 300 ms **with** cover policy on |
| **S5** | Bandwidth budget | Steady-state multiplier ≤ 2.0× for Normal profile; ≤ 1.4× for Fast; HighAnonymity allowed higher but must publish curve |
| **S6** | Metadata privacy | Directory / mailbox lookups via PIR (or equivalent oblivious path); no cleartext destination popularity channel |
| **S7** | Crypto soundness | Hybrid handshake + route layer: external review + KATs + fuzz + (where feasible) machine-checked properties |
| **S8** | Scale | ≥ 100 relays in simulation; ≥ 20 relays in real testnet; churn and partial compromise evaluated |
| **S9** | Reproducibility | One-command experiment suite producing the S3–S5 tables; CI gates on regressions |
| **S10** | Claim hygiene | README never says “solves the trilemma” without linking this document’s definitions |

**Result of this plan document:** a complete phased path from today’s prototype to S1–S10, with work packages, file ownership, metrics, and kill criteria.

---

## 1. Formal statement of the problem

### 1.1 Classical trilemma (informal)

For many ACNs, any design that keeps:

- **Latency overhead** \(\lambda\) small, and  
- **Bandwidth / cover overhead** \(\beta\) small,

cannot simultaneously keep a **global passive adversary’s** linking advantage \(\delta\) negligible when user sending rates are low or bursty.

Intuition:

- Strong anonymity against a GPA requires **mixing** (many users’ packets become indistinguishable).  
- Mixing requires either **waiting** (latency) or **padding / cover** (bandwidth) or **both**.  
- At low real traffic, you cannot fill anonymity sets without one of those costs.

### 1.2 Parameters CHRONOS must track

| Symbol | Meaning | CHRONOS knobs today |
|---|---|---|
| \(n\) | Active users / streams in epoch | directory + sessions |
| \(r\) | Real payload rate (pkt/s or B/s) | clients |
| \(K\) | Mix batch / anonymity set target | `mix_policy.target_k` |
| \(\lambda_{\max}\) | Max hold time | `mix_policy.max_wait_ms` |
| \(\beta\) | Bandwidth multiplier (sent / useful) | cover + FEC overhead |
| \(L\) | Path length (hops) | route layer |
| \(\delta\) | Adversary success / distinguishing advantage | measured + bounded |
| \(H\) | Anonymity entropy (bits) | measured |
| \(\varepsilon\) | DP budget if using noisy cover | future `mix_policy` |

### 1.3 Anonymity notions (pick explicitly; do not blur)

CHRONOS must report **separately**:

1. **Sender–receiver unlinkability** under GPA (packet timing + lengths on all links).  
2. **Sender anonymity** within an epoch (who sent a given egress unit).  
3. **Relationship anonymity** over long sessions (intersection / disclosure attacks).  
4. **Local adversary** (one ISP / one AS) — weaker than GPA; useful for UX profiles.  
5. **Active adversary** (drops, delays, confirms) — separate from passive trilemma core.

**Rule:** Every experiment labels which notion it measures.

### 1.4 What impossibility does *not* forbid

Impossibility results constrain a **class** of protocols and adversary models. They leave room when CHRONOS:

| Escape hatch | How CHRONOS uses it |
|---|---|
| **Weaker adversary than full GPA** | “Local / ISP” profiles with honest claims |
| **Bounded rate / busy networks** | Anonymity improves as \(r\) rises; design for busy epochs |
| **Non-mix primitives** | PIR mailboxes, DC-net style slots, PIR directory (outside pure mix bounds) |
| **Trusted hardware / TEE** | Optional *not* required for base claims |
| **Economic Sybil resistance** | Stake / reputation changes robustness, not pure GPA math |
| **Multipath + coding** | Attacks HoL and loss-induced latency without reducing cover need to zero |
| **Isochronous / physical-layer tricks** | Research option only; not base CHRONOS claim |
| **User-selectable profiles** | Explicit λ–β–δ menus instead of one universal point |

CHRONOS’s strategy is a **portfolio** of escape hatches, not a single loophole.

---

## 2. Where CHRONOS is today (baseline)

### 2.1 Assets already in tree

| Component | Path | Trilemma relevance |
|---|---|---|
| Adaptive mix policy | `crates/chronos-core/src/mix_policy.rs` | Direct λ–K–cover control |
| TDM slot planner | `crates/chronos-core/src/tdm.rs` | Constant-rate pacing plan |
| Traffic shape metrics | `crates/chronos-core/src/traffic_analysis.rs` | Length/interval regularity |
| MI / KL / CDF harness | `crates/chronos-core/src/anonymity_metrics.rs` | Empirical δ proxies |
| RS (16,10) | `crates/chronos-core/src/gf28.rs`, `shard_stream.rs` | Loss resilience vs overhead |
| Fountain prototype | `crates/chronos-core/src/fountain.rs` | Progressive recovery experiments |
| Route layer (RTE7) | `crates/chronos-core/src/route_layer.rs` | Unlinkability substrate |
| Hybrid PQC handshake | `handshake*`, `hybrid_route.rs` | Session secrecy (not mixing) |
| DPF-PIR prototype | `crates/chronos-lite/src/dpf_store.rs` | Metadata / mailbox privacy |
| Directory consensus | `crates/chronos-dir` | Trust / membership |
| Relay daemon | `crates/chronosd` | Deployment unit |
| Experiment CLI | `tools/chronos-nettest`, `scripts/run_mix_experiments.sh` | Reproducible sweeps |

### 2.2 Critical gaps vs S1–S10

| Gap | Why it blocks “true” progress |
|---|---|
| README / architecture still over-claim | Destroys scientific credibility |
| No complete threat model doc | Claims unfalsifiable |
| Sphinx module still simulation-grade | Route privacy not audit-ready |
| AF_XDP / io_uring not production | λ dominated by software, not theory |
| Cover traffic not cryptographically indistinguishable at application semantics | Classifier risk |
| No multi-hop GPA simulator with colluding relays | S3 incomplete |
| PIR not default for directory | Metadata side channel |
| No formal mapping \((K,\lambda,\beta)\to\delta\) | Cannot choose parameters rationally |
| No large testnet | Scale effects unknown |
| FEC fixed 1.6× always-on | β floor too high for Fast profile |

### 2.3 Baseline empirical snapshot (prototype mixer only)

From current `chronos-nettest` leak-audit style runs (single-hop simulated adaptive mix; **not** a full GPA proof):

- Identity (no mix) timing MI ≈ 4 bits (coarse 16-bin quantizer).  
- HighAnonymity profile can reduce MI substantially at high rate / large batch cost.  
- Cover-heavy low-rate regimes show **large** β (expected by trilemma).  
- RS(16,10) locks ~1.6× symbol overhead; fountain prototype can recover with lower *progressive* overhead in lossless lab conditions.

**Interpretation:** the control plane is alive; the network-scale evidence is not.

---

## 3. Strategy: five pillars of a real attack on the frontier

```text
                    ┌─────────────────────────────┐
                    │  Pillar 0: Claim hygiene     │
                    │  definitions, threat model  │
                    └──────────────┬──────────────┘
                                   │
     ┌─────────────────────────────┼─────────────────────────────┐
     │                             │                             │
     v                             v                             v
┌─────────────┐            ┌──────────────┐            ┌─────────────────┐
│ Pillar 1    │            │ Pillar 2     │            │ Pillar 3        │
│ Measure &   │            │ Adaptive     │            │ Coding &        │
│ bound δ     │            │ mixing &     │            │ multipath for λ │
│             │            │ cover (β,λ)  │            │ without false δ │
└──────┬──────┘            └──────┬───────┘            └────────┬────────┘
       │                          │                             │
       └──────────────┬───────────┴──────────────┬──────────────┘
                      v                          v
             ┌────────────────┐         ┌────────────────────┐
             │ Pillar 4       │         │ Pillar 5           │
             │ Metadata / PIR │         │ Scale, incentives, │
             │ & directory    │         │ dataplane, audit   │
             └────────────────┘         └────────────────────┘
```

**Ordering principle:** never optimize dataplane before measurement, and never claim anonymity from latency tricks that do not increase mixing or cryptographic uncertainty.

---

## 4. Pillar 0 — Claim hygiene and threat model (Week 0–2)

### 4.1 Deliverables

1. **`docs/threat-model.md`**  
   - Adversaries: GPA, k-link observer, malicious fraction f of relays, active delay/drop.  
   - Assets: packet unlinkability, session secrecy, directory privacy.  
   - Out of scope: endpoint malware, global active adaptive adversary v1, etc.

2. **`docs/claims-matrix.md`**  
   Table: *Claim → required assumptions → evidence type (proof/measure) → status*.

3. **README rewrite**  
   Replace “engineered to overcome the Anonymity Trilemma” with:

   > CHRONOS targets the practical anonymity–latency–bandwidth frontier under an explicit threat model. Absolute simultaneous optimization of all three against a GPA is information-theoretically constrained; see `docs/TRILEMMA_SOLUTION_PLAN.md`.

4. **Parameter card** in SECURITY.md: publish default \((K, \lambda_{\max}, \beta_{\text{target}}, L)\) per profile.

### 4.2 Exit criteria

- External reader can state what CHRONOS does *not* claim.  
- CI link-check: README links to this plan and threat model.

---

## 5. Pillar 1 — Measure and bound δ (the most important engineering work)

### 5.1 Why this is first

Without δ measurement, every mixer change is cargo-cult. The trilemma is a **quantitative** object.

### 5.2 Metric stack (mandatory)

| Layer | Metric | Tooling |
|---|---|---|
| L0 | Constant length / interval regularity | `traffic_analysis` |
| L1 | Shannon entropy of inter-departure times | `anonymity_metrics` |
| L2 | KL(egress ‖ ideal constant-rate) | `anonymity_metrics` |
| L3 | Mutual information ingress↔egress times | `anonymity_metrics` |
| L4 | Supervised classifier AUC (XGBoost / logistic on timing features) | new `tools/chronos-adversary` |
| L5 | Bayesian / exact linking on toy topologies | new simulator |
| L6 | Long-term intersection attack success | multi-day sims |

**Policy:** Ship L0–L3 in CI; L4–L6 in nightly experiment jobs.

### 5.3 Work packages

#### WP-1.1 Multi-hop topology simulator

**Owner crate:** `tools/chronos-nettest` → evolve into `tools/chronos-sim`

Features:

- Configurable stratified topology (entry / middle / exit).  
- Per-hop adaptive mix + TDM.  
- Adversary views:  
  - full GPA (all edges),  
  - partial (random fraction of edges),  
  - ISP (contiguous path segments).  
- Output: packet traces + JSON report of L0–L4.

#### WP-1.2 Adversary classifier suite

- Feature vectors: inter-arrival, burst length, size (should be constant), path RTT noise.  
- Train on labeled sender flows; report AUC and TPR @ FPR=0.01.  
- **Kill criterion for a “profile”:** AUC ≥ 0.7 under GPA ⇒ profile must not be marketed as strong anonymity.

#### WP-1.3 Parameter surface explorer

Automate grid:

```text
K ∈ {64, 256, 1024, 4096, 25000}
λ_max ∈ {10, 20, 50, 100, 200} ms
r ∈ {1, 10, 50, 200, 1000} pkt/s/user
L ∈ {2, 3, 4}
cover ∈ {off, adaptive, constant}
```

Produce Pareto plots: δ̂ vs λ vs β.

#### WP-1.4 Analytic bound notebook

Document mapping using known mixnet bounds (threshold mix / pool mix approximations):

- For threshold mix, anonymity set size scales with arrivals during wait;  
- For continuous-time mix (Loopix-style), exponential delay parameter μ sets λ and anonymity.

Deliverable: `docs/spec/parameter-to-anonymity.md` with formulas + simulation validation.

### 5.4 Exit criteria (Pillar 1)

- One command reproduces Pareto CSVs.  
- CI fails if Normal profile regresses AUC by > 0.05 or β by > 10%.  
- Public figures for at least one GPA and one ISP adversary.

---

## 6. Pillar 2 — Adaptive mixing and cover (buying δ with λ and β intelligently)

### 6.1 Design thesis

Fixed \(K=25000\) @ 50 ms is **incoherent** at low \(r\):

\[
\text{expected batch fill time} \approx K / r_{\text{aggregate}}
\]

If fill time ≫ 50 ms, you either violate latency or flush tiny batches (weak anonymity) or emit massive cover (β explosion).

**CHRONOS answer:** multi-objective controller, not a single constant.

### 6.2 Control law (target architecture)

State at each relay epoch \(t\):

- \(q_t\): real queue length  
- \(\hat{r}_t\): EWMA ingress rate  
- \(\hat{a}_t\): estimated active senders (from directory epoch or local observation)  
- profile \(p \in \{\text{Fast}, \text{Normal}, \text{HighAnon}\}\)

Actions:

- flush real  
- emit cover cells \(c_t\)  
- adjust local slot rate  
- signal neighbors for coordinated isochronous epochs (optional phase 2)

Objective (soft constraint form):

\[
\min \;\; w_\lambda \cdot \text{latency} + w_\beta \cdot \beta
\quad \text{s.t.}\quad \hat{\delta}(q,\hat{r},c,K) \le \delta_p
\]

where \(\delta_p\) is the profile’s max adversary advantage.

### 6.3 Implementation plan

| Step | Change | Files |
|---|---|---|
| 2.1 | Formalize profiles with \(\delta_p, \lambda_p, \beta_p\) targets | `mix_policy.rs`, SECURITY.md |
| 2.2 | EWMA rate estimator + active-sender estimate | `chronosd` mixing path |
| 2.3 | Coordinated epoch clock (logical epochs, signed) | `clock.rs`, directory |
| 2.4 | Cover cell generator: **same length, same crypto envelope, same schedule** | `secure_cell`, `tdm` |
| 2.5 | Per-client SLAs: clients advertise profile in handshake | CHS7 extension |
| 2.6 | Differential privacy option: Laplace noise on cover rate with ε budget | new module |

### 6.4 Cover traffic rules (non-negotiable)

1. Cover is **indistinguishable** on the wire (CHR7 cells).  
2. Cover **never** carries distinguishable timing relative to real under the profile’s schedule.  
3. Cover generation is **rate-limited by policy**, not “as much as needed to fake K=25k” at 1 pkt/s (that is β suicide).  
4. Prefer **shared cover** (relay-level isochronous emission) over per-client cover when topology allows.

### 6.5 Loopix-style continuous mixing (phase B)

Threshold batches help under high load; under interactive load, evaluate **per-hop exponential delays** (Loopix / Katzenpost lineage):

- Sender samples delay per hop.  
- Independent delays reduce sync batch artifacts.  
- Still subject to trilemma, but often better latency distribution for similar average anonymity.

**Experiment:** A/B threshold adaptive vs continuous-time mix in `chronos-sim`.

### 6.6 Exit criteria

- Fast / Normal / HighAnon each have published (λ, β, δ̂) operating points.  
- Controller never silently exceeds β_max without client consent.  
- Low-rate scenario does not claim HighAnon without enormous β or λ.

---

## 7. Pillar 3 — Coding and multipath (spend β to reduce *loss-induced* λ, not to fake anonymity)

### 7.1 Separation of concerns

Erasure coding **does not** replace mixing.  
It reduces retransmit latency and HoL blocking under loss — which improves **experienced** latency for a **fixed** anonymity schedule.

### 7.2 FEC roadmap

| Phase | Codec | Goal |
|---|---|---|
| Now | RS(16,10) systematic | Correctness baseline |
| P3.1 | Configurable (n,k) | Trade β vs loss tolerance |
| P3.2 | Sliding-window / fountain (RaptorQ-class) | Progressive decode; lower tail latency |
| P3.3 | Adaptive redundancy | Increase parity only when loss detected |
| P3.4 | Multipath scheduling | Send shards on diverse AS paths |

### 7.3 Multipath anonymity caution

Naive multipath can **hurt** anonymity (endpoint correlation, asymmetric observation). Rules:

1. Paths chosen from **relay-selected** diversity, not client IP affinity alone.  
2. Shard schedules still pass through mix epochs.  
3. Measure L3/L4 with multipath **on** — multipath ships only if δ̂ does not worsen beyond budget.

### 7.4 Exit criteria

- Documented curve: loss rate → needed β_FEC → p95 latency.  
- Adaptive FEC reduces average β by ≥ 20% vs always-on (16,10) at 0–1% loss.  
- Multipath enabled only with anonymity regression tests green.

---

## 8. Pillar 4 — Metadata privacy (escape pure mix limits for *lookup* and *mailbox*)

### 8.1 Why this matters

Even perfect packet mixing fails if:

- directory queries reveal destination popularity, or  
- mailbox fetches reveal who talks to whom.

These are **not** solved by TDM alone.

### 8.2 Directory

| Item | Plan |
|---|---|
| Consensus | Finish BFT path in `chronos-dir` with signed snapshots |
| Fetch | Default **PIR / DPF** read for client directory views (`dpf_store` integration) |
| Publish | Rate-limited, signed relay descriptors; no cleartext “who asked for X” logs |
| Epoch | Directory epochs aligned with mix epochs where possible |

### 8.3 Mailbox / dead-drop (asynchronous messaging)

For messaging (not bulk TCP tunnel):

- Write: deposit under unlinkable IDs via entry guards.  
- Read: multi-server PIR (already prototyped).  
- This can provide **stronger** relationship anonymity for async use cases at acceptable λ.

### 8.4 Stream mode vs message mode

CHRONOS should split products:

| Mode | UX | Anonymity approach |
|---|---|---|
| **Message mode** | chat, mail, signals | PIR mailbox + mix |
| **Stream mode** | interactive bytes | continuous mix + cover + short paths |
| **Bulk mode** | large transfer | high λ, high K, low cover waste |

**True trilemma progress often comes from not forcing stream mode to pretend to be DC-net.**

### 8.5 Exit criteria

- Directory cleartext query path removed from default client.  
- PIR end-to-end test in CI.  
- Messaging demo with published relationship-anonymity experiment.

---

## 9. Pillar 5 — Scale, dataplane, crypto soundness, incentives

### 9.1 Dataplane (buy real λ headroom)

Theory λ is mixing delay; implementation λ is crypto + syscall + scheduling.

| Priority | Work | Crate |
|---|---|---|
| D1 | Real `io_uring` path for UDP relay | `chronos-sys-dataplane`, `chronosd` |
| D2 | AF_XDP zero-copy RX/TX on Linux | same |
| D3 | Batch AEAD (ChaCha20-Poly1305) | `chronos-core` |
| D4 | CPU pinning + queue isolation | `chronosd` |
| D5 | Benchmarks: pkt/s, µs/pkt, cache misses | `benches/` |

**Target:** processing ≪ mix delay (e.g. < 5% of λ_max) so anonymity parameters dominate latency.

### 9.2 Cryptographic route layer

| Priority | Work |
|---|---|
| C1 | Freeze RTE7 wire format + test vectors |
| C2 | Remove / quarantine simulation Sphinx; single route story |
| C3 | Transcript binding for hybrid ML-KEM+X25519 |
| C4 | Replay caches proven bounded + expired |
| C5 | External crypto review |
| C6 | Kani/ProVerif for selected properties |

### 9.3 Network scale & incentives

Anonymity set is a **social** resource:

- Too few relays ⇒ intersection attacks.  
- Too centralized ⇒ GPA becomes ISP-level easy.

Plan:

1. Open testnet with geographic diversity goals.  
2. Relay bandwidth proofs / uptime scoring.  
3. Optional stake or deposit against Sybil floods (does not fix GPA, fixes active/Sybil).  
4. Guard rotation policies with measured intersection risk.

### 9.4 Exit criteria

- 10 Gbps-class lab relay **or** honest lower published capacity.  
- Audit report public.  
- Testnet ≥ 20 nodes; published δ̂ under partial compromise f ∈ {0, 0.1, 0.2}.

---

## 10. Phased timeline (12 months to “trilemma-competitive”)

### Phase 0 — Honesty & instrumentation (Weeks 0–3)

- Threat model, claims matrix, README hygiene.  
- Expand nettest → sim skeleton.  
- CI metrics gates.

**Gate G0:** S1 + partial S9.

### Phase 1 — Pareto frontier (Weeks 3–10)

- Full L0–L4 adversary suite.  
- Parameter surface explorer.  
- Profile contracts (Fast/Normal/HighAnon) with measured points.

**Gate G1:** Public Pareto plots; S3 preliminary; S5 measured for lab rates.

### Phase 2 — Mixer v2 + cover v2 (Weeks 8–18)

- Rate-adaptive controller with client SLAs.  
- Continuous-time mix option.  
- Indistinguishable cover generator integrated in chronosd path.

**Gate G2:** Interactive Normal profile meets S4 **or** documented shortfall with only dataplane left as cause.

### Phase 3 — FEC & multipath (Weeks 12–22)

- Configurable RS; fountain/RaptorQ path.  
- Adaptive redundancy.  
- Multipath with anonymity regression harness.

**Gate G3:** β reduced under low loss without δ̂ regression.

### Phase 4 — Metadata (Weeks 14–26)

- PIR-default directory.  
- Mailbox message mode MVP.  
- Remove cleartext lookup paths.

**Gate G4:** S6.

### Phase 5 — Dataplane & audit (Weeks 18–36)

- io_uring/AF_XDP production path.  
- Crypto audit.  
- Formal notes for route layer.

**Gate G5:** S7 + S4 processing budget.

### Phase 6 — Testnet & incentives (Weeks 28–52)

- 20+ relay testnet.  
- Partial compromise experiments.  
- Publish “CHRONOS Frontier Report”.

**Gate G6:** S8 + S10; decide go/no-go for mainnet claims.

---

## 11. Concrete work breakdown (engineering backlog)

### 11.1 Repository layout targets

```text
docs/
  TRILEMMA_SOLUTION_PLAN.md      # this file
  threat-model.md
  claims-matrix.md
  spec/
    parameter-to-anonymity.md
    RTE7.md
    CHR7.md
    CHS7.md
  frontier/
    YYYY-MM-pareto.md            # published experiment reports
tools/
  chronos-sim/                   # multi-hop GPA simulator
  chronos-adversary/             # classifiers
  chronos-nettest/               # integration smoke + sweeps
crates/
  chronos-core/                  # policy, metrics, crypto, FEC
  chronosd/                      # relay
  chronos-dir/                   # directory + PIR gateway
  chronos-lite/                  # client / residential
  chronos-sys-dataplane/         # HAL
scripts/
  run_mix_experiments.sh
  run_frontier_suite.sh          # full S3–S5 generator
```

### 11.2 Near-term tickets (ordered)

1. **DOC-001** Write `threat-model.md` + `claims-matrix.md`; tone down README.  
2. **SIM-001** Multi-hop simulator with GPA/partial views.  
3. **ADV-001** Timing classifier AUC pipeline.  
4. **MIX-001** Profile contracts with hard β_max / λ_max / δ̂_max.  
5. **MIX-002** EWMA controller in chronosd live path (not only sim).  
6. **COV-001** Cover cell path identical to real CHR7.  
7. **FEC-001** (n,k) parameters + adaptive parity.  
8. **PIR-001** Directory read via DPF by default in chronos-lite.  
9. **DP-001** io_uring UDP send/recv milestone.  
10. **AUD-001** Crypto review package (vectors + scope).

### 11.3 Kill criteria (stop digging)

| Symptom | Decision |
|---|---|
| HighAnon requires β > 50× at target r for δ̂ target | Pivot HighAnon to async message mode; do not market as interactive |
| Classifier AUC stays high despite cover | Cover is distinguishable — fix crypto/scheduling before more padding |
| Dataplane λ > 30% of budget | Pause protocol features; fix HAL |
| PIR too slow for directory | Hierarchical PIR / cached epochs; never revert to cleartext default |
| Testnet cannot attract diversity | Anonymity claims capped at lab-only |

---

## 12. Target operating points (initial numeric hypotheses)

> Hypotheses to **falsify** with Pillar 1 — not guarantees.

### 12.1 Fast (interactive browsing assist)

| Metric | Target |
|---|---|
| λ median | ≤ 80 ms mix contribution |
| β | ≤ 1.4× |
| δ̂ (ISP observer) | moderate (publish AUC) |
| δ̂ (full GPA) | **not** claimed strong |

### 12.2 Normal (default)

| Metric | Target |
|---|---|
| λ median | ≤ 150 ms mix contribution |
| β | ≤ 2.0× at aggregate r ≥ 500 pkt/s/relay |
| δ̂ (GPA) | below classifier AUC 0.6 on lab topologies |
| K_eff | adaptive 256–4096 |

### 12.3 HighAnonymity (sensitive)

| Metric | Target |
|---|---|
| λ median | ≤ 500 ms (or async) |
| β | ≤ 4× **or** move to message mode |
| δ̂ (GPA) | strong target: near-chance linking on epoch scale |
| Prefer | message/PIR mode when interactive β explodes |

### 12.4 The only coherent way to “have all three” for users

Offer **mode switching**:

- When network busy → Normal approaches strong δ at low β, low λ.  
- When network quiet → client UI shows cost: “wait / spend bandwidth / reduce anonymity”.  
- Never hide the trilemma from the user.

That is a product-level solution consistent with theory.

---

## 13. Validation architecture (expanded 4 gates)

| Gate | Name | Trilemma role |
|---|---|---|
| G1 | Logic & crypto correctness | Sound substrate |
| G2 | Concurrency / lifecycle | No implementation leaks |
| G3 | Topology simulation | Controlled δ̂ measurement |
| G4 | Macroscopic leak audit | Long-trace GPA classifiers |
| **G5** | **Frontier regression** | Pareto points must not worsen on main |
| **G6** | **External audit** | Human adversarial review |

### 13.1 Required CI jobs

```text
cargo test --workspace
cargo clippy -D warnings
scripts/static_audit.py
CHRONOS_NETTEST_MODE=mix-sweep ...
CHRONOS_NETTEST_MODE=leak-audit ...
# later:
chronos-sim --adversary gpa --packets 100000
chronos-adversary --eval latest_trace
```

### 13.2 Release rule

No release may advertise anonymity improvements without an updated `docs/frontier/` report.

---

## 14. Research options beyond the base plan (optional, labeled experimental)

These may push the frontier further but are **not** required for S1–S10:

1. **cMix-style precomputation** — reduce real-time crypto λ.  
2. **Hybrid DC-net slots for small groups** — strong anonymity for conferences/teams.  
3. **TEE-assisted shuffle** — strong with hardware trust; separate threat model.  
4. **Physical-layer / isochronous wireless** (CIDP-like ideas) — out of pure-software CHRONOS scope.  
5. **Formal verification** of unlinkability games for RTE7.  

Each experimental track gets its own threat model appendix; never merge into default claims silently.

---

## 15. Mapping impossibility literature → CHRONOS actions

| Literature insight | CHRONOS action |
|---|---|
| Choose two among strong anonymity / low λ / low β | Explicit profiles; UI honesty |
| Low rate forces cover or wait | Adaptive controller + busy-network incentives |
| Mix-net class is constrained | Add PIR mailbox / directory (outside pure mix) |
| Latency has mix + propagation + processing parts | Dataplane + routing locality (LARMix-like) without starving mixing |
| Continuous-time mix can improve UX | Evaluate Loopix-style delays |
| Scale & diversity matter | Testnet + anti-Sybil |

References (entry points):

- Das et al., *Anonymity Trilemma*, IEEE S&P 2018.  
- Das et al., *Anonymity Trilemma: Beyond Mix-Nets*.  
- Danezis & Goldberg, *Sphinx*.  
- Loopix / Nym / Katzenpost design notes and mixnet optimization literature.  
- LARMix / LAMP: latency-aware routing without pretending mix delay is free.

---

## 16. Success narrative (what we will be able to say when done)

**Allowed marketing when S1–S10 pass:**

> CHRONOS provides profiled anonymous communication with published GPA measurements. In Normal mode on a busy network, it achieves interactive latencies with bounded bandwidth overhead and quantified linking advantage below our published thresholds. In HighAnonymity and Message modes, it prioritizes unlinkability with explicit cost. We do not claim to violate the anonymity trilemma; we claim state-of-the-art operation *on* its frontier under a clear threat model.

**Forbidden until evidence exists:**

- “Unbreakable anonymity at Tor speeds with no overhead.”  
- “Solves the anonymity trilemma.”  
- “GPA-proof” without δ̂ numbers.

---

## 17. Immediate next 14 days (execution checklist)

- [ ] Land threat model + claims matrix + README tone-down.  
- [ ] Extend `anonymity_metrics` reports into `docs/frontier/2026-07-baseline.md`.  
- [ ] Scaffold `tools/chronos-sim` multi-hop GPA.  
- [ ] Define numeric contracts for Fast/Normal/HighAnon in `mix_policy`.  
- [ ] Wire cover emission on real `chronosd` flush path (not sim-only).  
- [ ] Add CI job for mix-sweep + leak-audit.  
- [ ] Start PIR-default design note for directory reads.  
- [ ] Freeze RTE7 test vectors for audit prep.

---

## 18. Document maintenance

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-07-08 | Initial full plan: definitions of success, pillars, phases, backlog, kill criteria |

**Owner:** CHRONOS maintainers  
**Review cadence:** every Gate (G0–G6) and after any public anonymity claim  

---

## 19. Bottom line

**Solving the trilemma “truly” means:**

1. Accept the math.  
2. Define success as **frontier dominance under explicit models**.  
3. Measure δ as hard as we measure latency.  
4. Spend λ and β *deliberately* via adaptive mixing and honest profiles.  
5. Use coding for loss latency, not as fake anonymity.  
6. Use PIR/async modes to escape pure-mix constraints where UX allows.  
7. Make the dataplane fast enough that theory, not syscalls, sets λ.  
8. Prove, audit, and publish — or do not claim.

This document is the plan. The next artifact that matters is **`docs/frontier/` data** that shows CHRONOS moving on the Pareto surface — not another slogan.
