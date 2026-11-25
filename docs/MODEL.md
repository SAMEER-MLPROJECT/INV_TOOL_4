# Model

Sakshya runs one pipeline per case. Each stage reads the output of the previous one and nothing is hidden from the investigator: every score is a sum of named terms, and every term names the record it came from.

The pipeline and module map are in [ARCHITECTURE_TRACEABILITY.md](ARCHITECTURE_TRACEABILITY.md). This document gives the arithmetic.

## 1. Intake and custody

Each file listed in `case.yaml` is hashed with SHA-256 before it is parsed and an `intake` entry is written to the case ledger. If the same path later has a different hash an `intake_changed` entry is written and any cached analysis is discarded.

The ledger is a hash chain that starts with a genesis entry. Each entry holds a sequence number, a time, a type, a payload and the hash of the previous entry, and its own hash is

```
hash_i = SHA-256(canonical_json(seq_i, time_i, type_i, payload_i, hash_{i-1}))
```

After every append the new head is signed with Ed25519 and stored as a checkpoint `(scope, seq, head, time, key_id, signature)`. Verification walks the chain and then checks every checkpoint against it. Hash check states and anchoring are described in [FORENSIC_RELIABILITY.md](FORENSIC_RELIABILITY.md).

## 2. Observations and identifiers

Every adapter emits rows with the same columns: time as recorded, time zone, place (latitude, longitude, radius), amount and direction, the identifiers involved and their roles (holder, counterparty, caller, called, device, ATM and so on), the raw text and a pointer to the file and line.

Identifiers are reduced to canonical entities:

| Kind | Canonical form |
| --- | --- |
| phone | E.164, `+91` added to ten digit Indian mobiles, leading zero removed |
| imei | 15 digits; a 14 digit IMEI gets its Luhn check digit |
| imsi | 14 or 15 digits |
| account | `IFSC:number`; numbers without IFSC become `UNKNOWN:number`; masked numbers keep the last four digits |
| upi, email | lower case |
| mac | lower case, colon separated |
| ip, domain | standard form; `www.` removed from domains |

Names are compared after transliterating Devanagari to Latin with schwa deletion, so `रोहित कुमार` and `Rohit Kumar` compare equal. Name agreement is only ever one term in a link; it never merges people on its own.

## 3. Clock correction

Reference sources (bank statements, ATM journals, CDRs, tower dumps) are trusted for time. Every other file is aligned to them.

For a file *f*, events that also appear in reference records (the same transaction reference, the same call, the same SMS alert) give candidate offsets *d_k = t_ref,k - t_f,k*. The offset is chosen by voting: the candidate with the most other candidates within 90 s wins. It is refined with the median of the supporting votes, and its uncertainty is

```
sigma = max(1.4826 * MAD, floor)
```

An anchor whose candidate reference events are more than 30 s apart is ambiguous and is not used. An offset within 150 s of a multiple of 30 minutes is reported as a time zone error only if the file declares no time zone, at least three anchors agree, their spread is at most 120 s and the offset is at least 20 minutes. Each estimate is labelled reference, estimated, weak or unestimated. With anchors spread over at least three days a drift rate is fitted with the Theil and Sen estimator. Files from the same phone export (call log and SMS) share one clock domain and are estimated together. The residual uncertainty is carried into every later time term.

## 4. Link tests

A link states a claim, for example that a phone was near an ATM when cash was withdrawn. Its weight is the base ten logarithm of a likelihood ratio,

```
W = log10 LR = log10 P(evidence | claim) / P(evidence | coincidence)
```

built as a sum of named terms.

**Time term.** For a gap *dt* with expected value *mu* and combined variance *sigma^2* (both clocks plus the event spread), compared with a uniform time in a window *T*:

```
w_time = log10( T * N(dt; mu, sigma^2) )
```

**Place term.** For a distance *d* between two located observations with radii *r_a* and *r_b*, a Rayleigh distance under the claim against a uniform point in a disc of radius *R* under coincidence:

```
sigma^2 = (r_a^2 + r_b^2) / 4
w_place = log10( pi R^2 / (2 pi sigma^2) ) - d^2 / (2 sigma^2 ln 10)
```

*R* is the area the competing phones were actually spread over, not a fixed city radius, so a cell that covers a whole block does not give a strong place term.

**Attribute terms** follow Fellegi and Sunter. For an attribute that agrees with probability *m* under the claim and *u* by chance:

```
w = log10(m / u)              if the attribute agrees
w = log10((1 - m) / (1 - u))  if it disagrees
```

*u* is taken from frequencies inside the case where possible, so a common surname or a popular bank branch counts for little.

**Rarity term** for co-presence. If *N* phones were on the same cells in the same window and *k* of the others are already linked to the case, an entity linked to the case agrees with *m = 0.5* and *u = (k + 1) / (N + 1)*. Busy locations therefore weaken presence links automatically.

**Combining.** Each term belongs to a dependence group: records with a common origin (all records from one bank's core system, one handset, one operator) are one group, whatever file they came from. Terms are summed per group and each group is capped at plus or minus 4, so no single origin can carry a link:

```
W = sum over dependence groups g of clip( sum of terms from g, -4, +4 )
```

A link is accepted (status `inferred`) when *W* is at least 2 and at least two independent groups contribute (for same-event links, two different evidence files). Strong links that rest on one origin stay as candidates with a note. Investigators can confirm or reject any link; rejected links are kept and shown.

**Coincidence rates.** Rates estimated from counts in the case use add-one smoothing, *(k + 1) / (n + 2)*, so a rate is never exactly zero or one.

**Blocking.** Candidate pairs are generated only inside blocks: shared reference or amount for same-event links, a sorted time window and then a distance limit for co-presence, shared KYC attributes for same-actor links. The number of pairs at each stage is recorded with every analysis.

**Prior and posterior.** Co-presence links carry prior odds of *1 / (N - 1)*, one person out of the crowd, so

```
posterior = (prior_odds * LR_c) / (1 + prior_odds * LR_c)
```

where *LR_c* is the calibrated likelihood ratio (section 10).

Link types:

| Type | Claim | Main terms |
| --- | --- | --- |
| same_event | Two records describe one event (debit and credit, UPI reference and SMS alert, ATM journal and statement) | time, amount, reference agreement |
| co_presence | A phone, handset or cloud account was near a cash withdrawal | time, place, rarity |
| impossibility | A phone could not have been at the withdrawal | travel speed above 120 km/h between a fix and the event |
| same_actor | Two identifiers belong to one person | KYC name and address, registered phone, SIM in handset, shared handset, cloud account device, seizure memo, shared network infrastructure, travelling together |
| sequence | One transfer triggered the next | Hawkes trigger probability |

**Sequence links.** Credits and debits on an account are modelled as a self-exciting process with background rate *mu* and kernel *alpha beta e^(-beta t)*, with *alpha = 0.8*. *beta* is fitted by maximum likelihood over a grid of decay times on the case's own statements. The weight of a link from a credit to a later debit is

```
w_trigger = log10( lambda(t) / mu )
```

and only the latest credit in a burst is credited. A new contact (first seen within 14 days) followed by a payment gives a contact to payment link.

## 5. People

Entities are grouped with union and find over accepted same-actor links at *W >= 2*, strongest first. A merge is refused, and the refusal recorded, when:

* an investigator marked the two identifiers as different people;
* the link rests on an identifier that is linked to three or more identifiers of one kind (a shared handset or router), which cannot join people on its own;
* the registered names of the two groups have a similarity below 0.6;
* the two groups have location fixes within 10 minutes of each other that are further apart than travel at 900 km/h, both radii and a 5 km margin allow;
* a shared handset would attach new identifiers to the complainant.

Persons are numbered by their distance from the complainant in the link graph.

## 6. Indicators

Behavioural indicators are computed per entity and weighted from `config/indicators.yaml`:

* money: received from the complainant, passed on within 60 minutes, split across payees, cash withdrawn, a new account, commission kept, funds retained, long history with the payee;
* communication: contact before payment, lure language, threat language;
* telecom: SIM change shortly before debits, OTP on the new SIM, many SIMs on one handset;
* location: present at a withdrawal, cleared by travel time;
* network: beaconing, large outbound volume, shared infrastructure.

## 7. Explain

A crime template (`config/templates/*.yaml`) lists roles, phases, the indicators that support or contradict each role, variants (for example a knowing or unwitting first-layer mule), the observability of each phase in each source and the typical time between phases.

Beam search binds candidate persons or accounts to roles. The score of a hypothesis *H* is

```
S(H) = prior(H)
     + sum over roles of indicator weights of the bound units
     + sum over template relationships of the capped link weights between bound roles
     + sum over missing phases of log10(1 - o)
     + order penalties
```

Relationships (contact before payment, co-presence or impossibility at withdrawals, transfer sequences, shared actor) take the weights of the links between the bound roles, capped per dependence group. To avoid counting the same evidence twice, an indicator that was derived from a link is replaced by that link, and a link whose records were already counted by another indicator is excluded; both lists are shown with each hypothesis.

*o* is the chance that the phase would have been seen given the sources in the case, the parties they cover, and the period they span. A missing phase that the evidence would almost certainly have shown costs a lot; one that the case simply has no source for costs nothing.

"No offence" is the reference with score 0. The decision has five outcomes, set out in [FORENSIC_RELIABILITY.md](FORENSIC_RELIABILITY.md): an offence pattern is reported as supported when *S >= 2* and it leads every other template and the reference by at least 1.

The difference in score between two explanations is a log ten likelihood ratio, so a margin of 5.5 reads as the leading explanation fitting the evidence about 316,000 times better.

## 8. Reach

Transfers are built from statements, with debit and credit legs joined by same-event links. Payments from the complainant to payees first seen within 30 days of the complaint are the origin of the trace.

Each account holds a tainted balance. On every debit the tainted share leaves with the money:

* pro-rata: tainted share of the debit = tainted balance / balance before the debit;
* first in, first out: the oldest money leaves first.

Both rules can be shown at any time *as of*, so the trail can be replayed as it stood at any moment. Cash withdrawals end a path. Reversed transfers are dropped, refunds to the complainant are counted as returned, and fees are kept apart from transfers.

Each statement is reconciled: the opening balance is inferred from the first row, each reported balance is compared with the running balance, gaps of more than 21 days with a balance jump are flagged, and totals of credits, debits and the unexplained remainder are reported. The trace conserves money: what left the complainant equals what is held, withdrawn as cash, or gone outside the evidence.

The freeze list gives, for each account still holding traced money, the verified statement balance, an upper bound on what can be recovered (the smaller of traced money held and the balance), and its basis:

```
expected recoverable = recoverable upper bound * (1 - P(money moves before a freeze lands))
```

The probability is used only for accounts bound to a mule role while the phase model says cash-out is next; the row is then marked "model estimate" and shows a range for the probability 20 points higher or lower. Every other account is marked "heuristic", has no probability, and is ranked by amount and hop.

## 9. Predict

The default model is semi-Markov over the phases of the leading template. The current phase is the latest phase with an observed event up to the cut-off. The time spent in it follows a log-normal duration with median and spread fitted on training cases where at least five exist, otherwise taken from the template and labelled as elicited. The probability that the next phase has already started unseen is

```
P(moved) = F(elapsed) * (1 - o_next) / ( (1 - F(elapsed)) + F(elapsed) * (1 - o_next) )
```

where *F* is the duration distribution and *o_next* the observability of the next phase. The engine reports the chance of the next phase within 15, 30, 60 and 120 minutes, an 80% interval for the time remaining and the chance it happens before a freeze can land (45 minutes by default). A hidden Markov model with fixed stay, advance and skip probabilities is kept for comparison. Every forecast is computed on a strict snapshot: records time-stamped after the cut-off and evidence acquired after it are removed before clock correction, and clock correction is repeated on the snapshot.

## 10. Calibration

For each link type with at least 50 labelled training links of both classes, a logistic model

```
P(true | W) = sigmoid( k * W * ln 10 + b )
```

is fitted by log loss, with *b* replaced by the link's own prior odds where every link has one. *k* is bounded between 0.2 and 2. The calibrated weight *k W* is used for the reported likelihood ratio, posterior and verbal strength. Acceptance uses the uncalibrated weight, so calibration never changes which links are accepted. The verbal scale follows the example bands of the ENFSI guideline for evaluative reporting (2015). Reliability tables with Wilson intervals are in [MODEL_VALIDATION.md](MODEL_VALIDATION.md).

## 11. Decide

Each possible evidence request (a statement for an account the money reached, CDRs for a number with no call records, a tower dump or CCTV for a withdrawal, hosting records for a domain, a statement from an account holder) is scored by

```
value per day = (expected information gain + gap bonus + money bonus) / days to obtain
```

Expected information gain has three outcomes per request: a result that supports the hypothesis, a result that does not, and no result at all (the record does not exist or is refused), with an elicited chance of the last for each request type:

```
EIG = H(prior) - [ sum over results r in {found, not found} of P(r) H(posterior | r) + P(unavailable) H(prior) ]
```

The prior is a tempered posterior over the hypotheses (scores divided by 3) so that the ranking does not collapse when one explanation dominates. The outcome probabilities are elicited, not measured, and each request says so.

Fragility is measured, not estimated: the strongest supporting links (and groups of links that were counted together) are removed one at a time, then in pairs, and the whole analysis from clustering onward is re-run each time. The result lists which removals change the conclusion, which is what a defence would challenge first.

## 12. Determinism

Every stage is deterministic. The result digest covers all analysis output and excludes only timings, the ledger listing, the freshness check and custody timestamps, so the same inputs give the same digest on any machine and with any Python hash seed.
