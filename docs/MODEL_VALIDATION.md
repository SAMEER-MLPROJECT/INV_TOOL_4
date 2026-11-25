# Model validation

Every number here comes from `sakshya/data/evaluation/results.json`, produced on 2026-11-24 by

```bash
python -m sakshya.evaluation.run --fit --per-kind 6 --training 18 --scales 1,5,10,20,100
```

which took 4 minutes 51 seconds on the build machine. The workbench shows the same file under Evaluation.

## What the evaluation can and cannot show

All cases are synthetic. They come from Sakshya's own generator, which writes an answer key beside each case. The engine never reads the answer keys. Training cases (seeds 500 to 517) are used only to fit calibration scales and phase durations; the 30 held-out cases use other seeds.

Because the generator and the engine were written by the same team, the held-out cases share the structure the engine was designed around. High scores here show that the engine does what it was built to do on data of that shape. They are not evidence of accuracy on real case files, and they do not replace a blind evaluation on real, independently labelled cases. Several results below are perfect for exactly this reason.

## Held-out results (30 cases: 6 each of UPI investment fraud, sextortion, SIM swap, no offence, unknown pattern)

| Area | Metric | Result |
| --- | --- | --- |
| Extraction | Records parsed, worst of 16 generated source types | 100% |
| Extraction | Field-level precision and recall on 17 labelled fixture formats (see below) | 1.000 and 1.000 |
| Same-event links | Precision / recall | 0.999 / 0.990 |
| Presence links | Precision, entity recall, impossibility recall | 1.000, 1.000, 1.000 |
| Identity resolution | Precision / recall / F1 | 1.000 / 0.772 / 0.866 |
| Identity resolution | Decoy pairs (same common name, different people) merged | 0 of 20 |
| Clocks | Offset error, median / worst over 24 skewed files | 5.1 s / 9.9 s |
| Clocks | Wrong time zones detected | 6 of 6 |
| Timeline | Kendall tau against true order, before / after correction | 0.975 / 0.998 |
| Traceability | Findings with a resolvable file, line and hash | 2,233 of 2,233 |
| Determinism | Same input, same digest | yes |
| Custody | Tampered CCTV frames caught / false alarms | 4 of 4 / 0 |
| Money | Accounts reached, precision / recall | 1.000 / 1.000 |
| Money | Cash withdrawn, relative error | 0.55% |
| Roles | First-layer mule, cash-out person, mule variant | 100%, 100%, 100% |
| Classification | Offence type including no offence and unknown | 30 of 30 |
| Speed | Analysis time per case, median / worst | 0.43 s / 2.20 s |

Identity resolution recall is the weakest figure. The engine refuses merges that rest on a single shared device used by several identifiers, on names that disagree, or on fixes too far apart to be one person, and it never merges on a common name alone. That keeps precision at 1.0 and decoy merges at zero, at the cost of leaving some true same-person pairs unmerged. Unmerged pairs are still shown as candidate links for the investigator to confirm.

## Link calibration by type

Held-out links, grouped by reported weight W (log10 likelihood ratio). The share that are true is shown with a 95% Wilson interval. Links are accepted at W of 2.

| Type | W band | Links | True | 95% interval |
| --- | --- | --- | --- | --- |
| Co-presence | below 0 | 6,616 | 0.0% | 0.0 to 0.1% |
| | 0 to 1 | 3,232 | 0.0% | 0.0 to 0.1% |
| | 1 to 2 | 1,287 | 0.0% | 0.0 to 0.3% |
| | 2 to 3 | 2 | 100% | 34 to 100% |
| | 3 to 4 | 42 | 100% | 92 to 100% |
| | 4 and above | 13 | 100% | 77 to 100% |
| Same actor | below 0 | 39 | 0.0% | 0 to 9% |
| | 1 to 2 | 13 | 100% | 77 to 100% |
| | 2 to 3 | 78 | 100% | 95 to 100% |
| | 3 to 4 | 8 | 100% | 68 to 100% |
| Same event | 1 to 2 | 8 | 100% | 68 to 100% |
| | 2 to 3 | 313 | 99.4% | 97.7 to 99.8% |
| | 3 to 4 | 395 | 100% | 99.0 to 100% |
| | 4 and above | 158 | 100% | 97.6 to 100% |

Calibration scales fitted on the training links by minimising log loss:

| Type | Training links | Scale | Brier, scaled / unscaled |
| --- | --- | --- | --- |
| Co-presence | 10,170 | 0.655 | 0.0015 / 0.0024 |
| Same actor | 127 | 2.0 | 0.0001 / 0.0478 |
| Same event | 881 | 2.0 | 0.0016 / 0.0758 |

For same actor and same event the fitted scale sits at the upper bound of the allowed range (0.2 to 2.0). On this synthetic data the weights understate the evidence, and the bound stops calibration from inflating them further. The scale changes only the reported likelihood ratio, posterior and verbal strength; acceptance always uses the uncalibrated weight, so calibration never changes which links are accepted. Types with fewer than 50 labelled links or with only one class are reported as not calibrated and keep their raw weights.

## Forecasting cash-out

For each held-out offence case two cut-offs were taken (10 and 40 minutes after layering began). At each cut-off the whole analysis was re-run with `as_of` set to the cut-off, so no record time-stamped later, and no evidence acquired later, was visible. The test `tests/test_pipeline.py::test_adding_future_evidence_does_not_change_a_past_forecast` checks this directly by adding a later bank row and comparing the forecasts.

| Model | Brier score, cash-out within 60 min | Median absolute error | 80% interval coverage | Phase correct |
| --- | --- | --- | --- | --- |
| Base rate from training cases | 0.229 | n/a | n/a | n/a |
| Median duration baseline | 0.167 | 9.3 min | n/a | n/a |
| Hidden Markov model | 0.133 | 9.2 min | 100% | 100% |
| Semi-Markov phase model (default) | 0.133 | 9.2 min | 100% | 100% |

36 forecasts on 18 cases. Both phase models beat both baselines on Brier score. The hidden Markov and semi-Markov models give almost the same numbers because at these cut-offs little time has passed compared with the typical layering duration, so the semi-Markov model's estimate that the next phase has already happened unseen is small. Interval coverage of 100% means the 80% intervals are wider than they need to be on this data. Phase durations were fitted on six training cases per offence type and the fitted spread sits at its floor (0.3), which reflects the low variance of the generator rather than real offences. In the workbench, a forecast based on fewer than five past cases for a transition is labelled as a rough guide, and its median time is not shown.

## Parser validation

`python -m sakshya.evaluation.parsers` builds 17 fixtures in a temporary folder, parses each and compares the result field by field with hand-written labels: record kind, every identifier with its role, time (within one second), direction, duration, amount, text and selected attributes.

| Format | Records | Precision | Recall | Value checks |
| --- | --- | --- | --- | --- |
| Bank statement CSV (multiline narration, failed, reversal, duplicate, fee) | 5 | 1.000 | 1.000 | 14 of 14 |
| WhatsApp text export (multiline, system line) | 2 | 1.000 | 1.000 | 6 of 6 |
| PCAP (DNS, TLS SNI, three flows) | 5 | 1.000 | 1.000 | 8 of 8 |
| Android SMS database with a deleted row | 4 | 1.000 | 1.000 | 9 of 9 |
| Android call log database | 2 | 1.000 | 1.000 | 6 of 6 |
| iOS Messages database | 2 | 1.000 | 1.000 | 4 of 4 |
| Chromium history | 1 | 1.000 | 1.000 | 1 of 1 |
| Binary property list | 2 | 1.000 | 1.000 | 4 of 4 |
| vCard | 2 | 1.000 | 1.000 | 4 of 4 |
| Telegram export | 2 | 1.000 | 1.000 | 4 of 4 |
| Instagram export (with text needing repair) | 2 | 1.000 | 1.000 | 3 of 3 |
| Social media CSV (multiline, malformed row) | 2 | 1.000 | 1.000 | 4 of 4 |
| HTML table | 2 | 1.000 | 1.000 | 4 of 4 |
| mbox (attachment, authentication results, reply) | 2 | 1.000 | 1.000 | 4 of 4 |
| Cloud sign-in JSON | 2 | 1.000 | 1.000 | 2 of 2 |
| Device report JSON | 1 | 1.000 | 1.000 | 1 of 1 |
| MPEG-4 video (key frame and scene change) | 2 | 1.000 | 1.000 | 3 of 3 |

These fixtures were written together with the parsers. They prove the parsers handle the documented structures and the edge cases listed; they do not prove coverage of every version of every vendor's export. Real exports should be checked with a few hand-labelled records before a new format is relied on.

## Scaling

The same UPI fraud scenario generated at increasing size, analysed end to end including the fragility recomputation. Times were measured with Python memory tracing switched on, which slows execution; without tracing the same 1x case took 3.95 s and the 10x case 6.38 s on the build machine.

| Size | Records | Identifiers | Presence pairs kept by blocking | Seconds | Peak traced memory |
| --- | --- | --- | --- | --- | --- |
| 1x | 3,063 | 1,271 | 1,383 of 2,619 | 8.5 | 11 MB |
| 5x | 5,644 | 5,118 | 7,041 of 10,365 | 13.3 | 28 MB |
| 10x | 8,782 | 9,920 | 13,862 of 19,767 | 19.2 | 50 MB |
| 20x | 15,137 | 19,515 | 27,817 of 38,850 | 32.3 | 93 MB |
| 100x | 66,265 | 96,310 | 139,395 of 192,258 | 135.5 | 456 MB |

Time grows much more slowly than the number of identifiers: 76 times the identifiers took 16 times as long. The decision stayed the same at every size. Same-event blocking compared 1,027 candidate pairs in 33 blocks at every size, because added background records do not share references or amounts with the offence.

## Reproducing

```bash
pip install -r requirements-dev.txt
python -m sakshya.evaluation.run --fit --per-kind 6 --training 18 --scales 1,5,10,20,100
python -m sakshya.evaluation.parsers --dir /tmp/sakshya-fixtures
python -m pytest -q
```

`--fit` rewrites `sakshya/config/calibration.json` and `sakshya/config/predict_params.json`. Their digest is part of every analysis cache key, so cases are re-analysed after a refit and each new result is stored as a new analysis version.
