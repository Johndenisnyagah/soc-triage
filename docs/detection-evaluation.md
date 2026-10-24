# Detection evaluation

Does the engine detect what it claims to, how noisy is it, and is
`MAX_COOCCURRING_KEYS = 12` — which `CLAUDE.md` calls "an unvalidated guess" — a
sensible value? This page answers those three questions against a labelled corpus,
and says plainly where the answers stop.

## Method

`backend/eval/corpus.py` describes one busy morning: 16 scenarios, 10 malicious and 6
benign, all inside the same two hours, so that unrelated activity overlaps in time and
shares ambient keys such as `user:root` and an office NAT address. That overlap is the
condition correlation exists to handle; isolated scenarios would never exercise it.

Every scenario states its ground truth in code before anything runs: which rule should
fire against which entity, or that the activity should stay silent. Two labels are
deliberately unflattering: a low-and-slow brute force is labelled with the detection it
*deserves*, and a user who forgot their password is labelled benign.

`backend/scripts/evaluate_detection.py` uploads the rendered logs
([`eval/corpus/auth.log`](../backend/eval/corpus/auth.log),
[`eval/corpus/cloudtrail.json`](../backend/eval/corpus/cloudtrail.json)) through the
real ingest endpoint, reads the persisted events back (decision 13), runs the rules,
correlates at each value of `MAX_COOCCURRING_KEYS`, and scores two levels:

- **Findings.** A finding is a *hit* when its rule matches an expectation, the expected
  anchor key is in its evidence, and the evidence contains that scenario's own events.
  Every finding is classified once: a detection, a *false positive* (it touches benign
  activity and matches no expectation), or an extra rule firing on malicious activity.
- **Incidents.** A detected malicious scenario is *isolated* when its findings sit in one
  incident containing nothing else, *split* when they spread over several, and *merged*
  when its incident also holds another scenario's activity.

`tests/test_detection_evaluation.py` regenerates everything below and fails if the
committed tables or corpus drift, so these numbers cannot go stale silently.

## Results

<!-- results:start -->
Corpus: 16 scenarios (10 malicious, 6 benign), 143 sshd lines and 13 CloudTrail records, 14 September 2026 09:30–11:30 UTC.

### At the shipped default (`MAX_COOCCURRING_KEYS = 12`)

| Measure | Result |
|---|---|
| Expected detections that fired | **13 / 14** |
| Malicious scenarios detected | **9 / 10** |
| Benign scenarios left silent | **2 / 6** |
| False-positive findings | **6** of 20 findings |
| Detected malicious scenarios in a clean incident of their own | **3 / 9** |
| Findings mixing more than one scenario's activity | **7** |

### Per scenario

| Scenario | Truth | Expected | Outcome | Incident |
|---|---|---|---|---|
| `internet_scanner_1` | malicious | `brute_force_auth` | hit 1/1 | merged with 9 other |
| `internet_scanner_2` | malicious | `brute_force_auth` | hit 1/1 | merged with 9 other |
| `internet_scanner_3` | malicious | `brute_force_auth` | hit 1/1 | merged with 9 other |
| `internet_scanner_4` | malicious | `brute_force_auth` | hit 1/1 | merged with 9 other |
| `password_spray_across_fleet` | malicious | `brute_force_auth` | hit 1/1 | merged with 9 other |
| `distributed_brute_force` | malicious | `brute_force_auth` | hit 1/1 | merged with 9 other |
| `brute_force_then_success` | malicious | `brute_force_auth`, `brute_force_success` | hit 2/2 | isolated |
| `username_enumeration` | malicious | `invalid_user_enumeration` | hit 1/1 | isolated |
| `low_and_slow` † | malicious | `brute_force_auth` | **missed** `brute_force_auth` | — |
| `cloud_account_takeover` | malicious | `brute_force_auth`, `brute_force_success`, `access_key_after_suspicious_auth`, `admin_policy_attached` | hit 4/4 | isolated |
| `forgotten_password` † | benign | silence | **false positive** `access_key_after_suspicious_auth`, `brute_force_auth`, `brute_force_success` | in 1 |
| `monitoring_probe` | benign | silence | silent | — |
| `username_typos` | benign | silence | **false positive** `brute_force_success` | in 1 |
| `routine_key_logins` | benign | silence | silent | — |
| `routine_iam_changes` | benign | silence | **false positive** `access_key_after_suspicious_auth` | in 1 |
| `planned_logging_stop` † | benign | silence | **false positive** `cloud_logging_disabled` | in 1 |

† labelled in advance as a known miss or known false positive:

- `low_and_slow`: BRUTE_FORCE_THRESHOLD is 5 failures in 10 minutes; at one every 3 minutes the window never holds more than 4.
- `forgotten_password`: Six failures then a success is the brute-force-success shape; the rules have no notion of a known user at a known address.
- `planned_logging_stop`: cloud_logging_disabled fires on any StopLogging by design: the logs cannot tell a change ticket from an attacker covering tracks.

### Sweeping `MAX_COOCCURRING_KEYS`

| Value | Incidents | Findings shown | Isolated | Split | Merged | False positives | Mixed findings |
|---|---|---|---|---|---|---|---|
| 2 | 34 | 39 | 2 | 2 | 6 | 12 | 7 |
| 4 | 9 | 21 | 3 | 1 | 6 | 6 | 7 |
| 6 | 5 | 20 | 3 | 0 | 6 | 6 | 7 |
| 8 | 5 | 20 | 3 | 0 | 6 | 6 | 7 |
| **12** (default) | 5 | 20 | 3 | 0 | 6 | 6 | 7 |
| 16 | 4 | 20 | 2 | 0 | 7 | 6 | 7 |
| 32 | 4 | 20 | 2 | 0 | 7 | 6 | 7 |

Isolated, split and merged count detected malicious scenarios (out of 9). A scenario can be both split and merged.
<!-- results:end -->

## What the results show

**Detection does what the rules claim.** Every expected detection fired except one, and
the cloud account takeover is caught end to end — console brute force, the successful
login, the new access key and the administrator policy — in a clean incident of its own.
The single miss is the low-and-slow brute force: one attempt every three minutes never
puts more than four failures inside the ten-minute window. Catching it needs a second,
longer-window rule, and on this corpus that rule would also fire on the monitoring probe
with a stale password. That is the trade-off, not a bug.

**False positives come from three mechanisms, and only one is intended.**

- *A shared address looks like one actor.* The office NAT carries Alice's failed
  logins, other people's successful key logins and an administrator creating an access
  key. Grouped by `ip:192.0.2.10`, that reads as "success after failures" and "access key
  created after suspicious authentication".
- *A host-scoped sequence pairs two different people.* On `web01`, an internet scanner's
  failed root logins followed by Alice's ordinary login are reported as a successful
  login after brute force.
- *Stopping a trail is always flagged.* `cloud_logging_disabled` fires on a planned
  `StopLogging`, by design: the logs cannot tell a change ticket from an attacker
  covering their tracks.

**Merged incidents are caused by the rules, not by the threshold.** At the default, six
of nine detected malicious scenarios share an incident with unrelated activity. The
sweep shows `MAX_COOCCURRING_KEYS` is not why: seven findings mix more than one
scenario's events **at every value tested**. Rules group events by `user:` and `host:` as
well as `ip:`, so a single `user:root` burst contains four unrelated scanners and the
password spray, and the collapse step keeps that widest copy. Correlation then joins on
evidence that is already mixed, and no threshold can separate a merge that happened
inside a rule.

**On this corpus the default sits on a plateau.** Values from 6 to 12 give identical
results. Below that, incidents fragment — 34 incidents and twice the false-positive
findings at 2 — without isolating more attacks. Above it, one more scenario merges. That
is evidence the value does no harm here; it is not evidence that 12 is right at
production scale, where breadth is measured over far more entities.

## What this suggests (not changed here)

Each of these changes a settled decision in `CLAUDE.md`, so they are recorded for
discussion rather than made in the same change that measured them.

- **Require the same actor across a sequence.** `brute_force_success` and
  `access_key_after_suspicious_auth` could require the leading failures and the
  follow-on to share a source address *and* an account or principal, rather than just a
  host or an address. That should remove the cross-actor alerts — the scanner paired
  with Alice's login on `web01`, and the NAT access-key alert — though not Alice's own
  forgotten-password alert, at the cost of missing an attacker who brute-forces one
  account and logs in to another.
- **Keep user- and host-scoped grouping, but stop it absorbing other actors.** It is the
  only reason the distributed brute force is caught (no single address crosses the
  threshold), so removing it trades merges for misses. Preferring the `ip:`-scoped copy
  during collapse when one exists might isolate the scanners without losing the
  distributed case — untested.
- **Add a low-rate, long-window rule** for low-and-slow attempts, paired with an
  allow-list for known service accounts so stale monitoring credentials don't trip it.

None of these effects is measured yet. Each can be, with the same script, before it is
adopted.

## Limitations

- **Synthetic and small.** Sixteen scenarios written to probe known behaviours, with
  denominators of 9, 10 and 14. This is a regression harness and a design probe, not an
  estimate of real-world precision or recall.
- **Labelled before scoring, but the scorer changed.** The scenario labels were fixed
  before the first run and were not changed afterwards. The scorer was corrected twice
  after the first run: once to let one finding satisfy several expectations (a shared
  `user:root` burst is a correlation problem, not four missed detections), and once to
  stop an anchor key alone counting as a hit when another scenario's activity touched
  the same host.
- **One morning, two sources.** `sshd` and CloudTrail only, one two-hour window, one
  office network. Windows events are not covered (build step 7).
- **Next step: public data.** Honeypot `sshd` logs and published CloudTrail attack
  simulations (for example Stratus Red Team) would test the rules against activity
  nobody wrote with the rules in mind.
