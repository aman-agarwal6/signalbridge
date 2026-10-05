# Blind evaluation

The published detection evaluation used scenarios written by the rules' own author, so it is
regression evidence, not accuracy. A blind round fixes that as far as a public project can: an
external author writes scenarios and labels without seeing the rules, and the frozen rules run
on them once.

**What "blind" means here.** It is **author-attested**: the author signs a statement in the
file that they read only [`AUTHOR-GUIDE.md`](AUTHOR-GUIDE.md) and [`template.yml`](template.yml).
The repository is public, so this can't be enforced. Results are one external author's
scenarios, never an independent accuracy figure.

## Protocol

1. **Freeze, before the author starts.**

   ```bash
   python -m detections.blind.blind freeze ROUND
   ```

   This records the git commit and the SHA-256 of every file that decides a verdict:
   - the official evaluator's frozen files (engine, contract, worker, ingestion, models and so on);
   - the event rebuild and Sigma code, and the Sigma rules;
   - `blind.py` itself.

   Commit and push `rounds/ROUND/freeze.json`, so a public timestamp shows the rules were fixed
   before any scenario existed.
2. **Hand over** only `AUTHOR-GUIDE.md` and `template.yml`. Answer format questions; never
   discuss the rules.
3. **Check the format** of what comes back:

   ```bash
   python -m detections.blind.blind check scenarios.yml
   ```

   It never runs the detector, so its messages can't leak results. Send back format errors only.
4. **Seal on receipt**, before anything else:

   ```bash
   python -m detections.blind.blind seal ROUND scenarios.yml
   ```

   This copies the file into the round and records its SHA-256, the author's chosen credit and
   the attestation.
5. **Score once:**

   ```bash
   python -m detections.blind.blind score ROUND
   ```

   Scoring refuses if any frozen file or the sealed file changed. It rebuilds each scenario as
   contract events, scored by:
   - `bridge.engine.detections()`, which reproduced the full evaluator in 48 of 48 frozen
     scenarios;
   - the compiled Sigma rules.

   It writes `rounds/ROUND/result.json` with precision, recall and false-positive rate. These use
   the same `metrics` function as the official evaluator: inconclusive scenarios are reported but
   excluded from the ratios.
6. **Publish everything**:
   - the scenarios, labels and rationales;
   - every miss and false alert;
   - the freeze and seal records.

   Don't change a rule because of a blind result before publishing. A later fix needs a new
   round, frozen openly.

## Privacy

Synthetic data only. The checker rejects email and IP addresses, and every field outside the
documented ones. The author's name is published only if they wrote it as their credit; otherwise
results say "an external author".

## Files

- [`AUTHOR-GUIDE.md`](AUTHOR-GUIDE.md): the only document the author reads.
- [`template.yml`](template.yml): the file they fill in.
- [`blind.py`](blind.py): freeze, check, seal and score.
- [`test_blind.py`](test_blind.py): tests on a synthetic fixture, run in CI without any author
  file. One test checks that this scoring reproduces the published evaluation's metrics.
- `rounds/`: one folder per round. Created by `freeze`; empty until then.
