# Reviewed model improvement

PG-V2-007 adds resource-specific batch retraining to the native v2 model.
It does not learn automatically from incoming packets or its own predictions.
The local operator reviews examples and explicitly activates a candidate only
after comparison with the current model and rule baseline.

## Review data

Sign in as the equipment owner and inspect detailed readings. Prepare a JSON
manifest under ignored `var/v2/` containing **only** resource/sequence references
and human-reviewed labels. Do not export sensor values or keys.

The manifest has exactly these properties:

- `schema_version`: integer `1`.
- `resource_id`: the owned equipment's resource reference.
- `training_sequences`: at least 32 distinct positive sequence numbers, each
  explicitly reviewed as normal. At least 16 different feature combinations.
- `validation`: objects with exactly `sequence` and `label`, where label is
  `normal` or `anomaly`. At least 20 examples of each label.

At most 4096 reviewed records total. Training and validation sequence numbers
must not overlap. Validation feature values must not exactly match training
examples from either the candidate or incumbent. Examples must belong to the
same resource and remain within the existing seven-day retention. Missing,
expired, corrupted or unowned records reject the operation.

Review labels are a trusted human input. Incorrect labels or nearly identical
observations split across sets can bias the result. Use genuinely separate
observation periods and independent new data for final evaluation.

## Evaluate, activate and roll back

From repository root in PowerShell, set `$resource` to the equipment reference:

```powershell
uv run --locked python infra/scripts/v2/retrain.py --owner owner --resource $resource --review var/v2/review.json
```

The command prints counts, model versions, confusion matrices, precision, recall,
F1 and false-positive rate. It prints no raw readings or keys. Evaluation alone
does not persist a candidate. `--config` selects a non-default local v2 config.

The candidate trains a fresh forest on the original 512 synthetic normal samples
plus reviewed normal records. Isolation Forest is a batch estimator here, not an
online learner. Fixed seed and parameters preserve reproducibility.

Activation requires strictly improved F1 and nondecreasing precision/recall with
nonincreasing false-positive rate on the reviewed validation set. The candidate
must also avoid these regressions on the original fixed synthetic holdout.
The rule baseline comparison is informational, not a claim that ML is superior.

```powershell
uv run --locked python infra/scripts/v2/retrain.py --owner owner --resource $resource --review var/v2/review.json --activate
# Stop/start your local stack to load the approved version:
./infra/scripts/v2/Stop.ps1
./infra/scripts/v2/Start.ps1 -Production
```

Non-improving activation exits 2 without replacing the model. Invalid operations
exit 1 with a sanitized error. Success exits 0. A per-resource writer lock rejects
concurrent updates, and atomic encrypted replacement protects interrupted writes.
A leftover `.lock` after an operator process crashes requires confirming that
process has stopped before manually removing that specific lock.

To return to the previous model (or the original model after the first update):

```powershell
uv run --locked python infra/scripts/v2/retrain.py --owner owner --resource $resource --rollback
./infra/scripts/v2/Stop.ps1
./infra/scripts/v2/Start.ps1 -Production
```

Restart applies activation/rollback. Running workers keep their loaded model
until restart or recipe expiry. Other resources retain their own models.

## Persistence and privacy

Recipes live at `var/v2/models/<resource_id>.enc`, inside the existing protected,
ignored runtime root. Active and previous training recipes use the existing
AES-GCM raw-data key with fresh nonces and resource-bound authenticated context.
Raw training values never enter plaintext files, reports, Git or the blockchain.
No executable estimator object is loaded. JSON recipes reproduce the estimator
using the exact recorded scikit-learn version; mismatch/corruption fails loading
with a safe error rather than silently running an unverified recipe.

Recipes expire no later than their oldest reviewed training sample's seven-day
deadline. On model use/startup, expired recipe slots are cleared and inference
returns to the original model. The model version in each encrypted insight
identifies the model that actually classified it. Five-field serialization,
recipient encryption and fresh permission checks still apply to every release.

## Limits

The synthetic regression set is small. Passing it cannot guarantee improvement
in the field. Repeatedly tuning against the same validation set causes selection
bias. Owner review and a new independent final test remain necessary. This local
CLI does not add a browser review interface, background scheduler or cross-owner
training. Existing retained historical results describe the original model.

Upstream references: [Isolation Forest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)
and [model persistence](https://scikit-learn.org/stable/model_persistence.html).
