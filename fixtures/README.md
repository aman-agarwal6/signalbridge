# Synthetic development benchmark

Two app scopes repeat the same eight scenarios, not independent replications. Per app:
12 events, 8 labelled episodes, 7 baseline cases, 5 required suspicious episodes.
The unsafe managed-device suppression retains only the revoked-read case among the
five required scenarios, plus the missing-context benign case (2 cases total).
The revised policy suppresses only benign-known: 6 cases, all 5 required episodes.
Expected case reduction: unsafe 71.43%; revised 14.29%. No analyst-time claim.

Events contain no labels or scenario names. labels.json is loaded only for scoring,
after decisions. The historical timestamp is deliberate; this fixture is replayed
offline, never sent as a current network event. This is not a blind holdout and does
not reproduce the unavailable original starter's fixture pack. Live lab events are
generated from actual SQL observations in integrations/check-apps.mjs.

