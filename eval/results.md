# Eval results

## Labels remapped under the revised rubric

Expiry-only targets (DNS resolves and RDAP registered, ≤ 90 days) mapped to info. `eval/labels.jsonl` was not edited.

- https://github.com/quantopian/zipline `quandl.com`: high → info (days_to_expiry=80)

## Original rubric

### All labels

precision@10 ranks labeled targets only and is capped by the few gold critical/high labels per repo.

| system | precision@10 | flag_precision | flagged_ch | gold_ch_caught | false_alarms | recall | cost_usd |
|---|---|---|---|---|---|---|---|
| baseline (original) | 0.056 | 0.102 | 49 | 5 | 44 | 1.000 | 0.00000000 |
| baseline (revised) | 0.044 | 0.222 | 18 | 4 | 14 | 0.800 | 0.00000000 |
| trustmap | 0.044 | 0.800 | 5 | 4 | 1 | 0.800 | 0.01689450 |

#### Confusion (baseline original, gold \ predicted)
| gold \ pred | critical | high | medium | low | info |
|---|---|---|---|---|---|
| critical | 1 | 0 | 0 | 0 | 0 |
| high | 0 | 4 | 0 | 0 | 0 |
| medium | 1 | 0 | 0 | 0 | 0 |
| low | 4 | 9 | 0 | 0 | 0 |
| info | 0 | 30 | 0 | 99 | 0 |

#### Confusion (baseline revised, gold \ predicted)
| gold \ pred | critical | high | medium | low | info |
|---|---|---|---|---|---|
| critical | 1 | 0 | 0 | 0 | 0 |
| high | 0 | 3 | 0 | 1 | 0 |
| medium | 1 | 0 | 0 | 0 | 0 |
| low | 4 | 9 | 0 | 0 | 0 |
| info | 0 | 0 | 0 | 129 | 0 |

#### Confusion (trustmap, gold \ predicted)
| gold \ pred | critical | high | medium | low | info |
|---|---|---|---|---|---|
| critical | 1 | 0 | 0 | 0 | 0 |
| high | 1 | 2 | 0 | 0 | 1 |
| medium | 1 | 0 | 0 | 0 | 0 |
| low | 0 | 0 | 0 | 3 | 10 |
| info | 0 | 0 | 0 | 85 | 44 |

### Human-labeled only

precision@10 ranks labeled targets only and is capped by the few gold critical/high labels per repo.

| system | precision@10 | flag_precision | flagged_ch | gold_ch_caught | false_alarms | recall |
|---|---|---|---|---|---|---|
| baseline (original) | 0.472 | 0.500 | 10 | 5 | 5 | 1.000 |
| baseline (revised) | 0.472 | 0.571 | 7 | 4 | 3 | 0.800 |
| trustmap | 0.472 | 0.800 | 5 | 4 | 1 | 0.800 |

#### Confusion (baseline original, gold \ predicted)
| gold \ pred | critical | high | medium | low | info |
|---|---|---|---|---|---|
| critical | 1 | 0 | 0 | 0 | 0 |
| high | 0 | 4 | 0 | 0 | 0 |
| medium | 1 | 0 | 0 | 0 | 0 |
| low | 0 | 2 | 0 | 0 | 0 |
| info | 0 | 2 | 0 | 2 | 0 |

#### Confusion (baseline revised, gold \ predicted)
| gold \ pred | critical | high | medium | low | info |
|---|---|---|---|---|---|
| critical | 1 | 0 | 0 | 0 | 0 |
| high | 0 | 3 | 0 | 1 | 0 |
| medium | 1 | 0 | 0 | 0 | 0 |
| low | 0 | 2 | 0 | 0 | 0 |
| info | 0 | 0 | 0 | 4 | 0 |

#### Confusion (trustmap, gold \ predicted)
| gold \ pred | critical | high | medium | low | info |
|---|---|---|---|---|---|
| critical | 1 | 0 | 0 | 0 | 0 |
| high | 1 | 2 | 0 | 0 | 1 |
| medium | 1 | 0 | 0 | 0 | 0 |
| low | 0 | 0 | 0 | 1 | 1 |
| info | 0 | 0 | 0 | 2 | 2 |

## Revised rubric

### All labels

precision@10 ranks labeled targets only and is capped by the few gold critical/high labels per repo.

| system | precision@10 | flag_precision | flagged_ch | gold_ch_caught | false_alarms | recall | cost_usd |
|---|---|---|---|---|---|---|---|
| baseline (original) | 0.044 | 0.082 | 49 | 4 | 45 | 1.000 | 0.00000000 |
| baseline (revised) | 0.044 | 0.222 | 18 | 4 | 14 | 1.000 | 0.00000000 |
| trustmap | 0.044 | 0.800 | 5 | 4 | 1 | 1.000 | 0.01689450 |

#### Confusion (baseline original, gold \ predicted)
| gold \ pred | critical | high | medium | low | info |
|---|---|---|---|---|---|
| critical | 1 | 0 | 0 | 0 | 0 |
| high | 0 | 3 | 0 | 0 | 0 |
| medium | 1 | 0 | 0 | 0 | 0 |
| low | 4 | 9 | 0 | 0 | 0 |
| info | 0 | 31 | 0 | 99 | 0 |

#### Confusion (baseline revised, gold \ predicted)
| gold \ pred | critical | high | medium | low | info |
|---|---|---|---|---|---|
| critical | 1 | 0 | 0 | 0 | 0 |
| high | 0 | 3 | 0 | 0 | 0 |
| medium | 1 | 0 | 0 | 0 | 0 |
| low | 4 | 9 | 0 | 0 | 0 |
| info | 0 | 0 | 0 | 130 | 0 |

#### Confusion (trustmap, gold \ predicted)
| gold \ pred | critical | high | medium | low | info |
|---|---|---|---|---|---|
| critical | 1 | 0 | 0 | 0 | 0 |
| high | 1 | 2 | 0 | 0 | 0 |
| medium | 1 | 0 | 0 | 0 | 0 |
| low | 0 | 0 | 0 | 3 | 10 |
| info | 0 | 0 | 0 | 85 | 45 |

### Human-labeled only

precision@10 ranks labeled targets only and is capped by the few gold critical/high labels per repo.

| system | precision@10 | flag_precision | flagged_ch | gold_ch_caught | false_alarms | recall |
|---|---|---|---|---|---|---|
| baseline (original) | 0.444 | 0.400 | 10 | 4 | 6 | 1.000 |
| baseline (revised) | 0.444 | 0.571 | 7 | 4 | 3 | 1.000 |
| trustmap | 0.444 | 0.800 | 5 | 4 | 1 | 1.000 |

#### Confusion (baseline original, gold \ predicted)
| gold \ pred | critical | high | medium | low | info |
|---|---|---|---|---|---|
| critical | 1 | 0 | 0 | 0 | 0 |
| high | 0 | 3 | 0 | 0 | 0 |
| medium | 1 | 0 | 0 | 0 | 0 |
| low | 0 | 2 | 0 | 0 | 0 |
| info | 0 | 3 | 0 | 2 | 0 |

#### Confusion (baseline revised, gold \ predicted)
| gold \ pred | critical | high | medium | low | info |
|---|---|---|---|---|---|
| critical | 1 | 0 | 0 | 0 | 0 |
| high | 0 | 3 | 0 | 0 | 0 |
| medium | 1 | 0 | 0 | 0 | 0 |
| low | 0 | 2 | 0 | 0 | 0 |
| info | 0 | 0 | 0 | 5 | 0 |

#### Confusion (trustmap, gold \ predicted)
| gold \ pred | critical | high | medium | low | info |
|---|---|---|---|---|---|
| critical | 1 | 0 | 0 | 0 | 0 |
| high | 1 | 2 | 0 | 0 | 0 |
| medium | 1 | 0 | 0 | 0 | 0 |
| low | 0 | 0 | 0 | 1 | 1 |
| info | 0 | 0 | 0 | 2 | 3 |

## Gold critical/high debug (original labels)

### https://github.com/quantopian/zipline `quantopian-orchestration` gold=critical
label_evidence: {"bucket_probe": {"status": "NoSuchBucket", "name": "quantopian-orchestration", "provider": "s3", "http_status": 404}}
trustmap: target=quantopian-orchestration model_severity=critical final_severity=critical floor_reason=(none)
finding_evidence: {"bucket_probe": {"status": "NoSuchBucket", "name": "quantopian-orchestration", "provider": "s3", "http_status": 404}, "wayback": {"status": "unavailable"}}

### https://github.com/quantopian/zipline `quandl.com` gold=high
label_evidence: {"dns": {"status": "resolves", "host": "docs.quandl.com"}, "rdap": {"status": "registered", "domain": "quandl.com", "days_to_expiry": 80}}
trustmap: target=quandl.com model_severity=info final_severity=info floor_reason=(none)
finding_evidence: {"dns": {"status": "resolves", "host": "docs.quandl.com"}, "rdap": {"status": "registered", "domain": "quandl.com", "days_to_expiry": 80}, "cert_history": {"status": "unavailable", "domain": "quandl.com"}, "wayback": {"status": "ok"}}

### https://github.com/lbryio/lbry-desktop `lbry.tech` gold=high
label_evidence: {"dns": {"status": "nxdomain", "host": "forum.lbry.tech"}, "rdap": {"status": "registered", "domain": "lbry.tech", "days_to_expiry": 70}}
trustmap: target=lbry.tech model_severity=low final_severity=high floor_reason=NXDOMAIN in executing position (browser, build) is at least high
finding_evidence: {"dns": {"status": "nxdomain", "host": "forum.lbry.tech"}, "rdap": {"status": "registered", "domain": "lbry.tech", "days_to_expiry": 70}, "cert_history": {"status": "unavailable", "domain": "lbry.tech"}, "wayback": {"status": "unavailable"}}

### https://github.com/debois/elm-mdl `polyfill.io` gold=high
label_evidence: {"dns": {"status": "nxdomain", "host": "cdn.polyfill.io"}, "rdap": {"status": "unknown", "domain": "polyfill.io", "days_to_expiry": null}}
trustmap: target=polyfill.io model_severity=high final_severity=high floor_reason=(none)
finding_evidence: {"dns": {"status": "nxdomain", "host": "cdn.polyfill.io"}, "rdap": {"status": "unknown", "domain": "polyfill.io", "days_to_expiry": null}, "cert_history": {"status": "unavailable", "domain": "polyfill.io"}, "wayback": {"status": "ok"}}

### https://github.com/TryKickoff/kickoff `polyfill.io` gold=high
label_evidence: {"dns": {"status": "nxdomain", "host": "cdn.polyfill.io"}, "rdap": {"status": "unknown", "domain": "polyfill.io", "days_to_expiry": null}}
trustmap: target=polyfill.io model_severity=critical final_severity=critical floor_reason=(none)
finding_evidence: {"dns": {"status": "nxdomain", "host": "cdn.polyfill.io"}, "rdap": {"status": "unknown", "domain": "polyfill.io", "days_to_expiry": null}, "cert_history": {"status": "unavailable", "domain": "polyfill.io"}, "wayback": {"status": "unavailable"}}

## Gold critical/high debug (revised labels)

### https://github.com/quantopian/zipline `quantopian-orchestration` gold=critical
label_evidence: {"bucket_probe": {"status": "NoSuchBucket", "name": "quantopian-orchestration", "provider": "s3", "http_status": 404}}
trustmap: target=quantopian-orchestration model_severity=critical final_severity=critical floor_reason=(none)
finding_evidence: {"bucket_probe": {"status": "NoSuchBucket", "name": "quantopian-orchestration", "provider": "s3", "http_status": 404}, "wayback": {"status": "unavailable"}}

### https://github.com/lbryio/lbry-desktop `lbry.tech` gold=high
label_evidence: {"dns": {"status": "nxdomain", "host": "forum.lbry.tech"}, "rdap": {"status": "registered", "domain": "lbry.tech", "days_to_expiry": 70}}
trustmap: target=lbry.tech model_severity=low final_severity=high floor_reason=NXDOMAIN in executing position (browser, build) is at least high
finding_evidence: {"dns": {"status": "nxdomain", "host": "forum.lbry.tech"}, "rdap": {"status": "registered", "domain": "lbry.tech", "days_to_expiry": 70}, "cert_history": {"status": "unavailable", "domain": "lbry.tech"}, "wayback": {"status": "unavailable"}}

### https://github.com/debois/elm-mdl `polyfill.io` gold=high
label_evidence: {"dns": {"status": "nxdomain", "host": "cdn.polyfill.io"}, "rdap": {"status": "unknown", "domain": "polyfill.io", "days_to_expiry": null}}
trustmap: target=polyfill.io model_severity=high final_severity=high floor_reason=(none)
finding_evidence: {"dns": {"status": "nxdomain", "host": "cdn.polyfill.io"}, "rdap": {"status": "unknown", "domain": "polyfill.io", "days_to_expiry": null}, "cert_history": {"status": "unavailable", "domain": "polyfill.io"}, "wayback": {"status": "ok"}}

### https://github.com/TryKickoff/kickoff `polyfill.io` gold=high
label_evidence: {"dns": {"status": "nxdomain", "host": "cdn.polyfill.io"}, "rdap": {"status": "unknown", "domain": "polyfill.io", "days_to_expiry": null}}
trustmap: target=polyfill.io model_severity=critical final_severity=critical floor_reason=(none)
finding_evidence: {"dns": {"status": "nxdomain", "host": "cdn.polyfill.io"}, "rdap": {"status": "unknown", "domain": "polyfill.io", "days_to_expiry": null}, "cert_history": {"status": "unavailable", "domain": "polyfill.io"}, "wayback": {"status": "unavailable"}}

## Budget skips
- (none)
