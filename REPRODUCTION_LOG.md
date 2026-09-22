# Clean re-run of the central results

Date: 2026-09-22. Host: macOS (Darwin 27.0.0, Apple Silicon). Fresh virtual environment
created with `python3.11 -m venv` and `pip install -r requirements-lock.txt`
(Python 3.11.8, lightgbm 4.6.0, scikit-learn 1.9.0, shap 0.46.0, pandas 2.3.3).
Existing `machine_learning/results/*.json` and `*.csv` were copied aside, each script
was run from the artifact's `machine_learning/` directory with the clean interpreter,
and the regenerated files were compared value by value with the copies.

| Script | Manuscript items | Wall time (s) | Result of comparison |
|---|---|---|---|
| `ieee_access_probe2b_common.py` | Table 10; per-flow OOF predictions | 61.71 | 43/43 values identical; OOF prediction CSV byte-identical |
| `ieee_access_probe2b_audit.py` | Table 9; orientation, cross-tab, session-bootstrap CIs | 103.94 | 87/87 values identical; per-fold-cell CSV byte-identical |
| `ieee_access_os_doh_client.py` | Tables 12, 14; Probe 5 manifest | 26.69 | 657/657 values identical |
| `ieee_access_round6.py` | Table 19 (seed 99 run); same-flow byte-layer 22.59 % vs 98.81 % | 147.76 | 167/170 identical; the 3 remaining are NaN vs NaN (per-session BA medians undefined) |
| `ieee_access_round4.py` | Table 20 (seed = target runs); hardening | 54.25 | 96/96 values identical |
| `ieee_access_browser_provenance.py` | Sec. VI-E table (provenance-complete browser DoH check; DoH selection by resolver address) | 9.16 | newly generated in this run; re-run identical |
| `browser_pcap_verification.py` | Section IV-C row-matching report | — | newly generated in this run |
| `browser_doh_protocol_check.py` | Sec. VI-E DNS/handshake split of the 200 flows (tshark 4.6.8) | — | newly generated in this run |

Comparison rule: floats compared with relative and absolute tolerance 1e-6; integers and
strings exact. All LightGBM fits use `random_state=42` and single-threaded-deterministic
histogram construction was not forced; identical results were nevertheless obtained on this
host. On a different CPU architecture small floating-point differences in LightGBM scores
are possible; counts, flags and the manifest columns should still match exactly.

Stdout of every run is in `reproduction_logs/<script>.log`; `/usr/bin/time -p` output in
`reproduction_logs/<script>.time`.

Not re-run here (long-running, not central): `ieee_access_experiments.py`,
`ieee_access_revision.py`, `ieee_access_round3.py`, `ieee_access_phaseB.py`,
`ieee_access_table13_pooledba.py`. Their stored results are what
`verify_manuscript_numbers.py` checks.

## Tranalyzer2 re-extraction performed in this run

The eight browser captures in `data/csv_from_pcap/benign/browser_verification/data/` were
extracted with the `tranalyzer-doh` container built from `tranalyzer/Containerfile.slim`:

```
podman run --rm -v $PWD/data:/data -v $PWD/result:/result -v $PWD/../../../../tranalyzer/sources:/sources localhost/tranalyzer-doh bash /sources/export_all.sh   # network-layer bytes
podman run --rm -v $PWD/data:/data -v $PWD/result:/result -v $PWD/../../../../tranalyzer/sources:/sources localhost/tranalyzer-doh bash /sources/export_L7.sh    # TCP-payload bytes
```

Exporter stdout, headers and the rebuild log are in `.../browser_verification/result/`.
