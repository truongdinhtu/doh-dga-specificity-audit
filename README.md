# Artifact: High Malware Recall Does Not Ensure Specificity: Auditing Client-Associated Shortcut Risk in Flow-Based DGA-over-DoH Detection

Reviewer-access artifact for the IEEE Access submission. Every count, rate and figure in
the manuscript is produced by a script in this package from a file in this package,
except where "Not included" below says otherwise.

## Contents

| Path | What it is |
|---|---|
| `paper/Figures/` | The exact figure files the manuscript includes (outputs of the figure scripts below) |
| `machine_learning/*.py` | All experiment, audit and figure scripts (see table below) |
| `machine_learning/results/*.json`, `*.csv` | Every result the manuscript quotes, including per-flow out-of-sample predictions for Probe 2b |
| `data/csv/generated/s2_mdoh.csv` | Stage 2 generated flows (browser benign, CLI benign, simulated DGA) with session, client, resolver, format |
| `data/csv/generated/s3_dga.csv` | Generated DGA flows with family labels (Probe 2 label substitution) |
| `data/csv/generated/s1_doh.csv.gz` | Stage 1 DoH-vs-HTTPS flows (gzip; outside the central audit) |
| `data/csv_from_pcap/malicious/HKD_tranalyzer/` | Sandbox-malware flows re-extracted with Tranalyzer2 under both byte layers, with t2 logs and headers |
| `data/csv_from_pcap/benign/browser_verification/` | Eight retained browser captures (independent runs, not the training captures), their Tranalyzer2 output under both byte layers, exporter logs, and `browser_provenance_predictions_manifest.csv` (all 1,521 port-443 flows with dst_ip, `is_doh` selection flag, `dns_confirmed` dissector flag and both models' predictions; the 200 resolver-address flows are those with `is_doh=True`, of which 96 have `dns_confirmed=True`; of the other 104, 58 have `decrypted_http2_no_dns=True` and 46 are handshake-only; no application-data record in any selected connection is undecrypted) |
| `data/pcap/malicious_generated_zloader/` | The 32 retained captures of DGA training sessions (all Zloader; the only training-session captures that survive) |
| `data/csv_from_pcap/os_doh_client/` | Probe 5: the three pktmon captures (`.pcapng`), block schedules (`blocks_*.json`), Tranalyzer2 output, the 478 labelled flows with `label_contaminated` flag, and `os_doh_client_predictions_manifest.csv` (one row per flow: session, block, resolver, flowInd, label, family, Model-B/Model-T score and prediction, exclusion reason, model hash) from which Table 12 is regenerated |
| `tranalyzer/` | Containerfile pinning Tranalyzer2 with `PACKETLENGTH`, `FDURLIMIT=180`, `FLOW_TIMEOUT=65`, and the export scripts |
| `generate_traffic/` | Traffic-generation scripts for browsers, CLI clients and the Windows OS-DoH experiment (domain lists included) |
| `requirements-lock.txt`, `PYTHON_VERSION.txt` | `pip freeze` and interpreter version of the environment that produced the results |
| `verify_manuscript_numbers.py` | One command that re-reads the results files and the Probe 5 manifest and checks the manuscript numbers |
| `REPRODUCTION_LOG.md`, `reproduction_logs/` | Clean re-run of the central results from a fresh environment: commands, timings, stdout, comparison outcome |
| `MANIFEST.sha256` | SHA-256 of every file |

## Not included, and why

* Captures of the other 96 DGA training sessions, the 32 benign CLI sessions and the 28 browser sessions: not retained. Their extracted flows are in `s2_mdoh.csv`.
* Sandbox malware PCAPs. These belong to the public collection of Mitsuhashi et al. (IEEE CCNC 2023) and are obtained from that source; only our re-extracted flow features are redistributed here.
* Browser PCAPs matching the training rows. These were not retained. Eight browser PCAPs that share training-session names ARE included; `browser_pcap_verification.py` shows they are separate shorter runs (no row matches), and they are used as a provenance-complete browser sample (Sec. VI-E table).

## Quick verification (no model training)

```bash
python3.11 -m venv .venv && . .venv/bin/activate
pip install -r requirements-lock.txt
python verify_manuscript_numbers.py        # expects "46/46 checks passed"
sha256sum -c MANIFEST.sha256               # (shasum -a 256 -c on macOS)
```

## Regenerating results and figures

Scripts read `ROOT` from a constant near the top; set it to the artifact root.

| Manuscript item | Script | Output |
|---|---|---|
| Tables 4–6, Fig. 2 (SHAP), Fig. 3, Fig. 4 | `ieee_access_experiments.py` | `results/ieee_results.json` |
| Grouped CV, bootstrap CIs, Fig. 1 | `ieee_access_revision.py` | `results/ieee_results_revision.json` |
| Nested CV, Probe 1b, factorial cells | `ieee_access_round3.py` | `results/ieee_results_round3.json` |
| Byte-volume sensitivity headline and hardening sweep (Tables 19–20) | `ieee_access_round4.py` | `results/ieee_results_round4.json` |
| Probe 2b identical splits, Table 19 rows, same-flow byte-layer 22.59% | `ieee_access_round6.py` | `results/ieee_results_round6.json` |
| Probe 2b common set (Table 10) and per-flow predictions | `ieee_access_probe2b_common.py` | `results/ieee_results_probe2b_common.json`, `results/probe2b_out_of_sample_predictions.csv` |
| **Probe 2b audit (Table 9)**: classes_ check, train/inner/test AUC, orientation by inner validation, session-bootstrap CIs, fold×cell cross-tab | `ieee_access_probe2b_audit.py` | `results/ieee_results_probe2b_audit.json`, `results/probe2b_audit_by_fold_cell.csv` |
| Sandbox re-extraction under both byte layers (Table 13) | `ieee_access_phaseB.py` | `results/ieee_results_phaseB.json` |
| Probe 5 (Tables 12, 14; label purity; E38 exploratory models) | `ieee_access_os_doh_client.py`, `ieee_access_label_purity.py` | `results/ieee_results_os_doh_client.json`, `results/ieee_results_label_purity.json` |
| Cross-configuration table pooled-BA column | `ieee_access_table13_pooledba.py` | `results/ieee_results_table13_pooledba.json` |
| Browser provenance table (Sec. VI-E) | `ieee_access_browser_provenance.py` | `results/ieee_results_browser_provenance.json` |
| Section IV-C row matching of browser PCAPs | `browser_pcap_verification.py` | `results/browser_pcap_verification.json` |
| Sec. VI-E protocol-level DoH confirmation (needs `tshark`; captures embed TLS secrets) | `browser_doh_protocol_check.py` | `results/browser_doh_protocol_check.json`; adds `dns_confirmed` to the browser manifest |
| Fig. 5 | `ieee_access_fig_factorial_final.py` | `paper/Figures/fig_factorial.pdf` |
| Fig. 6 | `ieee_access_fig_pipeline.py` | `paper/Figures/fig_pipeline.pdf` |
| Fig. 7 (Appendix) | `ieee_access_fig_sensitivity.py` | `paper/Figures/fig_evasion.pdf` |
| Figs. 3–4 with Probe 5 sources | `ieee_access_figs_probe5.py` | `fig_confound.pdf`, `fig_feature_dist.pdf` |

Operating threshold: every binary decision uses the classifier's default 0.5
(`model.predict`); no threshold is tuned anywhere.

Gaussian padding draws: the headline 155 B/pkt run uses generator seed 99; the sweep of
Table 20 uses seed = target for each row (so its 155 row uses seed 155). See
`ieee_access_round4.py`, functions `pad()` and the `adaptive` loop.

## Re-extracting flows from PCAP

```bash
podman build -t t2 -f tranalyzer/Containerfile.slim tranalyzer/
bash tranalyzer/sources/export_L3_L7.sh <capture.pcapng> <outdir>   # both byte layers
python machine_learning/t2_aggregate.py <outdir>                     # bidirectional aggregation
```
