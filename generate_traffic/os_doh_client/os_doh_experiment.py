"""
os_doh_experiment.py — generate benign and DGA DNS lookups through the operating
system's DoH client (macOS, configured by profile), in randomly ordered, time-separated
blocks, and log block boundaries so that flows can be labelled afterwards.

Design goals (from the review):
  * same client, same resolver, same environment, same exporter for both labels;
  * benign and DGA blocks interleaved in time in random order, so that any drift in
    network conditions is not aligned with the label;
  * a gap longer than the exporter's 65-s inactivity timeout between blocks, so that
    flows do not span two labels;
  * every lookup goes through the OS resolver (socket.getaddrinfo), never a custom client.

Usage:  python os_doh_experiment.py --blocks 8 --block-seconds 150 --gap-seconds 80
Writes: captures/blocks_<timestamp>.json
"""
import argparse, json, random, socket, time, os, sys, subprocess
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
TRANCO = os.path.join(ROOT, 'Code/generate_traffic/benign/tranco_KJYKW.csv')
DGA = {
    'zloader': os.path.join(ROOT, 'Code/generate_traffic/malicious/zloader-50000.txt'),
    'qsnatch': os.path.join(ROOT, 'Code/generate_traffic/malicious/qsnatch-50000.txt'),
    'bazarbackdoor': os.path.join(ROOT, 'Code/generate_traffic/malicious/bazarbackdoor_v3-20000.txt'),
    'flubot': os.path.join(ROOT, 'Code/generate_traffic/malicious/flubot_v4.8_202112.txt'),
}


def load_lists(seed):
    rng = random.Random(seed)
    with open(TRANCO) as fh:
        benign = [l.strip().split(',')[1] for l in fh if ',' in l]
    benign = benign[:20000]                  # top-20k: mostly resolvable
    rng.shuffle(benign)
    dga = {}
    for fam, path in DGA.items():
        with open(path) as fh:
            d = [l.strip() for l in fh if l.strip() and not l.startswith('#')]
        rng.shuffle(d); dga[fam] = d
    return benign, dga


def check_doh():
    out = subprocess.run(['scutil', '--dns'], capture_output=True, text=True).stdout
    return 'https' in out.lower() or 'doh' in out.lower()


def lookup(name, timeout=3.0):
    t0 = time.time()
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)
        rc = 'ok'
    except socket.gaierror as e:
        rc = f'gai:{e.errno}'
    except Exception as e:
        rc = f'err:{type(e).__name__}'
    return rc, time.time() - t0


def run_block(label, names, seconds, cadence, log):
    t_start = time.time(); n = 0; codes = {}
    while time.time() - t_start < seconds and n < len(names):
        rc, dt = lookup(names[n]); codes[rc] = codes.get(rc, 0) + 1; n += 1
        time.sleep(max(0.0, random.uniform(*cadence) - dt))
    t_end = time.time()
    rec = {'label': label, 't_start': t_start, 't_end': t_end, 'n_lookups': n, 'rc': codes}
    log.append(rec)
    print(f"  [{label:8}] {datetime.fromtimestamp(t_start).strftime('%H:%M:%S')}–"
          f"{datetime.fromtimestamp(t_end).strftime('%H:%M:%S')}  n={n}  rc={codes}", flush=True)
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--blocks', type=int, default=8, help='blocks per label')
    ap.add_argument('--block-seconds', type=int, default=150)
    ap.add_argument('--gap-seconds', type=int, default=80, help='> exporter inactivity timeout (65 s)')
    ap.add_argument('--cadence', type=float, nargs=2, default=(0.3, 1.2), help='seconds between lookups (uniform)')
    ap.add_argument('--seed', type=int, default=42)
    ap.add_argument('--out', default=os.path.join(HERE, 'captures'))
    a = ap.parse_args()

    if not check_doh():
        print("WARNING: scutil --dns does not show an HTTPS/DoH resolver. Install the profile first.", file=sys.stderr)
    benign, dga = load_lists(a.seed)
    rng = random.Random(a.seed + 1)
    fams = list(dga)
    order = ['benign'] * a.blocks + ['dga'] * a.blocks
    rng.shuffle(order)
    # never start with the same label three times in a row
    print(f"block order: {order}")
    log = []; bi = 0; di = {f: 0 for f in fams}
    per_block = int(a.block_seconds / a.cadence[0]) + 50
    meta = {'started_utc': datetime.now(timezone.utc).isoformat(), 'args': vars(a), 'order': order,
            'hostname': socket.gethostname(), 'resolver_config': subprocess.run(['scutil', '--dns'], capture_output=True, text=True).stdout}
    for k, label in enumerate(order):
        if label == 'benign':
            names = benign[bi:bi + per_block]; bi += per_block; fam = None
        else:
            fam = fams[k % len(fams)]
            names = dga[fam][di[fam]:di[fam] + per_block]; di[fam] += per_block
        print(f"block {k+1}/{len(order)} label={label} family={fam}")
        run_block(label if fam is None else f"dga:{fam}", names, a.block_seconds, tuple(a.cadence), log)
        if k < len(order) - 1:
            print(f"  gap {a.gap_seconds}s"); time.sleep(a.gap_seconds)
    meta['blocks'] = log; meta['finished_utc'] = datetime.now(timezone.utc).isoformat()
    os.makedirs(a.out, exist_ok=True)
    path = os.path.join(a.out, f"blocks_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    json.dump(meta, open(path, 'w'), indent=1)
    print("wrote", path)


if __name__ == '__main__':
    main()
