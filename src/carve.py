#!/usr/bin/env python3
"""
dex_carve.py
Carves the hidden payload described by `dex_hollow_check.py --json`.

Usage:
  dex_hollow_check.py classes.dex --json | dex_carve.py -o out/
  dex_carve.py report.json -o out/

stdout : the path of every carved file, one per line (pipe-friendly)
stderr : colored log
"""
import sys, os, json, zlib, hashlib, argparse


# =============================================================================
# 1. ARGUMENTS
# =============================================================================
ap = argparse.ArgumentParser(description='Carve the payload found by dex_hollow_check.py.')
ap.add_argument('report', nargs='?', default='-',
                help="JSON report from dex_hollow_check.py ('-' = stdin, the default)")
ap.add_argument('-o', '--outdir', default='.', help='output directory (default: current dir)')
ap.add_argument('--only-dex', action='store_true',
                help='print only carved .dex paths on stdout (handy before xargs/jadx)')
ap.add_argument('--no-extract', action='store_true',
                help='write the ZIP but do not unpack its entries')
args = ap.parse_args()


# =============================================================================
# 2. COLOR HELPERS (log goes to stderr, so stdout stays clean)
# =============================================================================
USE_COLOR = sys.stderr.isatty() and 'NO_COLOR' not in os.environ
if USE_COLOR and os.name == 'nt':
    os.system('')

def _c(code):
    return (lambda s: f'\033[{code}m{s}\033[0m') if USE_COLOR else (lambda s: str(s))

RED, GREEN, YELLOW, CYAN, BOLD = _c('31'), _c('32'), _c('33'), _c('36'), _c('1')

def log(s=''): print(s, file=sys.stderr)
def die(msg):  log(RED(f'[x] {msg}')); sys.exit(1)


# =============================================================================
# 3. LOAD THE REPORT AND THE SOURCE FILE
# =============================================================================
try:
    rep = json.load(sys.stdin if args.report == '-' else open(args.report))
except (OSError, json.JSONDecodeError) as e:
    die(f'cannot read report: {e}')

src = rep['file']
try:
    with open(src, 'rb') as f:
        d = f.read()
except OSError as e:
    die(f'{src}: {e}')

# Offsets in the report only make sense for the exact bytes that were analyzed.
if hashlib.sha256(d).hexdigest() != rep['sha256']:
    die(f'{src} changed since it was analyzed (sha256 mismatch). Re-run dex_hollow_check.py')

p = rep.get('payload')
if not p:
    log(YELLOW(f'[-] nothing to carve (verdict: {rep["verdict"]})'))
    sys.exit(0)

os.makedirs(args.outdir, exist_ok=True)
base = os.path.splitext(os.path.basename(src))[0]


# =============================================================================
# 4. OUTPUT HELPERS
# =============================================================================
def emit(name, data):
    """Writes 'data' to outdir/name, logs it, and prints the path on stdout."""
    out = os.path.join(args.outdir, name)
    with open(out, 'wb') as f:
        f.write(data)
    is_dex = data[:4] == b'dex\n'
    log(f'  {GREEN("✔")} {BOLD(out)}  {len(data):,} B' + (f'  {CYAN("DEX")}' if is_dex else ''))
    if is_dex or not args.only_dex:
        print(out, flush=True)

def safe(name):
    """Flattens a ZIP entry name into a safe file name (blocks ../ path traversal)."""
    name = name.replace('\\', '/').split('/')[-1] or 'entry'
    return ''.join(c if c.isalnum() or c in '._-' else '_' for c in name)


# =============================================================================
# 5. CARVE, BY PAYLOAD TYPE
# =============================================================================
log(BOLD(CYAN(f'=== CARVING {p["type"].upper()} from {src} ===')))

# --- Raw DEX files back to back ----------------------------------------------
if p['type'] == 'dex':
    for i, x in enumerate(p['dexes']):
        emit(f'{base}_hollow_{i}.dex', d[x['offset']:x['offset'] + x['size']])

# --- Appended ZIP -------------------------------------------------------------
elif p['type'] == 'zip':
    # [start:end] stops right after the EOCD, so the trailer is left out.
    emit(f'{base}_payload.zip', d[p['start']:p['end']])

    if not args.no_extract:
        # Entries are extracted straight from the offsets in the report
        # (no zipfile module), which also works on ZIPs packers have
        # slightly broken to stop normal unzip tools.
        seen = set()
        for e in p['entries']:
            if e['name'].endswith('/'):                       # directory entry
                continue
            if e['flags'] & 1:
                log(YELLOW(f'  ! {e["name"]}: encrypted entry, skipped'))
                continue

            raw = d[e['data_off']:e['data_off'] + e['csize']]
            if e['method'] == 0:                              # stored
                data = raw
            elif e['method'] == 8:                            # deflate (raw stream)
                try:
                    data = zlib.decompress(raw, -15)
                except zlib.error as ex:
                    log(RED(f'  ! {e["name"]}: inflate failed ({ex}), skipped'))
                    continue
            else:
                log(YELLOW(f'  ! {e["name"]}: unsupported method {e["method"]}, skipped'))
                continue

            if zlib.crc32(data) & 0xffffffff != e['crc32']:
                log(YELLOW(f'  ! {e["name"]}: CRC mismatch (kept anyway)'))

            # Unique, safe output name
            name = f'{base}_{safe(e["name"])}'
            stem, ext, k = *os.path.splitext(name), 1
            while name in seen:
                name, k = f'{stem}_{k}{ext}', k + 1
            seen.add(name)
            emit(name, data)

# --- Unknown or encrypted blob ------------------------------------------------
else:
    emit(f'{base}_payload.bin', d[p['start']:p['end']])
    log(YELLOW(f'  entropy {p.get("entropy", "?")} bits/byte. Find the decoder in the stub / native libs'))

# Remind the user what the trailer was, if the analyzer decoded one.
t = p.get('trailer')
if t and t.get('meaning'):
    log(CYAN(f'  trailer at {t["offset"]:#x} = {t["meaning"]} (left out of the carved files)'))
