#!/usr/bin/env python3
"""
restore_dpt_v1.0.py
Puts the method bodies stored in the dpt-shell code blob (assets/OoooooOooo)
back into the hollowed DEX files carved by carve_v1.0.py.

This is restore_v1.0.py reduced to what stock dpt-shell does: it only undoes
the hollowing. It does not look for or remove the junk fill-array-data tail
that this sample carries on top of dpt-shell, so the output is identical to
`restore_v1.0.py --keep-junk`.

Blob layout (version 2):
  u16 version | u16 dex_count | u32 dex_offset[dex_count]
  per dex   : u16 method_count, then method_count records
  per record: u32 method_idx | u32 size | u8 insns[size]   (size == insns_size * 2)
The insns are XORed with the 4-byte little-endian `insns_xor_key` taken from
the decrypted d_shell_data_001 config; the key restarts at every record.

Usage:
  restore_dpt_v1.0.py OoooooOooo -k 1302483400 -o out/ classes.dex classes2.dex ...

The DEX files must be given in the same order as they appear in the blob
(classes.dex, classes2.dex, ...). Extra DEX files with no blob entry are
copied untouched.

stdout : the path of every written file, one per line (pipe-friendly)
stderr : colored log
"""
import sys, os, struct, zlib, hashlib, argparse


# =============================================================================
# 1. ARGUMENTS
# =============================================================================
ap = argparse.ArgumentParser(description='Restore dpt-shell hollowed method bodies (hollowing only).')
ap.add_argument('blob', help='code blob (assets/OoooooOooo)')
ap.add_argument('dex', nargs='+', help='hollowed .dex files, in blob order')
ap.add_argument('-k', '--key', required=True, type=lambda s: int(s, 0),
                help='insns_xor_key from the decrypted config (decimal or 0x hex)')
ap.add_argument('-o', '--outdir', default='.', help='output directory (default: current dir)')
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
# 3. PARSERS
# =============================================================================
def uleb(d, o):
    """Reads an unsigned LEB128 at offset 'o'. Returns (value, next offset)."""
    r = s = 0
    while True:
        b = d[o]; o += 1
        r |= (b & 0x7f) << s; s += 7
        if not b & 0x80:
            return r, o

def code_offsets(d):
    """Maps method_idx -> code_off by walking every class_data_item."""
    defs_size, defs_off = struct.unpack_from('<II', d, 0x60)
    out = {}
    for i in range(defs_size):
        o = struct.unpack_from('<I', d, defs_off + i * 32 + 24)[0]
        if not o:
            continue
        sf, o = uleb(d, o); inf, o = uleb(d, o); dm, o = uleb(d, o); vm, o = uleb(d, o)
        for _ in range(sf + inf):
            _, o = uleb(d, o); _, o = uleb(d, o)
        for n in (dm, vm):
            idx = 0
            for _ in range(n):
                diff, o = uleb(d, o); _, o = uleb(d, o); off, o = uleb(d, o)
                idx += diff
                out[idx] = off
    return out

def parse_blob(b):
    """Returns one list of (method_idx, size, data_offset) per DEX."""
    version, count = struct.unpack_from('<HH', b, 0)
    if version != 2:
        log(YELLOW(f'[!] blob version {version}, only version 2 was tested'))
    offs = struct.unpack_from(f'<{count}I', b, 4)
    out = []
    for k, o in enumerate(offs):
        n = struct.unpack_from('<H', b, o)[0]; o += 2
        recs = []
        for _ in range(n):
            mi, sz = struct.unpack_from('<II', b, o); o += 8
            recs.append((mi, sz, o)); o += sz
        if o != (offs[k + 1] if k + 1 < count else len(b)):
            die(f'blob: dex #{k} does not end where the next one starts')
        out.append(recs)
    return out


# =============================================================================
# 4. RESTORE
# =============================================================================
try:
    with open(args.blob, 'rb') as f:
        blob = f.read()
except OSError as e:
    die(f'{args.blob}: {e}')

dexes = parse_blob(blob)
if len(args.dex) < len(dexes):
    die(f'blob describes {len(dexes)} dex files, only {len(args.dex)} given')

key = struct.pack('<I', args.key)
os.makedirs(args.outdir, exist_ok=True)

log(BOLD(CYAN(f'=== RESTORING {len(dexes)} DEX from {args.blob} (key {key.hex()}) ===')))
for k, path in enumerate(args.dex):
    try:
        with open(path, 'rb') as f:
            d = bytearray(f.read())
    except OSError as e:
        die(f'{path}: {e}')
    if d[:4] != b'dex\n':
        die(f'{path}: not a DEX file')

    recs = dexes[k] if k < len(dexes) else []
    code = code_offsets(d)
    done = 0
    for mi, sz, o in recs:
        off = code.get(mi)
        if not off:
            log(YELLOW(f'  [!] {path}: method {mi} has no code item, skipped')); continue
        insns_size = struct.unpack_from('<I', d, off + 12)[0]
        if insns_size * 2 != sz:
            log(YELLOW(f'  [!] {path}: method {mi} size mismatch ({sz} vs {insns_size * 2}), skipped'))
            continue
        d[off + 16:off + 16 + sz] = bytes(c ^ key[i & 3] for i, c in enumerate(blob[o:o + sz]))
        done += 1

    # The body changed, so the header signature and checksum must be redone.
    d[12:32] = hashlib.sha1(d[32:]).digest()
    struct.pack_into('<I', d, 8, zlib.adler32(d[12:]) & 0xffffffff)

    out = os.path.join(args.outdir, os.path.basename(path))
    with open(out, 'wb') as f:
        f.write(d)
    log(f'  {GREEN("✔")} {BOLD(out)}  {done:,}/{len(recs):,} methods restored')
    print(out, flush=True)
