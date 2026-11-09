#!/usr/bin/env python3
"""
dex_hollow_check.py
Checks whether a DEX file has hidden data that ART never reads, and
describes it. Generates a 'report.json' file when --json is set.

Usage:
  dex_hollow_check.py classes.dex           Colored report on stdout
  dex_hollow_check.py classes.dex --json    Writes 'report.json', colored report to stderr
  Multiple dexes: for f in *.dex; do python3 hollow_v1.1.py "$f"; done
"""
import sys, os, struct, zlib, hashlib, math, collections, json, argparse


# =============================================================================
# 1. ARGUMENTS
# =============================================================================
ap = argparse.ArgumentParser(description='Detect hidden data appended to a DEX file.')
ap.add_argument('dex', help='path to the .dex file')
ap.add_argument('--json', action='store_true',
                help='write a structured JSON report to report.json and log to stderr')
args = ap.parse_args()

# If --json is set, we redirect human output to stderr so stdout is reserved or silent
OUT = sys.stderr if args.json else sys.stdout


# =============================================================================
# 2. COLOR HELPERS
# =============================================================================
USE_COLOR = OUT.isatty() and 'NO_COLOR' not in os.environ
if USE_COLOR and os.name == 'nt':
    os.system('')                                   # ANSI support on Windows 10+

def _c(code):
    return (lambda s: f'\033[{code}m{s}\033[0m') if USE_COLOR else (lambda s: str(s))

RED, GREEN, YELLOW, BLUE, CYAN, BOLD, DIM = (
    _c('31'), _c('32'), _c('33'), _c('34'), _c('36'), _c('1'), _c('2'))

def say(s=''):  print(s, file=OUT)
def header(t):  say('\n' + BOLD(CYAN(f'=== {t} ===')))
def row(k, v):  say(f'  {BLUE(k.ljust(16))} {v}')
def die(msg):   print(RED(f'[x] {msg}'), file=sys.stderr); sys.exit(1)


# =============================================================================
# 3. LOAD THE FILE
# =============================================================================
path = args.dex
try:
    with open(path, 'rb') as f:
        d = f.read()
except OSError as e:
    die(f'{path}: {e}')

# Reads an unsigned 32-bit little-endian integer at offset 'o'.
u32 = lambda o: struct.unpack_from('<I', d, o)[0]


# =============================================================================
# 4. BASIC VALIDATION
# =============================================================================
if d[:4] != b'dex\n':
    die(f'{path}: not a standard DEX (magic {d[:8]!r})')
if len(d) < 0x70 or u32(0x34) + 4 > len(d):
    die(f'{path}: truncated or malformed header')


# =============================================================================
# 5. HEADER FIELDS
# =============================================================================
fields = {
    'checksum':        u32(0x08),   
    'file_size':       u32(0x20),   
    'map_off':         u32(0x34),   
    'method_ids_size': u32(0x58),   
    'class_defs_size': u32(0x60),   
    'data_size':       u32(0x68),   
    'data_off':        u32(0x6C),   
}
version = d[4:7].decode(errors='replace')
print("\n__________________________________________")
print(GREEN(path))
header('DEX HEADER')
row('version', YELLOW(version))
for k, v in fields.items():
    row(k, f'{YELLOW(f"{v:#x}")} {DIM(f"({v:,})")}')


# =============================================================================
# 6. SECTION BOUNDARIES & INTEGRITY
# =============================================================================
file_size = fields['file_size']
map_end   = fields['map_off'] + 4 + u32(fields['map_off']) * 12
data_end  = fields['data_off'] + fields['data_size']

header('BOUNDARIES & INTEGRITY')
row('data end', f'{data_end:#x}')
row('map end',  f'{map_end:#x}')
row('real size', f'{len(d):#x} ' + (GREEN('(matches header)') if len(d) == file_size
                                    else RED(f'(header says {file_size:#x})')))

adler_ok = (zlib.adler32(d[12:file_size]) & 0xffffffff) == fields['checksum']
sha1_ok  = hashlib.sha1(d[32:file_size]).digest() == d[12:32]
row('adler32', GREEN('OK') if adler_ok else RED('MISMATCH'))
row('sha1',    GREEN('OK') if sha1_ok  else RED('MISMATCH'))


# =============================================================================
# 7. SIGNATURE SCAN
# =============================================================================

header('SIGNATURE SCAN (past header)')
sig_hits = {}
for sig in (b'dex\n03', b'PK\x03\x04'):
    hits, i = [], d.find(sig, 0x70)
    while i != -1 and len(hits) < 20:
        hits.append(i)
        i = d.find(sig, i + 1)
    sig_hits[sig.hex()] = hits
    row(repr(sig), YELLOW(', '.join(map(hex, hits))) if hits else DIM('none'))
row('tail (32 B)', YELLOW(d[-32:].hex()))


# =============================================================================
# 8. PAYLOAD PARSERS
# =============================================================================
def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    return -sum(v / len(b) * math.log2(v / len(b)) for v in c.values())


def parse_dex_chain(off):
    out = []
    while off + 0x70 <= len(d) and d[off:off + 4] == b'dex\n':
        sz = u32(off + 0x20)
        if sz < 0x70 or off + sz > len(d):          
            break
        out.append({'offset': off, 'size': sz,
                    'methods': u32(off + 0x58), 'classes': u32(off + 0x60)})
        off = (off + sz + 3) & ~3
    end = out[-1]['offset'] + out[-1]['size'] if out else off
    return out, end


def parse_zip(lo):
    eocd = d.rfind(b'PK\x05\x06', lo)
    if eocd < 0 or eocd + 22 > len(d):
        return None
    _, _, _, total, cd_size, cd_off, clen = struct.unpack_from('<4x4HIIH', d, eocd)
    start = eocd - cd_size - cd_off
    if start < lo or d[start:start + 4] != b'PK\x03\x04':
        return None

    entries, p = [], start + cd_off
    for _ in range(total):
        if d[p:p + 4] != b'PK\x01\x02':
            break
        try:
            (_, _, flags, method, _, _, crc, csize, usize,
             nlen, xlen, clen_e, _, _, _, lh) = struct.unpack_from('<4x6H3I5H2I', d, p)
            name = d[p + 46:p + 46 + nlen].decode('utf-8', 'replace')
            lho = start + lh                                  
            lnlen, lxlen = struct.unpack_from('<HH', d, lho + 26)
        except struct.error:
            break
        data_off = lho + 30 + lnlen + lxlen                   
        entries.append({'name': name, 'method': method, 'flags': flags, 'crc32': crc,
                        'csize': csize, 'usize': usize, 'data_off': data_off,
                        'is_dex': d[data_off:data_off + 4] == b'dex\n'})
        p += 46 + nlen + xlen + clen_e
    return {'type': 'zip', 'start': start, 'end': eocd + 22 + clen, 'entries': entries}


def parse_trailer(end, payload_start):
    tail = d[end:]
    t = {'offset': end, 'size': len(tail), 'hex': tail[:64].hex(), 'meaning': None}
    if len(tail) == 4:
        be, le = struct.unpack('>I', tail)[0], struct.unpack('<I', tail)[0]
        length = end - payload_start
        t['meaning'] = ('payload_length_be' if be == length else
                        'payload_length_le' if le == length else
                        'payload_offset_be' if be == payload_start else
                        'payload_offset_le' if le == payload_start else None)
    return t


# =============================================================================
# 9. VERDICT
# =============================================================================
parsed_end = max(map_end, data_end)
gap        = len(d) - parsed_end
payload, verdict = None, None

header('VERDICT')
row('parsed end',     f'{parsed_end:#x}')
row('file end',       f'{len(d):#x}')
row('unparsed bytes', YELLOW(f'{gap:,}'))

if gap > 0x100:
    start  = (parsed_end + 3) & ~3
    region = d[start:]
    ent    = entropy(region[:1 << 20])                  
    ent_color = RED if ent > 7.9 else YELLOW if ent > 6.5 else GREEN

    say('\n' + BOLD(RED(f'[A] {gap:,} bytes are not referenced by any DEX section')))
    row('payload start',  f'{start:#x}')
    row('first 16 bytes', YELLOW(region[:16].hex()))
    row('entropy',        ent_color(f'{ent:.2f} bits/byte'))

    z = parse_zip(parsed_end) if region.startswith(b'PK\x03\x04') else None

    if region.startswith(b'dex\n'):
        dexes, end = parse_dex_chain(start)
        payload, verdict = {'type': 'dex', 'start': start, 'end': end, 'dexes': dexes}, 'appended_dex'
        say(GREEN(f'  -> {len(dexes)} raw DEX file(s) appended'))
        for i, x in enumerate(dexes):
            say(f'     {CYAN("DEX")} #{i}  @ {x["offset"]:#x}  {x["size"]:>12,} B  '
                f'classes={x["classes"]:,}  methods={x["methods"]:,}')

    elif z:
        payload, verdict = z, 'appended_zip'
        say(GREEN(f'  -> appended ZIP {z["start"]:#x}..{z["end"]:#x}, {len(z["entries"])} entries'))
        for e in z['entries']:
            kind = CYAN('DEX') if e['is_dex'] else DIM('---')
            meth = {0: 'stored', 8: 'deflate'}.get(e['method'], f'method {e["method"]}')
            enc  = RED(' ENCRYPTED') if e['flags'] & 1 else ''
            say(f'     {kind} {e["name"]:<24} {e["usize"]:>12,} B  {meth:<8} @ {e["data_off"]:#x}{enc}')

    else:
        verdict = 'appended_encrypted' if ent > 7.9 else 'appended_unknown'
        payload = {'type': 'blob', 'start': start, 'end': len(d), 'entropy': round(ent, 3)}
        if region.startswith(b'PK\x03\x04'):
            say(YELLOW('  -> starts like a ZIP, but its central directory is broken. Carving as a blob'))
        elif ent > 7.9:
            say(RED('  -> encrypted or compressed blob. Native code probably decodes it'))
        else:
            say(YELLOW('  -> structured data in an unknown format. Check the tail for a trailer'))

    if payload['type'] in ('dex', 'zip') and payload['end'] < len(d):
        t = parse_trailer(payload['end'], payload['start'])
        payload['trailer'] = t
        row('trailer', f'{t["size"]} B @ {t["offset"]:#x}: {YELLOW(t["hex"])} '
                       + (GREEN(f'({t["meaning"]})') if t['meaning'] else DIM('(unknown)')))

elif fields['class_defs_size'] > 500:
    verdict = 'clean_code_inside'
    say(GREEN(f'\n[B] no unparsed data, and {fields["class_defs_size"]:,} classes. The code is inside this DEX'))

else:
    verdict = 'few_classes_check_map'
    say(YELLOW('\n[?] no unparsed data and only a few classes. The payload is probably inside a section. Check the map_list'))


# =============================================================================
# 10. JSON OUTPUT & FILE GENERATION
# =============================================================================
# If --json is set, we serialize the dictionary and write it to report.json
if args.json:
    report_data = {
        'file': os.path.abspath(path), 'size': len(d),
        'sha256': hashlib.sha256(d).hexdigest(), 'dex_version': version,
        'header': fields, 'parsed_end': parsed_end, 'gap': gap,
        'checksums': {'adler32': adler_ok, 'sha1': sha1_ok},
        'signatures': sig_hits, 'verdict': verdict, 'payload': payload,
    }
    
    # Write the file
    report_filename = 'report.json'
    try:
        with open(report_filename, 'w') as jf:
            json.dump(report_data, jf, indent=2)
        print(GREEN(f"\n[✔] Structured JSON report successfully saved to '{report_filename}'\n"), file=sys.stderr)
    except OSError as e:
        print(RED(f"\n[x] Failed to write '{report_filename}': {e}\n"), file=sys.stderr)
