#!/usr/bin/env python3

import sys, os, re, shutil, zipfile, subprocess, argparse


# =============================================================================
# 1. ARGUMENTS
# =============================================================================
ap = argparse.ArgumentParser(description='Unpack a dpt-shell APK end to end.')
ap.add_argument('apk', help='packed APK')
ap.add_argument('-o', '--outdir', help='output directory (default: unpacked_<apk name>/)')
ap.add_argument('-k', '--key', type=lambda s: int(s, 0),
                help='insns_xor_key (decimal or 0x hex); skips decrypt_config.py')
ap.add_argument('--dex', default='classes.dex', help='stub DEX inside the APK (default: %(default)s)')
ap.add_argument('--config', default='assets/d_shell_data_001',
                help='encrypted config inside the APK (default: %(default)s)')
ap.add_argument('--blob', default='assets/OoooooOooo',
                help='code blob inside the APK (default: %(default)s)')
ap.add_argument('--lib', help='packer native library inside the APK '
                '(default: try every .so under assets/, arm64 first)')
ap.add_argument('--aes-key', help='config AES key as hex; skips extract_key.py')
ap.add_argument('-q', '--quiet', action='store_true',
                help="hide the scripts' own logs unless a step fails")
ap.add_argument('--force', action='store_true', help='allow a non-empty output directory')
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

def log(s=''): print(s, file=sys.stderr, flush=True)
def die(msg):  log(RED(f'[x] {msg}')); sys.exit(1)
def step(n, s): log(BOLD(CYAN(f'\n=== [{n}/5] {s} ===')))


# =============================================================================
# 3. HELPERS
# =============================================================================
SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src')

def script(name):
    p = os.path.join(SRC, name)
    if not os.path.isfile(p):
        die(f'{name} not found in {SRC}')
    return p

def run(name, *argv, cwd=None, fatal=True):
    cmd = [sys.executable, script(name), *map(str, argv)]
    r = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE if args.quiet else None, text=True)
    if r.returncode and not fatal:
        return None
    if r.returncode:
        if args.quiet and r.stderr:
            log(r.stderr.rstrip())
        if r.stdout:
            log(r.stdout.rstrip())
        die(f'{name} failed (exit {r.returncode})')
    return r.stdout

def dex_order(path):
    #classes.dex -> 1, classes2.dex -> 2, ... (the blob's order)
    m = re.search(r'classes(\d*)\.dex$', os.path.basename(path))
    return (int(m.group(1) or 1) if m else 1 << 30, path)

def abi_rank(name):
    #Library preference: arm64 first, then arm, x86_64, x86.
    for i, abi in enumerate(('arm64', 'aarch64', 'armeabi', 'arm', 'x86_64', 'x86')):
        if f'/{abi}' in name:
            return (i, name)
    return (99, name)

def extract(z, name, dst):
    # The entry name comes from the APK: refuse anything that leaves apk_dir.
    if not os.path.abspath(dst).startswith(os.path.abspath(apk_dir) + os.sep):
        log(YELLOW(f'  ! {name}: unsafe path, skipped'))
        return False
    try:
        data = z.read(name)
    except KeyError:
        return False
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, 'wb') as f:
        f.write(data)
    log(f'  {GREEN("✔")} {name}  {len(data):,} B')
    return True


# =============================================================================
# 4. PIPELINE
# =============================================================================
if not os.path.isfile(args.apk):
    die(f'{args.apk}: not found')

out = os.path.abspath(args.outdir or
                      f'unpacked_{os.path.splitext(os.path.basename(args.apk))[0]}')
if os.path.isdir(out) and os.listdir(out) and not args.force:
    die(f'{out} is not empty (use --force to reuse it)')
apk_dir, carved_dir, restored_dir = (os.path.join(out, x) for x in ('apk', 'carved', 'restored'))
for p in (carved_dir, restored_dir):
    shutil.rmtree(p, ignore_errors=True)       # no stale DEX files from an earlier run
os.makedirs(apk_dir, exist_ok=True)

log(BOLD(f'APK    : {os.path.abspath(args.apk)}'))
log(BOLD(f'Output : {out}'))

# --- 1. Extract ---------------------------------------------------------------
step(1, 'EXTRACTING FROM APK')
dex_path    = os.path.join(apk_dir, args.dex)
config_path = os.path.join(apk_dir, args.config)
blob_path   = os.path.join(apk_dir, args.blob)
try:
    with zipfile.ZipFile(args.apk) as z:
        if not extract(z, args.dex, dex_path):
            die(f'{args.dex} not in the APK')
        if not extract(z, args.blob, blob_path):
            die(f'{args.blob} not in the APK (renamed? pass --blob)')
        has_config = extract(z, args.config, config_path)
        # dpt-shell keeps its native library in assets/<folder>/<abi>/lib*.so
        names = [args.lib] if args.lib else sorted(
            (n for n in z.namelist() if n.startswith('assets/') and n.endswith('.so')), key=abi_rank)
        libs = [os.path.join(apk_dir, n) for n in names
                if extract(z, n, os.path.join(apk_dir, n))]
except zipfile.BadZipFile as e:
    die(f'{args.apk}: {e}')
if not has_config:
    log(YELLOW(f'  ! {args.config} not in the APK (renamed, or a pre-v2.11 build with no config)'))

# --- 2. Hollow ----------------------------------------------------------------
step(2, 'ENUMERATING THE STUB DEX')
run('enumerate.py', dex_path, '--json', cwd=out)      # writes report.json in cwd
report = os.path.join(out, 'report.json')
if not os.path.isfile(report):
    die('enumerate.py did not write report.json')

# --- 3. Carve -----------------------------------------------------------------
step(3, 'CARVING')
dexes = sorted((l for l in run('carve.py', report, '-o', carved_dir, '--only-dex').splitlines()
                if l.endswith('.dex')), key=dex_order)
if not dexes:
    die('nothing was carved: no appended payload in the stub DEX')

# --- 4. Config ----------------------------------------------------------------
step(4, 'CONFIG')
info = {}
if args.key is not None:
    key = args.key
    log(f'  key from the command line, decrypt_config.py skipped')
elif not has_config:
    die(f'no config to decrypt: pass the key with -k (pre-v2.11 builds have none: try -k 0)')
else:
    aes = args.aes_key
    if aes:
        log(f'  AES key from the command line, extract_key.py skipped')
    for lib in ([] if aes else libs):
        r = run('extract_key.py', lib, '--config', config_path, fatal=False)
        if r and r.strip():
            aes = r.strip()
            log(f'  {GREEN("✔")} AES key {aes} from {os.path.relpath(lib, apk_dir)}')
            break
        log(YELLOW(f'  ! no key from {os.path.relpath(lib, apk_dir)}'))
    if not aes:
        die('no AES key found in the native libraries (pass --aes-key, or -k for the XOR key)')
    text = run('decrypt_config.py', config_path, '--key', aes)
    with open(os.path.join(out, 'config.txt'), 'w') as f:
        f.write(text)
    m = re.search(r'"insns_xor_key"\s*:\s*(\d+)', text)
    if not m:
        log(text.rstrip())
        die('insns_xor_key not found in the decrypted config '
            '(wrong AES key/IV in decrypt_config.py for this sample?)')
    key = int(m.group(1))
    for k in ('app_name', 'acf_name'):
        v = re.search(rf'"{k}"\s*:\s*"([^"]*)"', text)
        if v:
            info[k] = v.group(1)
log(f'  {GREEN("✔")} insns_xor_key = {key} = 0x{key:08X}')
for k, v in info.items():
    log(f'  {GREEN("✔")} {k} = {v}')

# --- 5. Restore ---------------------------------------------------------------
step(5, 'RESTORING')
restored = [l for l in run('restore_dpt.py', blob_path, '-k', key, '-o', restored_dir, *dexes).splitlines()
            if l.endswith('.dex')]

# --- Summary ------------------------------------------------------------------
log(BOLD(GREEN(f'\n[✔] {len(restored)} DEX files restored in {restored_dir}')))
for p in restored:
    print(p, flush=True)
