#!/usr/bin/env python3

import sys, os, struct, argparse


# =============================================================================
# 1. ARGUMENTS
# =============================================================================
ap = argparse.ArgumentParser(description='Extract the dpt-shell config key from the native library.')
ap.add_argument('lib', help='dpt-shell native library (.so)')
ap.add_argument('--config', help='encrypted config (d_shell_data_001) used to verify the key')
ap.add_argument('--symbol', default='DPT_UNKNOWN_DATA', help='key symbol name (default: %(default)s)')
ap.add_argument('--no-scan', action='store_true', help='do not brute-force the key when the symbol fails')
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
# 3. MINIMAL ELF READER
# =============================================================================
class ELF:
    """Just enough ELF parsing to read symbols and map addresses to offsets."""

    def __init__(self, d):
        if d[:4] != b'\x7fELF':
            raise ValueError('not an ELF file')
        self.d = d
        self.b64 = d[4] == 2
        self.e = '<' if d[5] == 1 else '>'
        if self.b64:
            (self.phoff, self.shoff) = struct.unpack_from(self.e + 'QQ', d, 0x20)
            (self.phentsize, self.phnum, self.shentsize,
             self.shnum, self.shstrndx) = struct.unpack_from(self.e + '5H', d, 0x36)
        else:
            (self.phoff, self.shoff) = struct.unpack_from(self.e + 'II', d, 0x1c)
            (self.phentsize, self.phnum, self.shentsize,
             self.shnum, self.shstrndx) = struct.unpack_from(self.e + '5H', d, 0x2a)
        self.segments = [self._ph(i) for i in range(self.phnum)]
        self.sections = [self._sh(i) for i in range(self.shnum)]

    def _ph(self, i):
        o = self.phoff + i * self.phentsize
        if self.b64:
            t, _, off, va, _, fsz, msz, _ = struct.unpack_from(self.e + 'IIQQQQQQ', self.d, o)
        else:
            t, off, va, _, fsz, msz, _, _ = struct.unpack_from(self.e + '8I', self.d, o)
        return {'type': t, 'offset': off, 'vaddr': va, 'filesz': fsz}

    def _sh(self, i):
        o = self.shoff + i * self.shentsize
        if self.b64:
            name, t, _, addr, off, size, link, _, _, entsize = \
                struct.unpack_from(self.e + 'IIQQQQIIQQ', self.d, o)
        else:
            name, t, _, addr, off, size, link, _, _, entsize = \
                struct.unpack_from(self.e + '10I', self.d, o)
        return {'name': name, 'type': t, 'addr': addr, 'offset': off,
                'size': size, 'link': link, 'entsize': entsize}

    def cstr(self, off):
        return self.d[off:self.d.index(b'\0', off)].decode('utf-8', 'replace')

    def symbols(self):
        """Yields (name, value, size) from .dynsym and .symtab."""
        for sh in self.sections:
            if sh['type'] not in (2, 11) or not sh['entsize']:   # SHT_SYMTAB, SHT_DYNSYM
                continue
            strtab = self.sections[sh['link']]['offset']
            for k in range(sh['size'] // sh['entsize']):
                o = sh['offset'] + k * sh['entsize']
                if self.b64:
                    name, _, _, _, value, size = struct.unpack_from(self.e + 'IBBHQQ', self.d, o)
                else:
                    name, value, size, _, _, _ = struct.unpack_from(self.e + 'IIIBBH', self.d, o)
                yield self.cstr(strtab + name), value, size

    def offset_of(self, vaddr):
        """File offset of a virtual address, through the PT_LOAD segments."""
        for s in self.segments:
            if s['type'] == 1 and s['vaddr'] <= vaddr < s['vaddr'] + s['filesz']:
                return s['offset'] + vaddr - s['vaddr']
        return None

    def loaded_ranges(self):
        """(offset, size) of every PT_LOAD segment's file content."""
        return [(s['offset'], s['filesz']) for s in self.segments if s['type'] == 1]


# =============================================================================
# 4. KEY CHECK
# =============================================================================
def iv_of(key):
    """dpt-shell v2.11-v2.12: the IV is the key with bytes 3 and 9 patched."""
    iv = bytearray(key)
    iv[3], iv[9] = 0x2f, 0x76
    return bytes(iv)

def make_checker(cfg):
    """Returns check(key) -> bool, true when the key decrypts the config."""
    from Crypto.Cipher import AES   # only needed when verifying
    if not cfg or len(cfg) % 16:
        die(f'config is {len(cfg)} bytes, not a multiple of 16: not AES-CBC')
    first = cfg[:16]

    def check(key):
        # Cheap pre-filter: the plaintext must start with '{'.
        if AES.new(key, AES.MODE_CBC, iv_of(key)).decrypt(first)[:1] != b'{':
            return False
        p = AES.new(key, AES.MODE_CBC, iv_of(key)).decrypt(cfg)
        n = p[-1]
        return 1 <= n <= 16 and p[-n:] == bytes([n]) * n and p[:-n].rstrip().endswith(b'}')
    return check


# =============================================================================
# 5. MAIN
# =============================================================================
try:
    with open(args.lib, 'rb') as f:
        d = f.read()
    elf = ELF(d)
except (OSError, ValueError, struct.error) as e:
    die(f'{args.lib}: {e}')

check = None
if args.config:
    try:
        with open(args.config, 'rb') as f:
            check = make_checker(f.read())
    except OSError as e:
        die(f'{args.config}: {e}')

log(BOLD(CYAN(f'=== KEY from {args.lib} ({"64" if elf.b64 else "32"}-bit ELF) ===')))

# --- Symbol --------------------------------------------------------------------
key = None
sym = next(((v, s) for n, v, s in elf.symbols() if n == args.symbol and v), None)
if sym is None:
    log(YELLOW(f'  ! symbol {args.symbol} not found'))
else:
    vaddr, size = sym
    off = elf.offset_of(vaddr)
    if off is None or size < 16:
        log(YELLOW(f'  ! {args.symbol} @ 0x{vaddr:x} ({size} B) is not 16 bytes of file data'))
    else:
        cand = d[off:off + 16]
        log(f'  {args.symbol} @ vaddr 0x{vaddr:x}, file offset 0x{off:x}: {cand.hex()}')
        if check is None:
            key = cand
            log(YELLOW('  ! not verified (no --config given)'))
        elif check(cand):
            key = cand
            log(f'  {GREEN("✔")} decrypts the config')
        else:
            log(YELLOW('  ! does not decrypt the config (other dpt-shell version?)'))

# --- Scan ----------------------------------------------------------------------
if key is None and check is not None and not args.no_scan:
    total = sum(sz for _, sz in elf.loaded_ranges())
    log(f'  scanning {total:,} bytes of loaded data for a 16-byte key...')
    seen = set()
    for start, sz in elf.loaded_ranges():
        for o in range(start, start + sz - 15):
            cand = d[o:o + 16]
            if cand in seen:
                continue
            seen.add(cand)
            if check(cand):
                key = cand
                log(f'  {GREEN("✔")} key found at file offset 0x{o:x}')
                break
        if key:
            break

if key is None:
    die('no key found')

log(f'  {GREEN("✔")} AES key {BOLD(key.hex())}')
log(f'  {GREEN("✔")} AES IV  {BOLD(iv_of(key).hex())}')
print(key.hex(), flush=True)
