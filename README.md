# dpt-shell static unpacker

A static unpacker for Android APKs protected by stock
[dpt-shell](https://github.com/luoyesiqiu/dpt-shell) **v2.11.x–v2.12.x**. Given a packed
APK, it recovers the original DEX files with their hollowed method bodies put back,
ready to open in [jadx](https://github.com/skylot/jadx).

Nothing is executed: the APK is only read. No emulator, device, Frida or disassembler is
needed.

```bash
python3 unpack.py sample.apk
# -> unpacked_sample/restored/classes_classes.dex, classes_classes2.dex, ...
```

## Requirements

- Python 3.8+
- [`pycryptodome`](https://pypi.org/project/pycryptodome/) (`pip install pycryptodome`),
  used to decrypt the config. Everything else uses the standard library only.

## How dpt-shell protects an app

| What | Where in the APK | Role |
|---|---|---|
| Stub DEX | `classes.dex` | A small loader (`JniBridge`, `ProxyApplication`, …). The app's real DEX files are in a stored ZIP **appended after the stub's data section**, followed by a 4-byte big-endian length. The header's `file_size` and checksums are patched to cover the whole file, so it still looks valid. |
| Hollowed DEX files | inside that ZIP | The real classes, but the bodies of the protected methods are overwritten with random bytes. |
| Code blob | `assets/OoooooOooo` | The original bodies of the hollowed methods, XORed with a 4-byte key. |
| Config | `assets/d_shell_data_001` | AES-128-CBC encrypted JSON that holds `insns_xor_key`, the real `app_name` and `acf_name`. |
| Native library | `assets/vwwwwwvwww/<abi>/lib*.so` | The packer runtime. Its `.bitcode` section is RC4-encrypted. It exports the 16-byte config key as `DPT_UNKNOWN_DATA`. |

At runtime the library extracts the ZIP to `code_cache/i11111i111.zip`, adds it to the
class loader, hooks `ClassLinker::DefineClass` and XORs each method body back in as its
class loads. This tool does the same thing offline.

## Pipeline

`unpack.py` runs these steps in order. Each script in `src/` can also be run on its own.

| Step | Script | Input → output |
|---|---|---|
| 1. Extract | `unpack.py` | APK → `classes.dex`, `OoooooOooo`, `d_shell_data_001`, the native libraries |
| 2. Enumerate | `src/enumerate.py` | stub `classes.dex` → `report.json`: header fields, section boundaries, checksums, the appended ZIP and its entries |
| 3. Carve | `src/carve.py` | `report.json` → the hollowed DEX files and the payload ZIP |
| 4a. Key | `src/extract_key.py` | native library → AES key (`DPT_UNKNOWN_DATA`), verified against the config |
| 4b. Config | `src/decrypt_config.py` | `d_shell_data_001` + key → decrypted JSON with `insns_xor_key` |
| 5. Restore | `src/restore_dpt.py` | `OoooooOooo` + hollowed DEX files + `insns_xor_key` → restored DEX files |

### Output

```
unpacked_<apk>/
├── apk/          files extracted from the APK
├── report.json   enumerate.py report
├── carved/       hollowed DEX files + classes_payload.zip
├── config.txt    decrypted config
└── restored/     restored DEX files: open these in jadx
```

The paths of the restored DEX files are printed on stdout, one per line, and the log goes
to stderr. This means the output can be piped:

```bash
python3 unpack.py sample.apk -q | xargs jadx -d sources/
```

## Usage

```
python3 unpack.py APK [-o OUTDIR] [-k KEY] [--aes-key HEX] [--lib ENTRY]
                      [--dex ENTRY] [--config ENTRY] [--blob ENTRY] [-q] [--force]
```

| Option | Meaning |
|---|---|
| `-o`, `--outdir` | Output directory. Default: `unpacked_<apk name>/`. It must be new or empty. |
| `--force` | Reuse a non-empty output directory. `carved/` and `restored/` are emptied first. |
| `-k`, `--key` | `insns_xor_key` (decimal or `0x` hex). Skips key extraction and config decryption. |
| `--aes-key` | Config AES key as 32 hex digits. Skips `extract_key.py`. |
| `--lib` | Native library entry to read the key from. Default: every `.so` under `assets/`, arm64 first, until one works. |
| `--dex`, `--config`, `--blob` | APK entry names, if a build renamed them. Defaults: `classes.dex`, `assets/d_shell_data_001`, `assets/OoooooOooo`. |
| `-q`, `--quiet` | Hide the scripts' own logs unless a step fails. |

### Running the scripts by hand

```bash
unzip -p sample.apk classes.dex > classes.dex
unzip -p sample.apk assets/OoooooOooo > OoooooOooo
unzip -p sample.apk assets/d_shell_data_001 > d_shell_data_001
unzip -p sample.apk assets/vwwwwwvwww/arm64/libXXXX.so > lib.so

python3 src/enumerate.py classes.dex --json                   # writes ./report.json
python3 src/carve.py report.json -o carved/                    # carved/classes_classes*.dex
KEY=$(python3 src/extract_key.py lib.so --config d_shell_data_001)
python3 src/decrypt_config.py d_shell_data_001 --key $KEY      # look for insns_xor_key
python3 src/restore_dpt.py OoooooOooo -k <insns_xor_key> -o restored/ \
    carved/classes_classes.dex carved/classes_classes{2,3,4,5,6,7}.dex
```

Notes:

- **Use `unzip -p`, not a plain extract.** Some samples add fake entries such as
  `classes.dex/…` so that `unzip` creates a directory and cannot write the real file.
  `unpack.py` reads entries by exact name and is not affected.
- **`enumerate.py` always writes `report.json` to the current directory.** Without
  `--json`, it prints a human-readable report instead.
- **Give `restore_dpt.py` the DEX files in blob order:** `classes.dex`, `classes2.dex`,
  and so on. A shell glob puts `classes_classes.dex` last, which is wrong. DEX files with
  no blob entry are copied unchanged. This includes dpt-shell's junk-code DEX
  (`com/luoye/dpt/junkcode/JunkClass-*`), whose broken `<clinit>` methods are intentional.

## Details

### Config key (`extract_key.py`)

`DPT_UNKNOWN_DATA` is a 16-byte array in the library's `.data` section, exported in
`.dynsym`. `extract_key.py` reads it with a small built-in ELF parser and checks it by
decrypting the config:

- **AES-128-CBC.** The key is `DPT_UNKNOWN_DATA`. The IV is the same 16 bytes with
  `iv[3] = 0x2f` and `iv[9] = 0x76`.
- **A key is accepted only if** the result has valid PKCS#7 padding and is a JSON object.

If the symbol is missing or does not verify, every 16-byte window of the library's loaded
data is tried as the key, which takes a few seconds. This also works on stripped builds.

### Code blob (`restore_dpt.py`)

```
u16 version (2) | u16 dex_count | u32 dex_offset[dex_count]
per DEX:    u16 method_count
per method: u32 method_idx | u32 size | u8 insns[size]
```

For each record, `restore_dpt.py`:

1. finds the method's `code_item` through `class_defs` → `class_data_item`,
2. checks that `insns_size * 2 == size`,
3. XORs the bytes with `insns_xor_key` as 4 little-endian bytes, restarting the key at
   every record,
4. writes them at `code_off + 16`,
5. finally recomputes the DEX SHA-1 and Adler-32.

## Supported versions and limitations

| dpt-shell | Status |
|---|---|
| v2.11.x – v2.12.x | Supported |
| v2.13.0+ | Not supported. The config key is HMAC-SHA256(`DPT_UNKNOWN_DATA`, `<package>_<build key>`) with AES-256, so key verification fails. |
| v2.20.0+ | Not supported. Method bodies are RC4-encrypted instead of XORed. |
| before v2.11 | No `d_shell_data_001` and no XOR key. Pass `-k 0`; untested. |

- **Only dpt-shell's own protection is undone.** If the app was obfuscated before it was
  packed, the restored code is exactly as obfuscated as the original. One example is
  junk `fill-array-data` payloads appended to method bodies, which make jadx fail with
  `newPosition > limit`.
- **Blob version.** `restore_dpt.py` warns on any blob version other than 2.
- **Unsupported or renamed builds fail with an error**, not wrong output. The key must
  decrypt the config, and every record's size must match its method.

## Safety

The APKs this tool is meant for are often malware. The tool never runs the sample, but
handle it in an isolated VM all the same. Don't install the APK on a real device.
