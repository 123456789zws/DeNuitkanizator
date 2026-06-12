#!/usr/bin/env python3
import sys
import os
import re
import struct
import marshal
import zlib
import hashlib
import datetime
import shutil
import math
import string
from pathlib import Path
from collections import Counter

try:
    import pefile
except ImportError:
    print("FATAL: pefile not installed. Run: pip install pefile")
    sys.exit(1)

try:
    import capstone
except ImportError:
    capstone = None

try:
    import zstandard as zstd
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False

from colorama import init, Fore, Back, Style
init(autoreset=True)

VERSION = "1.0"
REPO = "github.com/2M12/DeNuitkanizator"

PYTHON_MAGICS = {
    b'\x42\x0d\x0d\x0a': "3.7",
    b'\x55\x0d\x0d\x0a': "3.8",
    b'\x61\x0d\x0d\x0a': "3.9",
    b'\x6f\x0d\x0d\x0a': "3.10",
    b'\xa7\x0d\x0d\x0a': "3.11",
}

NUITKA_SIGNATURES = [
    b'Nuitka', b'nuitka', b'__nuitka_', b'nuitka_version',
    b'Nuitka_Onefile', b'Nuitka-Scons', b'__compiled__', b'frozen_modules',
]

ANTI_DEBUG_APIS = [
    b'IsDebuggerPresent', b'CheckRemoteDebuggerPresent',
    b'NtQueryInformationProcess', b'NtSetInformationThread',
    b'OutputDebugStringA', b'GetTickCount', b'QueryPerformanceCounter', b'rdtsc',
]

BANNER = f"""{Fore.YELLOW}
  _____       _   _       _ _   _               _          _             
 |  __ \\     | \\ | |     (_) | | |             (_)        | |            
 | |  | | ___|  \\| |_   _ _| |_| | ____ _ _ __  _ ______ _| |_ ___  _ __ 
 | |  | |/ _ \\ . ` | | | | | __| |/ / _` | '_ \\| |_  / _` | __/ _ \\| '__|
 | |__| |  __/ |\\  | |_| | | |_|   < (_| | | | | |/ / (_| | || (_) | |   
 |_____/ \\___|_| \\_|\\__,_|_|\\__|_|\\_\\__,_|_| |_|_/___\\__,_|\\__\\___/|_|   
                                                                         {Style.RESET_ALL}"""


class Logger:
    def __init__(self, log_path):
        self.log_file = open(log_path, 'w', encoding='utf-8')
        self.start_time = datetime.datetime.now()

    def info(self, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"{Back.CYAN}{Fore.BLACK} INFO {Style.RESET_ALL} [{ts}] {msg}")
        self.log_file.write(f"[INFO] [{ts}] {msg}\n")
        self.log_file.flush()

    def warning(self, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"{Back.YELLOW}{Fore.BLACK} WARNING {Style.RESET_ALL} [{ts}] {msg}")
        self.log_file.write(f"[WARNING] [{ts}] {msg}\n")
        self.log_file.flush()

    def fatal(self, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"{Back.RED}{Fore.WHITE} FATAL {Style.RESET_ALL} [{ts}] {msg}")
        self.log_file.write(f"[FATAL] [{ts}] {msg}\n")
        self.log_file.flush()

    def done(self, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"\n{Back.GREEN}{Fore.BLACK} DONE {Style.RESET_ALL} [{ts}] {msg}")
        self.log_file.write(f"[DONE] [{ts}] {msg}\n")
        self.log_file.flush()

    def elapsed(self):
        return (datetime.datetime.now() - self.start_time).total_seconds()

    def close(self):
        self.log_file.close()


class NuitkaDumper:
    def __init__(self, filepath):
        self.filepath = Path(filepath).resolve()
        self.data = None
        self.pe = None
        self.detected_packager = None
        self.detected_nuitka = False
        self.detected_python = None
        self.found_bytecodes = []
        self.found_frozen_modules = []
        self.output_dir = None
        self.logger = None
        self.all_sections_data = b''
        self.extracted_strings = []
        self.extracted_modules = set()
        self.extracted_ips = set()
        self.extracted_urls = set()
        self.extracted_paths = set()
        self.extracted_emails = set()
        self.rsrc_entropy = 0.0
        self.rsrc_data = b''
        self.rsrc_start = 0
        self.rsrc_end = 0
        self.section_ranges = {}

    def run(self):
        self._show_banner()
        target = self._prompt_path()
        self._init_output(target)
        self._dump_all()
        self._write_summary()
        self.logger.done("EXIT CODE: 0 (Success). Check output files! :)")
        self.logger.close()

    def _show_banner(self):
        print(BANNER)
        print(f"{Back.CYAN}{Fore.BLACK} INFO {Style.RESET_ALL} Created by 2M12 on Python 3.11")
        print(f"{Back.CYAN}{Fore.BLACK} INFO {Style.RESET_ALL} This is version {VERSION}")
        print(f"{Back.CYAN}{Fore.BLACK} INFO {Style.RESET_ALL} Repository: {REPO}")
        print(f"{Back.CYAN}{Fore.BLACK} INFO {Style.RESET_ALL} Please read the instructions in the repository before using the program.")
        print(f"{Back.YELLOW}{Fore.BLACK} WARNING {Style.RESET_ALL} By using this tool, you agree to the terms in EULA.md (check Repository)")
        print()

    def _prompt_path(self):
        border = f"{Fore.CYAN}╔═════════════════════════════════════════════════════════════════════════════╗{Style.RESET_ALL}"
        prompt = f"{Fore.CYAN}║{Style.RESET_ALL} Enter path .exe file:                                                       {Fore.CYAN}║{Style.RESET_ALL}"
        bottom = f"{Fore.CYAN}╚═════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}"
        print(border)
        print(prompt)
        print(bottom)
        path = input("> ").strip().strip('"')
        os.system('cls' if os.name == 'nt' else 'clear')
        return path

    def _init_output(self, target):
        target_path = Path(target)
        if not target_path.exists():
            self._fatal_error(1)
        if not target_path.is_file():
            self._fatal_error(1)

        self.data = target_path.read_bytes()
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = target_path.stem
        self.output_dir = Path.cwd() / "DeNuitkanizator_Output" / f"{base_name}_{ts}"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        log_path = self.output_dir / f"{base_name}_{ts}.log"
        self.logger = Logger(str(log_path))
        self.logger.info(f"Output directory: {self.output_dir}")
        self.logger.info(f"Target file: {target_path}")
        self.logger.info(f"File size: {len(self.data):,} bytes")
        if not HAS_ZSTD:
            self.logger.warning("zstandard not installed. Install: pip install zstandard")

        try:
            self.pe = pefile.PE(data=self.data)
            self.logger.info("PE file detected")
            for section in self.pe.sections:
                try:
                    section_data = section.get_data()
                    self.all_sections_data += section_data
                    name = section.Name.decode('utf-8', errors='replace').strip('\x00')
                    start = section.PointerToRawData
                    end = start + section.SizeOfRawData
                    self.section_ranges[name] = (start, end)
                    if name == '.rsrc':
                        self.rsrc_data = section_data
                        self.rsrc_entropy = self._calc_entropy(section_data)
                        self.rsrc_start = start
                        self.rsrc_end = end
                except:
                    pass
        except Exception:
            self.logger.info("Not a valid PE file, continuing with raw data")
            self.all_sections_data = self.data

    def _is_in_section(self, offset, section_name):
        if section_name in self.section_ranges:
            start, end = self.section_ranges[section_name]
            return start <= offset < end
        return False

    def _dump_all(self):
        self._create_dirs()
        self._detect_packager()
        self._dump_sections()
        self._dump_overlay()
        self._dump_resources()
        self._extract_all_strings()
        self._aggressive_bytecode_search()
        self._extract_frozen_modules()
        self._extract_nuitka_constants()
        self._extract_python_object_headers()
        self._extract_source_paths()
        self._extract_variable_names()
        self._extract_nuitka_onefile_payload()
        self._dump_info()
        self._dump_hashes()
        self._dump_entropy()
        self._dump_disasm()
        self._dump_analysis()
        self._dump_suspicious()
        self._dump_compressed_blocks()
        self._dump_string_files()
        self._write_log_copy()

    def _create_dirs(self):
        dirs = [
            "Dumps/sections", "Dumps/resources/icons", "Dumps/resources/manifests",
            "Dumps/resources/version_info", "Dumps/resources/bitmaps",
            "Dumps/bytecode/3.7", "Dumps/bytecode/3.8", "Dumps/bytecode/3.9",
            "Dumps/bytecode/3.10", "Dumps/bytecode/3.11",
            "Dumps/memory/py_objects", "Dumps/memory/nuitka_structs",
            "Dumps/frozen_modules", "Dumps/payloads",
            "Strings/suspicious", "Info", "Disasm/xrefs", "Analysis",
            "Suspicious/encrypted_blocks", "Suspicious/compressed_blocks",
            "Suspicious/obfuscated_code", "Suspicious/anti_debug",
            "Suspicious/packed_sections",
            "Recovered/source/incomplete", "Recovered/bytecode_decoded",
            "Recovered/configs",
        ]
        for d in dirs:
            (self.output_dir / d).mkdir(parents=True, exist_ok=True)

    def _detect_packager(self):
        self.logger.info("Detecting packager...")
        nuitka_hits = 0
        for sig in NUITKA_SIGNATURES:
            if sig in self.data:
                nuitka_hits += 1

        if nuitka_hits >= 1:
            self.detected_packager = "Nuitka"
            self.detected_nuitka = True
            self.logger.info(f"  Detected: Nuitka ({nuitka_hits} signatures matched)")
        elif self.rsrc_entropy > 7.9 and len(self.rsrc_data) > 100000:
            self.detected_packager = "Nuitka (detected by .rsrc entropy)"
            self.detected_nuitka = True
            self.logger.info(f"  Detected: Nuitka (high entropy .rsrc: {self.rsrc_entropy:.2f}/8.0, size: {len(self.rsrc_data):,} bytes)")
        elif b'MEI' in self.data[:100] or b'PYZ-00.pyz' in self.data:
            self.detected_packager = "PyInstaller"
            self.logger.warning("  Detected: PyInstaller (not Nuitka)")
            self.logger.warning("  Error 5: You are not using Nuitka.")
        elif b'cx_Freeze' in self.data:
            self.detected_packager = "cx_Freeze"
            self.logger.warning("  Detected: cx_Freeze (not Nuitka)")
        else:
            self.detected_packager = "Unknown"
            self.logger.info("  Packager not identified")

    def _dump_sections(self):
        if not self.pe:
            return
        self.logger.info("Dumping sections...")
        for section in self.pe.sections:
            name = section.Name.decode('utf-8', errors='replace').strip('\x00').strip()
            if not name:
                name = f"section_{hex(section.VirtualAddress)}"
            fname = self.output_dir / "Dumps" / "sections" / f"{name}.bin"
            try:
                data = section.get_data()
                fname.write_bytes(data)
                self.logger.info(f"  Section {name}: {len(data):,} bytes")
            except Exception as e:
                self.logger.warning(f"  Failed to dump section {name}: {e}")

    def _dump_overlay(self):
        if not self.pe:
            return
        self.logger.info("Dumping overlay...")
        last_section = self.pe.sections[-1]
        pe_end = last_section.PointerToRawData + last_section.SizeOfRawData
        if pe_end < len(self.data):
            overlay = self.data[pe_end:]
            fname = self.output_dir / "Dumps" / "overlay.bin"
            fname.write_bytes(overlay)
            self.logger.info(f"  Overlay: {len(overlay):,} bytes")
        else:
            self.logger.info("  No overlay found")

    def _dump_resources(self):
        if not self.pe:
            return
        self.logger.info("Dumping resources...")
        count = 0
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    dest = None
                    if entry.id == 3 or entry.id == 14:
                        dest = self.output_dir / "Dumps" / "resources" / "icons"
                    elif entry.id == 24:
                        dest = self.output_dir / "Dumps" / "resources" / "manifests"
                    elif entry.id == 16:
                        dest = self.output_dir / "Dumps" / "resources" / "version_info"
                    elif entry.id == 2:
                        dest = self.output_dir / "Dumps" / "resources" / "bitmaps"
                    if dest is None:
                        continue
                    dest.mkdir(parents=True, exist_ok=True)
                    if hasattr(entry, 'directory'):
                        for res in entry.directory.entries:
                            if hasattr(res, 'data'):
                                try:
                                    data = self.pe.get_data(res.data.struct.OffsetToData, res.data.struct.Size)
                                    ext = ".bin"
                                    if entry.id in [3, 14]:
                                        ext = ".ico"
                                    elif entry.id == 24:
                                        ext = ".xml"
                                    elif entry.id == 2:
                                        ext = ".bmp"
                                    fname = dest / f"resource_{res.id}{ext}"
                                    fname.write_bytes(data)
                                    count += 1
                                except:
                                    pass
        except Exception as e:
            self.logger.warning(f"  Failed to dump some resources: {e}")
        self.logger.info(f"  Resources extracted: {count}")

    def _is_garbage_string(self, s):
        if len(s) < 4:
            return True
        printable_count = sum(1 for c in s if c in string.printable)
        ratio = printable_count / len(s) if len(s) > 0 else 0
        if ratio < 0.5:
            return True
        garbage_chars = set('!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~')
        alpha_count = sum(1 for c in s if c.isalpha())
        garbage_count = sum(1 for c in s if c in garbage_chars)
        if alpha_count == 0 and garbage_count > len(s) * 0.6:
            return True
        if len(s) >= 6 and garbage_count > len(s) * 0.8:
            return True
        return False

    def _extract_all_strings(self):
        self.logger.info("Extracting all readable strings...")
        strings = []
        for match in re.finditer(b'[\x20-\x7e]{4,}', self.data):
            try:
                s = match.group().decode('ascii', errors='replace')
                if not self._is_garbage_string(s):
                    strings.append(s)
            except:
                pass
        self.extracted_strings = list(set(strings))
        self.logger.info(f"  Total unique ASCII strings (filtered): {len(self.extracted_strings)}")

    def _dump_string_files(self):
        strings_dir = self.output_dir / "Strings"

        ascii4 = []
        ascii8 = []
        utf16le = []

        for s in self.extracted_strings:
            if len(s) >= 4:
                ascii4.append(s)
            if len(s) >= 8:
                ascii8.append(s)

        for match in re.finditer(b'(?:[\x20-\x7e]\x00){4,}', self.data):
            raw = match.group()
            try:
                s = raw.decode('utf-16-le', errors='replace')
                if s.strip() and not self._is_garbage_string(s):
                    utf16le.append(s)
            except:
                pass

        self._write_list(strings_dir / "all_ascii_4.txt", sorted(set(ascii4)))
        self._write_list(strings_dir / "all_ascii_8.txt", sorted(set(ascii8)))
        self._write_list(strings_dir / "all_utf16le.txt", sorted(set(utf16le)))
        self._write_list(strings_dir / "all_utf8.txt", sorted(set(ascii8)))
        self._write_list(strings_dir / "paths.txt", sorted(self.extracted_paths))
        self._write_list(strings_dir / "urls.txt", sorted(self.extracted_urls))
        self._write_list(strings_dir / "emails.txt", sorted(self.extracted_emails))
        self._write_list(strings_dir / "ips.txt", sorted(self.extracted_ips))
        self._write_list(strings_dir / "unique.txt", sorted(set(ascii4)))

    def _scan_data_for_patterns(self, data):
        path_pattern = re.compile(rb'(?:[A-Za-z]:\\|/|\./|\.\./)[\x20-\x7e\\/]{4,}')
        for match in path_pattern.finditer(data):
            try:
                p = match.group().decode('ascii', errors='replace')
                if p and len(p) > 5 and all(c in string.printable for c in p):
                    self.extracted_paths.add(p)
            except:
                pass

        url_pattern = re.compile(rb'https?://[\x20-\x7e]{4,}')
        for match in url_pattern.finditer(data):
            try:
                u = match.group().decode('ascii', errors='replace')
                self.extracted_urls.add(u)
            except:
                pass

        email_pattern = re.compile(rb'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
        for match in email_pattern.finditer(data):
            try:
                e = match.group().decode('ascii', errors='replace')
                self.extracted_emails.add(e)
            except:
                pass

        ip_pattern = re.compile(rb'(?:\d{1,3}\.){3}\d{1,3}')
        for match in ip_pattern.finditer(data):
            try:
                ip = match.group().decode('ascii')
                parts = ip.split('.')
                if all(0 <= int(p) <= 255 for p in parts):
                    self.extracted_ips.add(ip)
            except:
                pass

        for match in re.finditer(b'[\x20-\x7e]{4,}', data):
            try:
                s = match.group().decode('ascii', errors='replace')
                if not self._is_garbage_string(s):
                    self.extracted_strings.append(s)
            except:
                pass

        module_pattern = re.compile(rb'([A-Za-z0-9_/\\]+\.py)\x00')
        for match in module_pattern.finditer(data):
            try:
                mod = match.group(1).decode('ascii', errors='replace')
                if 3 < len(mod) < 200:
                    self.extracted_modules.add(mod)
            except:
                pass

        for magic, ver_name in PYTHON_MAGICS.items():
            offset = data.find(magic)
            if offset != -1:
                self.logger.info(f"    Found {ver_name} magic in decompressed data")
                bytecode_dir = self.output_dir / "Dumps" / "bytecode" / ver_name
                fname = bytecode_dir / f"decompressed_magic_{offset:08x}.bin"
                fname.write_bytes(data[max(0, offset - 16):offset + 65536])
                self.found_bytecodes.append((ver_name, offset, "decompressed"))

    def _aggressive_bytecode_search(self):
        self.logger.info("Aggressive bytecode/magic search...")
        bytecode_dir = self.output_dir / "Dumps" / "bytecode"

        for magic, ver_name in PYTHON_MAGICS.items():
            for section in self.pe.sections:
                try:
                    name = section.Name.decode('utf-8', errors='replace').strip('\x00')
                    region_data = section.get_data()
                    offset = 0
                    while True:
                        offset = region_data.find(magic, offset)
                        if offset == -1:
                            break
                        self._dump_magic_context(region_data, offset, ver_name, bytecode_dir, name)
                        if offset + 12 <= len(region_data):
                            self._try_marshal_load(region_data, offset, ver_name, bytecode_dir)
                        offset += max(len(magic), 1)
                except:
                    pass

        self.logger.info(f"  Bytecode candidates saved: {len(self.found_bytecodes)}")

    def _dump_magic_context(self, data, offset, ver_name, bytecode_dir, region_name):
        chunk_size = 65536
        start = max(0, offset - 256)
        end = min(len(data), offset + chunk_size)
        chunk = data[start:end]
        safe_region = region_name.replace('/', '_').replace('\\', '_')
        fname = bytecode_dir / ver_name / f"magic_context_{safe_region}_{offset:08x}.bin"
        fname.write_bytes(chunk)
        self.found_bytecodes.append((ver_name, offset, f"magic_context_{safe_region}"))

    def _try_marshal_load(self, data, offset, ver_name, bytecode_dir):
        for skip in [0, 4, 8, 12]:
            test_offset = offset + skip
            if test_offset + 4 > len(data):
                continue
            for test_size in [4096, 8192, 16384, 32768, 65536, 131072]:
                if test_offset + test_size > len(data):
                    continue
                chunk = data[test_offset:test_offset + test_size]
                try:
                    marshal.loads(chunk)
                    fname = bytecode_dir / ver_name / f"marshal_valid_{offset:08x}_skip{skip}.pyc"
                    fname.write_bytes(chunk)
                    self.logger.info(f"  [VALID MARSHAL] {ver_name} at 0x{offset:08x} skip={skip} size={test_size}")
                    return
                except:
                    continue

    def _extract_frozen_modules(self):
        self.logger.info("Searching for frozen module names...")
        frozen_dir = self.output_dir / "Dumps" / "frozen_modules"

        patterns = [
            rb'([A-Za-z0-9_/\\]+\.py)\x00',
            rb'__frozen__([A-Za-z0-9_]+)',
            rb'frozen_module_([A-Za-z0-9_]+)',
            rb'module_([a-z_]+)_frozen',
        ]

        found_modules = set()

        for data_source in [self.data, self.rsrc_data]:
            if not data_source:
                continue
            for pattern in patterns:
                for match in re.finditer(pattern, data_source):
                    try:
                        mod_name = match.group(1).decode('ascii', errors='replace')
                        mod_offset = match.start()
                        if 3 < len(mod_name) < 200:
                            found_modules.add((mod_name, mod_offset))
                    except:
                        pass

        for mod_name, mod_offset in found_modules:
            mod_end = min(mod_offset + 512, len(self.data))
            chunk = self.data[mod_offset:mod_end]
            safe_name = mod_name.replace('/', '_').replace('\\', '_').replace('.', '_')
            fname = frozen_dir / f"{safe_name}_{mod_offset:08x}.bin"
            fname.write_bytes(chunk)

        self.found_frozen_modules = list(found_modules)
        self.logger.info(f"  Frozen module candidates: {len(found_modules)}")

    def _extract_nuitka_constants(self):
        self.logger.info("Extracting Nuitka constant tables...")
        const_patterns = [
            rb'(?:PyObject\*|PyConst|constant_)[\x20-\x7e]{0,50}',
            rb'__constant_table_[\x20-\x7e]{0,50}',
        ]
        constants = []
        for pattern in const_patterns:
            for match in re.finditer(pattern, self.data):
                try:
                    val = match.group().decode('ascii', errors='replace')
                    constants.append(val)
                except:
                    pass
        self._write_list(self.output_dir / "Analysis" / "constants.txt", constants[:10000])

    def _extract_python_object_headers(self):
        self.logger.info("Scanning for Python object headers...")
        pyobj_dir = self.output_dir / "Dumps" / "memory" / "py_objects"
        struct_patterns = [
            b'PyObject', b'PyCode', b'PyTuple', b'PyDict', b'PyList',
            b'PyUnicode', b'PyBytes', b'PyModule',
        ]
        total = 0
        for pattern in struct_patterns:
            offset = 0
            while True:
                offset = self.data.find(pattern, offset)
                if offset == -1:
                    break
                if offset > 16 and offset + 128 <= len(self.data):
                    chunk = self.data[offset - 16:offset + 128]
                    pattern_name = pattern.decode('ascii', errors='replace')
                    fname = pyobj_dir / f"{pattern_name}_{offset:08x}.bin"
                    fname.write_bytes(chunk)
                    total += 1
                offset += len(pattern)
        self.logger.info(f"  Python object headers extracted: {total}")

    def _extract_source_paths(self):
        self.logger.info("Extracting source file paths...")
        paths = set()
        path_regexes = [
            rb'([A-Za-z]:\\[A-Za-z0-9_\\/\-\. ]{5,200})',
            rb'(/[A-Za-z0-9_\\/\-\. ]{5,200})',
            rb'([A-Za-z0-9_/\\]{3,}\.py)',
        ]

        sections_to_scan = ['.rdata', '.data']
        for section in self.pe.sections:
            name = section.Name.decode('utf-8', errors='replace').strip('\x00')
            if name in sections_to_scan:
                try:
                    section_data = section.get_data()
                    for regex in path_regexes:
                        for match in re.finditer(regex, section_data):
                            try:
                                p = match.group(1).decode('ascii', errors='strict')
                                p = p.strip('\x00').strip()
                                if p and len(p) > 5 and all(c in string.printable for c in p):
                                    paths.add(p)
                            except:
                                pass
                except:
                    pass

        self.extracted_paths.update(paths)
        self._write_list(self.output_dir / "Analysis" / "source_paths.txt", sorted(paths))
        self.logger.info(f"  Source paths found: {len(paths)}")

    def _extract_variable_names(self):
        self.logger.info("Extracting variable/function names...")
        var_patterns = [rb'([a-z_][a-z0-9_]{3,50})\x00']
        names = set()

        sections_to_scan = ['.rdata', '.data']
        for section in self.pe.sections:
            name = section.Name.decode('utf-8', errors='replace').strip('\x00')
            if name in sections_to_scan:
                try:
                    section_data = section.get_data()
                    for pattern in var_patterns:
                        for match in re.finditer(pattern, section_data, re.IGNORECASE):
                            try:
                                vname = match.group(1).decode('ascii', errors='replace')
                                if vname.isidentifier() and not vname.startswith('__'):
                                    names.add(vname)
                            except:
                                pass
                except:
                    pass

        names = {n for n in names if not n.startswith('0') and len(n) < 100}
        self._write_list(self.output_dir / "Analysis" / "variable_names.txt", sorted(names)[:5000])
        self.logger.info(f"  Variable names extracted: {len(names)}")

    def _extract_nuitka_onefile_payload(self):
        self.logger.info("Searching for Nuitka OneFile payload...")
        payload_dir = self.output_dir / "Dumps" / "payloads"
        decompressed_count = 0

        if self.rsrc_data and len(self.rsrc_data) > 0:
            self.logger.info(f"  Scanning .rsrc section ({len(self.rsrc_data):,} bytes, entropy: {self.rsrc_entropy:.2f}/8.0)")

            if HAS_ZSTD:
                decompressed_count += self._try_zstd_decompress(self.rsrc_data, payload_dir)
            else:
                self.logger.warning("  zstandard not available, install: pip install zstandard")

            decompressed_count += self._try_zlib_decompress(self.rsrc_data, payload_dir, ".rsrc")

        if decompressed_count == 0:
            self.logger.info("  No payloads decompressed from .rsrc")
        else:
            self.logger.info(f"  Total payloads decompressed: {decompressed_count}")

    def _try_zstd_decompress(self, data, payload_dir):
        zstd_magic = b'\x28\xb5\x2f\xfd'
        count = 0
        offset = 0
        tried = set()
        while True:
            offset = data.find(zstd_magic, offset)
            if offset == -1:
                break
            if offset in tried:
                offset += 4
                continue
            tried.add(offset)
            for window in [65536, 131072, 262144, 524288, 1048576, 2097152, 4194304]:
                if offset + window > len(data):
                    continue
                chunk = data[offset:offset + window]
                try:
                    dctx = zstd.ZstdDecompressor()
                    decompressed = dctx.decompress(chunk)
                    if len(decompressed) > 4096:
                        fname = payload_dir / f"zstd_decompressed_{offset:08x}.bin"
                        fname.write_bytes(decompressed)
                        count += 1
                        self.logger.info(f"  [PAYLOAD ZSTD] Decompressed {len(decompressed):,} bytes at 0x{offset:08x}")
                        self._scan_data_for_patterns(decompressed)
                except:
                    pass
            offset += 4
        return count

    def _try_zlib_decompress(self, data, payload_dir, source_name):
        zlib_sigs = [b'\x78\x9c', b'\x78\x01', b'\x78\xda', b'\x78\x5e']
        count = 0
        for sig in zlib_sigs:
            offset = 0
            tried = set()
            while True:
                offset = data.find(sig, offset)
                if offset == -1:
                    break
                if offset in tried:
                    offset += len(sig)
                    continue
                tried.add(offset)
                for window in [65536, 131072, 262144, 524288, 1048576]:
                    if offset + window > len(data):
                        continue
                    chunk = data[offset:offset + window]
                    try:
                        decompressed = zlib.decompress(chunk)
                        if len(decompressed) > 4096:
                            fname = payload_dir / f"zlib_decompressed_{source_name}_{offset:08x}.bin"
                            fname.write_bytes(decompressed)
                            count += 1
                            self.logger.info(f"  [PAYLOAD ZLIB] Decompressed {len(decompressed):,} bytes at 0x{offset:08x}")
                            self._scan_data_for_patterns(decompressed)
                    except:
                        pass
                offset += len(sig)
        return count

    def _dump_info(self):
        self.logger.info("Collecting metadata...")
        info_dir = self.output_dir / "Info"

        gen_info = []
        if self.pe:
            gen_info.append(f"File type: PE (Portable Executable)")
            gen_info.append(f"Architecture: {'x64' if self.pe.FILE_HEADER.Machine == 0x8664 else 'x86'}")
            gen_info.append(f"Subsystem: {'GUI' if self.pe.OPTIONAL_HEADER.Subsystem == 2 else 'Console'}")
            gen_info.append(f"Entry point: 0x{self.pe.OPTIONAL_HEADER.AddressOfEntryPoint:08x}")
            gen_info.append(f"Image base: 0x{self.pe.OPTIONAL_HEADER.ImageBase:016x}")
            gen_info.append(f"Number of sections: {len(self.pe.sections)}")
        else:
            gen_info.append(f"File type: Raw binary")
        gen_info.append(f"File size: {len(self.data):,} bytes ({len(self.data)/1024/1024:.2f} MB)")
        gen_info.append(f"Packager: {self.detected_packager or 'Unknown'}")

        pe_end = 0
        if self.pe:
            last = self.pe.sections[-1]
            pe_end = last.PointerToRawData + last.SizeOfRawData
        payload = len(self.data) - pe_end if pe_end > 0 else len(self.data)
        if payload == 0 and self.rsrc_data:
            payload = len(self.rsrc_data)
        gen_info.append(f"Payload size: {payload:,} bytes ({payload/1024/1024:.2f} MB)")
        gen_info.append(f"Payload compression: {str(payload < len(self.data) * 0.95).lower()}")
        if len(self.data) > 0:
            ratio = payload / len(self.data) * 100 if payload > 0 else 0
            gen_info.append(f"Compression ratio: {ratio:.1f}%")
        gen_info.append(f"Timestamp: {datetime.datetime.fromtimestamp(self.pe.FILE_HEADER.TimeDateStamp) if self.pe else 'N/A'}")
        self._write_list(info_dir / "general.txt", gen_info)

        if self.pe:
            pe_hdr = self.pe.dump_info()
            (info_dir / "pe_header.txt").write_text(pe_hdr, encoding='utf-8')

            sec_info = []
            for sec in self.pe.sections:
                name = sec.Name.decode('utf-8', errors='replace').strip('\x00')
                ent = self._calc_entropy(sec.get_data()) if sec.SizeOfRawData > 0 else 0
                sec_info.append(f"{name}: VA=0x{sec.VirtualAddress:08x} RawSize={sec.SizeOfRawData:,} VirtSize={sec.Misc_VirtualSize:,} Entropy={ent:.2f}/8.0 Rights=0x{sec.Characteristics:08x}")
            self._write_list(info_dir / "sections.txt", sec_info)

            imports = []
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode('utf-8', errors='replace')
                    for imp in entry.imports:
                        if imp.name:
                            imports.append(f"{dll}: {imp.name.decode('utf-8', errors='replace')}")
            self._write_list(info_dir / "imports.txt", imports)

            python_imports = [i for i in imports if 'Py' in i or 'python' in i.lower()]
            self._write_list(info_dir / "imports_python.txt", python_imports)

            exports = []
            if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        exports.append(exp.name.decode('utf-8', errors='replace'))
            self._write_list(info_dir / "exports.txt", exports)

            compiler = "Unknown"
            if b'GCC' in self.data or b'MinGW' in self.data or b'gcc' in self.data:
                compiler = "MinGW GCC"
            elif b'MSVC' in self.data or b'cl.exe' in self.data:
                compiler = "MSVC"
            elif b'Clang' in self.data or b'LLVM' in self.data:
                compiler = "Clang/LLVM"

            prot = []
            if self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100:
                prot.append("DEP enabled")
            if self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040:
                prot.append("ASLR enabled")
            if self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0080:
                prot.append("High Entropy ASLR (64-bit)")
            if hasattr(self.pe, 'DIRECTORY_ENTRY_SECURITY'):
                try:
                    if self.pe.DIRECTORY_ENTRY_SECURITY:
                        prot.append("Digitally signed")
                except:
                    pass
            self._write_list(info_dir / "protection.txt", prot)

        if self.detected_python:
            (info_dir / "python_version.txt").write_text(f"Python version: {self.detected_python}")
        if self.detected_nuitka:
            (info_dir / "nuitka_version.txt").write_text(f"Nuitka: detected\nPackager: {self.detected_packager}")

    def _dump_hashes(self):
        self.logger.info("Calculating hashes...")
        hashes = []
        hashes.append(f"MD5:    {hashlib.md5(self.data).hexdigest()}")
        hashes.append(f"SHA1:   {hashlib.sha1(self.data).hexdigest()}")
        hashes.append(f"SHA256: {hashlib.sha256(self.data).hexdigest()}")
        self._write_list(self.output_dir / "Info" / "hashes.txt", hashes)

    def _dump_entropy(self):
        self.logger.info("Calculating entropy...")
        entropy_lines = []
        if self.pe:
            for sec in self.pe.sections:
                name = sec.Name.decode('utf-8', errors='replace').strip('\x00')
                try:
                    data = sec.get_data()
                    ent = self._calc_entropy(data)
                    entropy_lines.append(f"{name}: entropy={ent:.2f}/8.0 ({len(data):,} bytes)")
                except:
                    pass
        else:
            ent = self._calc_entropy(self.data)
            entropy_lines.append(f"Full file: entropy={ent:.2f}/8.0")
        self._write_list(self.output_dir / "Info" / "entropy.txt", entropy_lines)

    def _calc_entropy(self, data):
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counter.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _dump_disasm(self):
        if capstone is None:
            self.logger.warning("Capstone not installed. Skipping disassembly.")
            return
        if not self.pe:
            return
        self.logger.info("Disassembling...")
        disasm_dir = self.output_dir / "Disasm"

        try:
            md_x86 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

            ep_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            ep_offset = self.pe.get_offset_from_rva(ep_rva)
            if ep_offset is None:
                ep_offset = self.pe.get_offset_from_rva(ep_rva - self.pe.OPTIONAL_HEADER.ImageBase)

            if ep_offset and ep_offset + 4096 <= len(self.data):
                code = self.data[ep_offset:ep_offset + 4096]
                lines = []
                for insn in md_x86.disasm(code, ep_rva + self.pe.OPTIONAL_HEADER.ImageBase):
                    lines.append(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
                self._write_list(disasm_dir / "entry_point.asm", lines)

            for section in self.pe.sections:
                name = section.Name.decode('utf-8', errors='replace').strip('\x00')
                if b'.text' in section.Name or name == 'CODE':
                    try:
                        data = section.get_data()[:8192]
                        lines = []
                        for insn in md_x86.disasm(data, section.VirtualAddress + self.pe.OPTIONAL_HEADER.ImageBase):
                            lines.append(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
                        self._write_list(disasm_dir / f"section_{name}.asm", lines[:500])
                    except:
                        pass
        except Exception as e:
            self.logger.warning(f"  Disassembly failed: {e}")

    def _dump_analysis(self):
        self.logger.info("Running analysis...")
        analysis_dir = self.output_dir / "Analysis"

        if self.found_bytecodes:
            bc_map = []
            for ver, offset, ctx in self.found_bytecodes:
                bc_map.append(f"{ver}: offset=0x{offset:08x} context={ctx}")
            self._write_list(analysis_dir / "bytecode_map.txt", bc_map)

            versions = Counter(v for v, _, _ in self.found_bytecodes)
            if versions:
                python_ver = versions.most_common(1)[0][0]
                self.detected_python = python_ver
                (analysis_dir / "python_version.txt").write_text(f"Python version: {python_ver}")

        if self.found_frozen_modules:
            frozen_list = [f"{name} @ 0x{offset:08x}" for name, offset in self.found_frozen_modules]
            self._write_list(analysis_dir / "frozen_modules.txt", frozen_list)

        if self.extracted_modules:
            self._write_list(analysis_dir / "module_list.txt", sorted(self.extracted_modules))

    def _dump_suspicious(self):
        self.logger.info("Scanning for suspicious patterns...")
        susp_dir = self.output_dir / "Suspicious"

        anti_debug_found = []
        for api in ANTI_DEBUG_APIS:
            if api in self.data:
                anti_debug_found.append(api.decode('ascii'))
        if anti_debug_found:
            self._write_list(susp_dir / "anti_debug" / "found.txt", anti_debug_found)
            self.logger.warning(f"  Anti-debug APIs: {len(anti_debug_found)} found")

        if self.pe:
            packed = []
            for sec in self.pe.sections:
                name = sec.Name.decode('utf-8', errors='replace').strip('\x00')
                if sec.SizeOfRawData > 0 and sec.Misc_VirtualSize > 0:
                    ratio = sec.Misc_VirtualSize / sec.SizeOfRawData
                    if ratio > 1.5 or ratio < 0.5:
                        packed.append(f"{name}: raw={sec.SizeOfRawData} virt={sec.Misc_VirtualSize} ratio={ratio:.2f}")
            if packed:
                self._write_list(susp_dir / "packed_sections" / "packed.txt", packed)

        high_entropy_blocks = []
        if self.pe:
            for sec in self.pe.sections:
                try:
                    data = sec.get_data()
                    ent = self._calc_entropy(data)
                    if ent > 7.0:
                        name = sec.Name.decode('utf-8', errors='replace').strip('\x00')
                        high_entropy_blocks.append(f"{name}: entropy={ent:.2f}/8.0 ({len(data):,} bytes)")
                except:
                    pass
        if high_entropy_blocks:
            self._write_list(susp_dir / "encrypted_blocks" / "high_entropy.txt", high_entropy_blocks)

    def _dump_compressed_blocks(self):
        self.logger.info("Scanning for compressed blocks in .rsrc only...")
        comp_dir = self.output_dir / "Suspicious" / "compressed_blocks"

        comp_signatures = {
            b'\x78\x9c': 'zlib_default', b'\x78\x01': 'zlib_none',
            b'\x78\xda': 'zlib_best', b'\x1f\x8b\x08': 'gzip',
            b'BZh': 'bzip2', b'\xfd7zXZ\x00': 'lzma',
            b'\x50\x4b\x03\x04': 'zip',
        }

        search_data = self.rsrc_data if self.rsrc_data else self.data
        found = []
        for sig, name in comp_signatures.items():
            offset = 0
            while True:
                offset = search_data.find(sig, offset)
                if offset == -1:
                    break
                if self.rsrc_data:
                    actual_offset = self.rsrc_start + offset
                    if not self._is_in_section(actual_offset, '.rsrc'):
                        offset += len(sig)
                        continue
                found.append(f"{name} at 0x{offset:08x}")
                try:
                    chunk = search_data[offset:offset + 65536]
                    fname = comp_dir / f"{name}_{offset:08x}.bin"
                    fname.write_bytes(chunk)
                except:
                    pass
                offset += len(sig)

        if found:
            self._write_list(comp_dir / "found.txt", found)
            self.logger.info(f"  Compressed blocks in .rsrc: {len(found)}")
        else:
            self.logger.info("  No compressed blocks found in .rsrc")

    def _write_log_copy(self):
        try:
            log_dest = self.output_dir / f"{self.output_dir.name}.log"
            if hasattr(self.logger, 'log_file') and self.logger.log_file.name != str(log_dest):
                shutil.copy(self.logger.log_file.name, log_dest)
        except:
            pass

    def _write_summary(self):
        self.logger.info("Writing summary...")
        summary = []
        summary.append("╔══════════════════════════════════════════════════════════╗")
        summary.append(f"║         DeNuitkanizator v{VERSION} - Analysis Report        ║")
        summary.append("╚══════════════════════════════════════════════════════════╝")
        summary.append("")
        summary.append(f"Target:         {self.filepath.name}")
        summary.append(f"Analysis date:  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        summary.append(f"Duration:       {self.logger.elapsed():.1f} sec")
        summary.append("")
        summary.append("─" * 54)
        summary.append(" GENERAL")
        summary.append("─" * 54)

        if self.pe:
            summary.append(f"File type:              PE (Portable Executable)")
            summary.append(f"Architecture:           {'x64' if self.pe.FILE_HEADER.Machine == 0x8664 else 'x86'}")
        else:
            summary.append(f"File type:              Raw binary")
        summary.append(f"File size:              {len(self.data):,} bytes ({len(self.data)/1024/1024:.2f} MB)")

        pe_end = 0
        if self.pe:
            last = self.pe.sections[-1]
            pe_end = last.PointerToRawData + last.SizeOfRawData
        payload = len(self.data) - pe_end if pe_end > 0 else len(self.data)
        if payload == 0 and self.rsrc_data:
            payload = len(self.rsrc_data)
        summary.append(f"Payload size:           {payload:,} bytes ({payload/1024/1024:.2f} MB)")
        summary.append(f"Payload compression:    {str(payload < len(self.data) * 0.95).lower()}")
        if len(self.data) > 0:
            ratio = payload / len(self.data) * 100 if payload > 0 else 0
            summary.append(f"Compression ratio:      {ratio:.1f}%")

        summary.append("")
        summary.append("─" * 54)
        summary.append(" HASHES")
        summary.append("─" * 54)
        summary.append(f"MD5:        {hashlib.md5(self.data).hexdigest()}")
        summary.append(f"SHA1:       {hashlib.sha1(self.data).hexdigest()}")
        summary.append(f"SHA256:     {hashlib.sha256(self.data).hexdigest()}")

        summary.append("")
        summary.append("─" * 54)
        summary.append(" PACKER")
        summary.append("─" * 54)
        summary.append(f"Detected:               {self.detected_packager or 'Unknown'}")
        if self.detected_python:
            summary.append(f"Python:                 {self.detected_python}")
        compiler = "Unknown"
        if self.pe:
            if b'GCC' in self.data or b'MinGW' in self.data:
                compiler = "MinGW GCC"
            elif b'MSVC' in self.data:
                compiler = "MSVC"
        summary.append(f"Compiler:               {compiler}")

        summary.append("")
        summary.append("─" * 54)
        summary.append(" BYTECODE / MAGIC")
        summary.append("─" * 54)
        total_bc = len(self.found_bytecodes)
        summary.append(f"Found:                  {total_bc} magic contexts")
        for ver in PYTHON_MAGICS.values():
            count = sum(1 for v, _, _ in self.found_bytecodes if v == ver)
            if count > 0:
                summary.append(f"  {ver}:                 {count} contexts")

        summary.append("")
        summary.append("─" * 54)
        summary.append(" FROZEN MODULES")
        summary.append("─" * 54)
        summary.append(f"Found:                  {len(self.found_frozen_modules)} candidates")
        for name, _ in self.found_frozen_modules[:10]:
            summary.append(f"  {name}")

        summary.append("")
        summary.append("─" * 54)
        summary.append(" STRINGS / MODULES")
        summary.append("─" * 54)
        summary.append(f"Total strings:          {len(set(self.extracted_strings))}")
        summary.append(f"Modules found:          {len(self.extracted_modules)}")
        summary.append(f"IPs found:              {len(self.extracted_ips)}")
        summary.append(f"URLs found:             {len(self.extracted_urls)}")
        summary.append(f"Paths found:            {len(self.extracted_paths)}")

        summary.append("")
        summary.append("─" * 54)
        summary.append(" SECTIONS")
        summary.append("─" * 54)
        if self.pe:
            summary.append(f"{'Name':<12} {'Size':<12} {'Entropy'}")
            for sec in self.pe.sections:
                name = sec.Name.decode('utf-8', errors='replace').strip('\x00')[:11]
                try:
                    ent = self._calc_entropy(sec.get_data())
                except:
                    ent = 0.0
                summary.append(f"{name:<12} {sec.SizeOfRawData:>10,}  {ent:.1f}")

        summary.append("")
        summary.append("─" * 54)
        summary.append(" WARNINGS")
        summary.append("─" * 54)
        if not self.detected_nuitka and self.detected_packager and self.detected_packager != "Nuitka" and "Nuitka" not in str(self.detected_packager):
            summary.append(f"[WARNING] Not a Nuitka file. Detected: {self.detected_packager}")
        if self.pe:
            for sec in self.pe.sections:
                try:
                    ent = self._calc_entropy(sec.get_data())
                    if ent > 7.5:
                        sec_name = sec.Name.decode('utf-8', errors='replace').strip('\x00')
                        summary.append(f"[WARNING] High entropy in {sec_name}")
                except:
                    pass
        if not HAS_ZSTD:
            summary.append("[WARNING] zstandard not installed. Install: pip install zstandard")

        summary.append("")
        summary.append("─" * 54)
        summary.append(" OUTPUT")
        summary.append("─" * 54)
        summary.append(f"Full report:    {self.output_dir}")
        summary.append("")
        summary.append("─" * 54)
        summary.append(" EXIT CODE: 0 (Success)")
        summary.append("─" * 54)

        (self.output_dir / "summary.txt").write_text("\n".join(summary), encoding='utf-8')

    def _write_list(self, path, items):
        if items:
            path.write_text("\n".join(sorted(set(items))), encoding='utf-8')

    def _fatal_error(self, code, msg=None):
        errors = {
            1: "File not found or inaccessible. Try to double-check the file path or whether the file exists.",
            2: "You are using an unsupported version of Python (only 3.7, 3.8, 3.9, 3.10, 3.11) or it is modified.",
            3: "Unpacking the .exe file compiled through Nuitka failed:",
            4: "An unknown error has occurred. Probably the .exe file is broken or the .exe file is built by a custom Nuitka fork, or the file is intentionally corrupted, but the program cannot read or unpack it.",
        }
        base = errors.get(code, "Unknown error")
        if code == 3 and msg:
            base = f"{base} {msg}"
        elif code == 2 and msg:
            base = f"{base} Detected: {msg}"
        print(f"\n{Back.RED}{Fore.WHITE} FATAL Error {code}. {base} {Style.RESET_ALL}")
        sys.exit(code)


def main():
    if len(sys.argv) > 1:
        target = sys.argv[1]
        dumper = NuitkaDumper(target)
        dumper.run()
    else:
        dumper = NuitkaDumper("")
        dumper.run()


if __name__ == "__main__":
    main()