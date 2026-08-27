from dataclasses import dataclass, field
from typing import List, Optional
import os
import sqlite3
import hashlib
import struct
import subprocess
import tempfile
import shutil
import zlib
import unicodedata

# ========================= CONFIG =========================
VDM_DIR = r"D:\Vex0\CTF\TEST\Windef\target_version"
BASE_VDM_PATH = os.path.join(VDM_DIR, "mpasbase.vdm")
DELTA_VDM_PATH = os.path.join(VDM_DIR, "mpasdlta.vdm")
BASE_DECOMPRESSED_PATH = None   # None -> <base_vdm_basename>.decompressed
DELTA_DECOMPRESSED_PATH = None  # None -> <delta_vdm_basename>.decompressed
MERGED_DECOMPRESSED_PATH = None # None -> <base_vdm_basename>_merged.decompressed
OUTPUT_DB = None                # None -> <merged_basename>.db
WEIGHT_LOG_FILE = None          # None -> <merged_basename>_WeightAnomaly.log
MERGE_VERBOSE = True
DELETE_BASE_DELTA_DECOMPRESSED_AFTER_PARSE = True

# LUASTANDALONE:
# Each RuleData contains one structured blob:
#   BYTE  nameLength;
#   BYTE  Category;
#   WORD  sizeofMetaData;
#   DWORD sizeofMPLua;
#   BYTE  name[nameLength];
#   BYTE  MetaData[sizeofMetaData];
#   BYTE  MPLUA[sizeofMPLua];
#
# MPLUA is temporarily written to lua_drop/<RuleId>.mplua, normalized to
# lua_drop/<RuleId>.luac, then decompiled by cLuaDecompiler.
# The temporary .mplua file is deleted after processing; only .luac remains.
# Decompiled Lua source is cached in SQLite by RuleId so an existing .luac can
# be reused on later runs without invoking cLuaDecompiler again.
# lua_drop is created next to the output SQLite database.
LUA_DECOMPILER_PATH = r"cLuaDecompiler.exe"
LUA_DECOMPILER_TIMEOUT = 30
# ==========================================================

SIGNATURE_TYPES = {
    0x01: "SIGNATURE_TYPE_RESERVED",
    0x02: "SIGNATURE_TYPE_VOLATILE_THREAT_INFO",
    0x03: "SIGNATURE_TYPE_VOLATILE_THREAT_ID",
    0x11: "SIGNATURE_TYPE_CKOLDREC",
    0x20: "SIGNATURE_TYPE_KVIR32",
    0x21: "SIGNATURE_TYPE_POLYVIR32",
    0x27: "SIGNATURE_TYPE_NSCRIPT_NORMAL",
    0x28: "SIGNATURE_TYPE_NSCRIPT_SP",
    0x29: "SIGNATURE_TYPE_NSCRIPT_BRUTE",
    0x2C: "SIGNATURE_TYPE_NSCRIPT_CURE",
    0x30: "SIGNATURE_TYPE_TITANFLT",
    0x3D: "SIGNATURE_TYPE_PEFILE_CURE",
    0x3E: "SIGNATURE_TYPE_MAC_CURE",
    0x40: "SIGNATURE_TYPE_SIGTREE",
    0x41: "SIGNATURE_TYPE_SIGTREE_EXT",
    0x42: "SIGNATURE_TYPE_MACRO_PCODE",
    0x43: "SIGNATURE_TYPE_MACRO_SOURCE",
    0x44: "SIGNATURE_TYPE_BOOT",
    0x49: "SIGNATURE_TYPE_CLEANSCRIPT",
    0x4A: "SIGNATURE_TYPE_TARGET_SCRIPT",
    0x50: "SIGNATURE_TYPE_CKSIMPLEREC",
    0x51: "SIGNATURE_TYPE_PATTMATCH",
    0x53: "SIGNATURE_TYPE_RPFROUTINE",
    0x55: "SIGNATURE_TYPE_NID",
    0x56: "SIGNATURE_TYPE_GENSFX",
    0x57: "SIGNATURE_TYPE_UNPLIB",
    0x58: "SIGNATURE_TYPE_DEFAULTS",
    0x5B: "SIGNATURE_TYPE_DBVAR",
    0x5C: "SIGNATURE_TYPE_THREAT_BEGIN",
    0x5D: "SIGNATURE_TYPE_THREAT_END",
    0x5E: "SIGNATURE_TYPE_FILENAME",
    0x5F: "SIGNATURE_TYPE_FILEPATH",
    0x60: "SIGNATURE_TYPE_FOLDERNAME",
    0x61: "SIGNATURE_TYPE_PEHSTR",
    0x62: "SIGNATURE_TYPE_LOCALHASH",
    0x63: "SIGNATURE_TYPE_REGKEY",
    0x64: "SIGNATURE_TYPE_HOSTSENTRY",
    0x67: "SIGNATURE_TYPE_STATIC",
    0x69: "SIGNATURE_TYPE_LATENT_THREAT",
    0x6A: "SIGNATURE_TYPE_REMOVAL_POLICY",
    0x6B: "SIGNATURE_TYPE_WVT_EXCEPTION",
    0x6C: "SIGNATURE_TYPE_REVOKED_CERTIFICATE",
    0x70: "SIGNATURE_TYPE_TRUSTED_PUBLISHER",
    0x71: "SIGNATURE_TYPE_ASEP_FILEPATH",
    0x73: "SIGNATURE_TYPE_DELTA_BLOB",
    0x74: "SIGNATURE_TYPE_DELTA_BLOB_RECINFO",
    0x75: "SIGNATURE_TYPE_ASEP_FOLDERNAME",
    0x77: "SIGNATURE_TYPE_PATTMATCH_V2",
    0x78: "SIGNATURE_TYPE_PEHSTR_EXT",
    0x79: "SIGNATURE_TYPE_VDLL_X86",
    0x7A: "SIGNATURE_TYPE_VERSIONCHECK",
    0x7B: "SIGNATURE_TYPE_SAMPLE_REQUEST",
    0x7C: "SIGNATURE_TYPE_VDLL_X64",
    0x7E: "SIGNATURE_TYPE_SNID",
    0x7F: "SIGNATURE_TYPE_FOP",
    0x80: "SIGNATURE_TYPE_KCRCE",
    0x83: "SIGNATURE_TYPE_VFILE",
    0x84: "SIGNATURE_TYPE_SIGFLAGS",
    0x85: "SIGNATURE_TYPE_PEHSTR_EXT2",
    0x86: "SIGNATURE_TYPE_PEMAIN_LOCATOR",
    0x87: "SIGNATURE_TYPE_PESTATIC",
    0x88: "SIGNATURE_TYPE_UFSP_DISABLE",
    0x89: "SIGNATURE_TYPE_FOPEX",
    0x8A: "SIGNATURE_TYPE_PEPCODE",
    0x8B: "SIGNATURE_TYPE_IL_PATTERN",
    0x8C: "SIGNATURE_TYPE_ELFHSTR_EXT",
    0x8D: "SIGNATURE_TYPE_MACHOHSTR_EXT",
    0x8E: "SIGNATURE_TYPE_DOSHSTR_EXT",
    0x8F: "SIGNATURE_TYPE_MACROHSTR_EXT",
    0x90: "SIGNATURE_TYPE_TARGET_SCRIPT_PCODE",
    0x91: "SIGNATURE_TYPE_VDLL_IA64",
    0x95: "SIGNATURE_TYPE_PEBMPAT",
    0x96: "SIGNATURE_TYPE_AAGGREGATOR",
    0x97: "SIGNATURE_TYPE_SAMPLE_REQUEST_BY_NAME",
    0x98: "SIGNATURE_TYPE_REMOVAL_POLICY_BY_NAME",
    0x99: "SIGNATURE_TYPE_TUNNEL_X86",
    0x9A: "SIGNATURE_TYPE_TUNNEL_X64",
    0x9B: "SIGNATURE_TYPE_TUNNEL_IA64",
    0x9C: "SIGNATURE_TYPE_VDLL_ARM",
    0x9D: "SIGNATURE_TYPE_THREAD_X86",
    0x9E: "SIGNATURE_TYPE_THREAD_X64",
    0x9F: "SIGNATURE_TYPE_THREAD_IA64",
    0xA0: "SIGNATURE_TYPE_FRIENDLYFILE_SHA256",
    0xA1: "SIGNATURE_TYPE_FRIENDLYFILE_SHA512",
    0xA2: "SIGNATURE_TYPE_SHARED_THREAT",
    0xA3: "SIGNATURE_TYPE_VDM_METADATA",
    0xA4: "SIGNATURE_TYPE_VSTORE",
    0xA5: "SIGNATURE_TYPE_VDLL_SYMINFO",
    0xA6: "SIGNATURE_TYPE_IL2_PATTERN",
    0xA7: "SIGNATURE_TYPE_BM_STATIC",
    0xA8: "SIGNATURE_TYPE_BM_INFO",
    0xA9: "SIGNATURE_TYPE_NDAT",
    0xAA: "SIGNATURE_TYPE_FASTPATH_DATA",
    0xAB: "SIGNATURE_TYPE_FASTPATH_SDN",
    0xAC: "SIGNATURE_TYPE_DATABASE_CERT",
    0xAD: "SIGNATURE_TYPE_SOURCE_INFO",
    0xAE: "SIGNATURE_TYPE_HIDDEN_FILE",
    0xAF: "SIGNATURE_TYPE_COMMON_CODE",
    0xB0: "SIGNATURE_TYPE_VREG",
    0xB1: "SIGNATURE_TYPE_NISBLOB",
    0xB2: "SIGNATURE_TYPE_VFILEEX",
    0xB3: "SIGNATURE_TYPE_SIGTREE_BM",
    0xB4: "SIGNATURE_TYPE_VBFOP",
    0xB5: "SIGNATURE_TYPE_VDLL_META",
    0xB6: "SIGNATURE_TYPE_TUNNEL_ARM",
    0xB7: "SIGNATURE_TYPE_THREAD_ARM",
    0xB8: "SIGNATURE_TYPE_PCODEVALIDATOR",
    0xBA: "SIGNATURE_TYPE_MSILFOP",
    0xBB: "SIGNATURE_TYPE_KPAT",
    0xBC: "SIGNATURE_TYPE_KPATEX",
    0xBD: "SIGNATURE_TYPE_LUASTANDALONE",
    0xBE: "SIGNATURE_TYPE_DEXHSTR_EXT",
    0xBF: "SIGNATURE_TYPE_JAVAHSTR_EXT",
    0xC0: "SIGNATURE_TYPE_MAGICCODE",
    0xC1: "SIGNATURE_TYPE_CLEANSTORE_RULE",
    0xC2: "SIGNATURE_TYPE_VDLL_CHECKSUM",
    0xC3: "SIGNATURE_TYPE_THREAT_UPDATE_STATUS",
    0xC4: "SIGNATURE_TYPE_VDLL_MSIL",
    0xC5: "SIGNATURE_TYPE_ARHSTR_EXT",
    0xC6: "SIGNATURE_TYPE_MSILFOPEX",
    0xC7: "SIGNATURE_TYPE_VBFOPEX",
    0xC8: "SIGNATURE_TYPE_FOP64",
    0xC9: "SIGNATURE_TYPE_FOPEX64",
    0xCA: "SIGNATURE_TYPE_JSINIT",
    0xCB: "SIGNATURE_TYPE_PESTATICEX",
    0xCC: "SIGNATURE_TYPE_KCRCEX",
    0xCD: "SIGNATURE_TYPE_FTRIE_POS",
    0xCE: "SIGNATURE_TYPE_NID64",
    0xCF: "SIGNATURE_TYPE_MACRO_PCODE64",
    0xD0: "SIGNATURE_TYPE_BRUTE",
    0xD1: "SIGNATURE_TYPE_SWFHSTR_EXT",
    0xD2: "SIGNATURE_TYPE_REWSIGS",
    0xD3: "SIGNATURE_TYPE_AUTOITHSTR_EXT",
    0xD4: "SIGNATURE_TYPE_INNOHSTR_EXT",
    0xD5: "SIGNATURE_TYPE_CERT_STORE_ENTRY",
    0xD6: "SIGNATURE_TYPE_EXPLICITRESOURCE",
    0xD7: "SIGNATURE_TYPE_CMDHSTR_EXT",
    0xD8: "SIGNATURE_TYPE_FASTPATH_TDN",
    0xD9: "SIGNATURE_TYPE_EXPLICITRESOURCEHASH",
    0xDA: "SIGNATURE_TYPE_FASTPATH_SDN_EX",
    0xDB: "SIGNATURE_TYPE_BLOOM_FILTER",
    0xDC: "SIGNATURE_TYPE_RESEARCH_TAG",
    0xDE: "SIGNATURE_TYPE_ENVELOPE",
    0xDF: "SIGNATURE_TYPE_REMOVAL_POLICY64",
    0xE0: "SIGNATURE_TYPE_REMOVAL_POLICY64_BY_NAME",
    0xE1: "SIGNATURE_TYPE_VDLL_META_X64",
    0xE2: "SIGNATURE_TYPE_VDLL_META_ARM",
    0xE3: "SIGNATURE_TYPE_VDLL_META_MSIL",
    0xE4: "SIGNATURE_TYPE_MDBHSTR_EXT",
    0xE5: "SIGNATURE_TYPE_SNIDEX",
    0xE6: "SIGNATURE_TYPE_SNIDEX2",
    0xE7: "SIGNATURE_TYPE_AAGGREGATOREX",
    0xE8: "SIGNATURE_TYPE_PUA_APPMAP",
    0xE9: "SIGNATURE_TYPE_PROPERTY_BAG",
    0xEA: "SIGNATURE_TYPE_DMGHSTR_EXT",
    0xEB: "SIGNATURE_TYPE_DATABASE_CATALOG",
    0xEC: "SIGNATURE_TYPE_DATABASE_CERT2",
    0xED: "SIGNATURE_TYPE_BM_ENV_VAR_MAP",
}


class VDMExtractor:
    RT_RCDATA = 10
    @staticmethod
    def _u16(data, off):
        if off < 0 or off + 2 > len(data):
            raise ValueError(f"Truncated uint16 at file offset 0x{off:X}")
        return struct.unpack_from("<H", data, off)[0]
    @staticmethod
    def _u32(data, off):
        if off < 0 or off + 4 > len(data):
            raise ValueError(f"Truncated uint32 at file offset 0x{off:X}")
        return struct.unpack_from("<I", data, off)[0]
    @classmethod
    def _parse_pe(cls, data):
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise ValueError("Input is not a PE file (missing MZ header)")
        pe_off = cls._u32(data, 0x3C)
        if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\x00\x00":
            raise ValueError("Input is not a valid PE file (missing PE signature)")
        coff = pe_off + 4
        section_count = cls._u16(data, coff + 2)
        optional_size = cls._u16(data, coff + 16)
        optional = coff + 20
        if optional + optional_size > len(data):
            raise ValueError("Truncated PE optional header")
        magic = cls._u16(data, optional)
        if magic == 0x10B:
            data_directory = optional + 96
        elif magic == 0x20B:
            data_directory = optional + 112
        else:
            raise ValueError(f"Unsupported PE optional-header magic 0x{magic:04X}")
        if data_directory + 8 * 3 > optional + optional_size:
            raise ValueError("PE has no resource data-directory entry")
        resource_rva = cls._u32(data, data_directory + 8 * 2)
        resource_size = cls._u32(data, data_directory + 8 * 2 + 4)
        if resource_rva == 0 or resource_size == 0:
            raise ValueError("PE has no resource directory")
        section_table = optional + optional_size
        sections = []
        for i in range(section_count):
            off = section_table + i * 40
            if off + 40 > len(data):
                raise ValueError("Truncated PE section table")
            name = data[off:off + 8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
            virtual_size = cls._u32(data, off + 8)
            virtual_address = cls._u32(data, off + 12)
            raw_size = cls._u32(data, off + 16)
            raw_offset = cls._u32(data, off + 20)
            sections.append((name, virtual_address, virtual_size, raw_offset, raw_size))
        def rva_to_offset(rva):
            for _, va, vs, raw, raw_size in sections:
                span = max(vs, raw_size)
                if va <= rva < va + span:
                    delta = rva - va
                    if delta >= raw_size:
                        raise ValueError(f"RVA 0x{rva:X} points outside section raw data")
                    return raw + delta
            if rva < len(data):
                return rva
            raise ValueError(f"Unable to map RVA 0x{rva:X} to file offset")
        return resource_rva, resource_size, rva_to_offset
    @classmethod
    def extract_rcdata(cls, data):
        resource_rva, resource_size, rva_to_offset = cls._parse_pe(data)
        resource_base = rva_to_offset(resource_rva)
        resource_limit = min(len(data), resource_base + resource_size)
        def dir_entries(rel):
            directory = resource_base + rel
            if directory < resource_base or directory + 16 > resource_limit:
                raise ValueError(f"Invalid resource directory offset 0x{rel:X}")
            count = cls._u16(data, directory + 12) + cls._u16(data, directory + 14)
            entries = []
            for i in range(count):
                off = directory + 16 + i * 8
                if off + 8 > resource_limit:
                    raise ValueError("Truncated resource directory entry")
                entries.append((cls._u32(data, off), cls._u32(data, off + 4)))
            return entries
        def entry_name(raw):
            if not (raw & 0x80000000):
                return raw & 0xFFFF
            rel = raw & 0x7FFFFFFF
            off = resource_base + rel
            if off < resource_base or off + 2 > resource_limit:
                return f"<bad-name@0x{rel:X}>"
            length = cls._u16(data, off)
            end = off + 2 + length * 2
            if end > resource_limit:
                return f"<bad-name@0x{rel:X}>"
            return data[off + 2:end].decode("utf-16le", errors="replace")
        def collect_payloads(target, out):
            if not (target & 0x80000000):
                child = target & 0x7FFFFFFF
                entry = resource_base + child
                if entry < resource_base or entry + 16 > resource_limit:
                    raise ValueError(f"Invalid resource data-entry offset 0x{child:X}")
                payload_rva = cls._u32(data, entry)
                payload_size = cls._u32(data, entry + 4)
                payload_off = rva_to_offset(payload_rva)
                if payload_off + payload_size > len(data):
                    raise ValueError("Resource payload exceeds PE file size")
                out.append(data[payload_off:payload_off + payload_size])
                return
            rel = target & 0x7FFFFFFF
            for _, child_target in dir_entries(rel):
                collect_payloads(child_target, out)
        def is_rmdx_candidate(blob):
            if len(blob) < 28:
                return False
            n = cls._u32(blob, 24)
            compressed_offset = 8 + n
            if compressed_offset >= len(blob):
                return False
            try:
                zlib.decompress(blob[compressed_offset:], -zlib.MAX_WBITS)
                return True
            except zlib.error:
                return False
        root_entries = dir_entries(0)
        root_types = [(entry_name(name), target) for name, target in root_entries]
        preferred = []
        for type_name, target in root_types:
            is_rcdata = type_name == cls.RT_RCDATA or (isinstance(type_name, str) and type_name.upper() in ("RCDATA", "RT_RCDATA"))
            if is_rcdata:
                collect_payloads(target, preferred)
        valid_preferred = [blob for blob in preferred if is_rmdx_candidate(blob)]
        if valid_preferred:
            return max(valid_preferred, key=len)
        if preferred:
            return max(preferred, key=len)
        fallback = []
        for _, target in root_types:
            payloads = []
            collect_payloads(target, payloads)
            fallback.extend(blob for blob in payloads if is_rmdx_candidate(blob))
        if fallback:
            return max(fallback, key=len)
        available = ", ".join(repr(name) for name, _ in root_types) or "<none>"
        raise ValueError(f"RT_RCDATA/RMDX resource not found. Available root resource types: {available}")
    @classmethod
    def unpack_vdm(cls, path):
        with open(path, "rb") as f:
            pe_data = f.read()
        rmdx = cls.extract_rcdata(pe_data)
        if len(rmdx) < 28:
            raise ValueError(f"RT_RCDATA is too short for RMDX header: {len(rmdx)} byte(s)")
        n = cls._u32(rmdx, 24)
        compressed_offset = 8 + n
        if compressed_offset >= len(rmdx):
            raise ValueError(f"Invalid RMDX compressed offset: 8 + 0x{n:X} = 0x{compressed_offset:X}, RMDX size=0x{len(rmdx):X}")
        compressed = rmdx[compressed_offset:]
        try:
            decompressed = zlib.decompress(compressed, -zlib.MAX_WBITS)
        except zlib.error as e:
            raise ValueError(f"Raw-deflate decompression failed at RMDX offset 0x{compressed_offset:X}: {e}") from e
        return decompressed, len(rmdx), n, compressed_offset

class DeltaMerger:
    SIG_DELTA_BLOB = 0x73
    SIG_DELTA_BLOB_RECINFO = 0x74
    @staticmethod
    def _u16(buf, off):
        return struct.unpack_from("<H", buf, off)[0]
    @staticmethod
    def _u32(buf, off):
        return struct.unpack_from("<I", buf, off)[0]
    @classmethod
    def _sig_size(cls, buf, off):
        if off + 4 > len(buf):
            raise ValueError(f"Truncated signature header at 0x{off:X}")
        return buf[off + 1] | (cls._u16(buf, off + 2) << 8)
    @classmethod
    def merge(cls, base, delta, verbose=True):
        if len(delta) < 4:
            raise ValueError("Delta file is too small")
        if delta[0] != cls.SIG_DELTA_BLOB_RECINFO:
            raise ValueError(f"Expected DELTA_BLOB_RECINFO (0x74), got 0x{delta[0]:02X}")
        recinfo_size = cls._sig_size(delta, 0)
        blob_off = 4 + recinfo_size
        if blob_off + 4 > len(delta):
            raise ValueError("DELTA_BLOB_RECINFO exceeds delta file")
        if delta[blob_off] != cls.SIG_DELTA_BLOB:
            raise ValueError(f"Expected DELTA_BLOB (0x73) at 0x{blob_off:X}, got 0x{delta[blob_off]:02X}")
        blob_size = cls._sig_size(delta, blob_off)
        payload_off = blob_off + 4
        payload_end = payload_off + blob_size
        if payload_end > len(delta):
            raise ValueError("DELTA_BLOB exceeds delta file")
        if blob_size < 8:
            raise ValueError("DELTA_BLOB too small")
        merge_size = cls._u32(delta, payload_off)
        merge_crc = cls._u32(delta, payload_off + 4)
        cmd_off = payload_off + 8
        cmd_end = payload_end
        out = bytearray()
        p = cmd_off
        command_id = 0
        copy_count = 0
        literal_count = 0
        while p < cmd_end:
            command_start = p
            if p + 2 > cmd_end:
                raise ValueError(f"Truncated command at 0x{p:X}")
            value = cls._u16(delta, p)
            p += 2
            if value & 0x8000:
                if p + 4 > cmd_end:
                    raise ValueError(f"Truncated COPY command at 0x{command_start:X}")
                base_offset = cls._u32(delta, p)
                p += 4
                copy_size = (value & 0x7FFF) + 6
                base_end = base_offset + copy_size
                if base_end > len(base):
                    raise ValueError(f"COPY out of bounds: base[0x{base_offset:X}:0x{base_end:X}], base size=0x{len(base):X}")
                output_offset = len(out)
                out += base[base_offset:base_end]
                copy_count += 1
            else:
                literal_size = value
                literal_end = p + literal_size
                if literal_end > cmd_end:
                    raise ValueError(f"LITERAL out of bounds at 0x{command_start:X}")
                output_offset = len(out)
                literal = delta[p:literal_end]
                out += literal
                p = literal_end
                literal_count += 1
            command_id += 1
        return bytes(out)

def _auto_decompressed_path(vdm_path):
    return os.path.splitext(os.path.abspath(vdm_path))[0] + ".decompressed"

def _unpack_vdm_to_file(vdm_path, output_path):
    decompressed, rmdx_size, n, compressed_offset = VDMExtractor.unpack_vdm(vdm_path)
    with open(output_path, "wb") as f:
        f.write(decompressed)
    return decompressed

THREAT_BEGIN = 0x5C
THREAT_END = 0x5D
FILEPATH = 0x5F
FOLDERNAME = 0x60
REGKEY = 0x63
FRIENDLYFILE_SHA256 = 0xA0
FRIENDLYFILE_SHA512 = 0xA1
ASEP_FILEPATH = 0x71
ASEP_FOLDERNAME = 0x75
WEIGHT_ANOMALY_RATIO = 10.0
WEIGHT_ANOMALY_LOG = "WeightAnomaly.log"
@dataclass
class SignatureRecord:
    offset: int
    sig_type: int
    sig_name: str
    size: int
    content: bytes
    size_low: int = 0
    size_high: int = 0
    parsed_lines: List[str] = field(default_factory=list)
    contains_wildcard: Optional[str] = None
    threshold_required: Optional[int] = None
    subrule_weights: List[int] = field(default_factory=list)
    parsed_subrule_count: int = 0
@dataclass
class ThreatRecord:
    threat_id: int
    start_offset: int
    signatures: List[SignatureRecord] = field(default_factory=list)
    complete: bool = False
    def add_signature(self, sig: SignatureRecord):
        self.signatures.append(sig)
    def to_log(self):
        lines = [f"===== THREAT {self.threat_id} BEGIN @ 0x{self.start_offset:X} ====="]
        for sig in self.signatures:
            lines.append(f"Signature: {sig.sig_name} (0x{sig.sig_type:02X}), Offset: 0x{sig.offset:X}, Size: {sig.size}")
            lines.append(f"Content: {sig.content.hex()}")
            lines.extend(sig.parsed_lines)
        lines.append(f"===== THREAT {self.threat_id} {'END' if self.complete else 'INCOMPLETE'} =====")
        return lines
class CommonSignatureParser:
    @staticmethod
    def parse(record: SignatureRecord):
        rule_data = " ".join(f"{b:02X}" for b in record.content)
        return [f"    Common Signature: ui8SignatureType: 0x{record.sig_type:02X}, ui8SizeLow: 0x{record.size_low:02X}, ui16SizeHigh: 0x{record.size_high:04X}, Size: {record.size}, pbRuleContent Length: {len(record.content)}", f"    Rule Data: {rule_data}"]
class ThreatBeginSignatureParser:
    CATEGORY_TABLE = {
        1: "Backdoor", 2: "TrojanDownloader", 3: "TrojanDropper", 4: "Spammer", 5: "DDoS", 6: "DoS", 7: "Joke", 8: "PWS", 9: "Worm", 10: "Flooder",
        11: "Trojan", 12: "Virus", 13: "Constructor", 14: "Nuker", 15: "Spoofer", 16: "Tool", 17: "AolPWS", 18: "TrojanSpy", 19: "VirTool", 20: "Exploit",
        21: "TrojanClicker", 22: "HackTool", 23: "TrojanProxy", 24: "Tool", 25: "Sniffer", 26: "TrojanNotifier", 27: "Adware", 28: "Spyware", 29: "Dialer"
    }
    PLATFORM_TABLE = {
        1: "Win32", 2: "Win95", 3: "WinNT", 4: "DOS", 5: "Linux", 6: "Win16", 7: "MacOS", 8: "BAT", 9: "VBS", 10: "JS",
        11: "Java", 12: "IRC", 13: "W97M", 14: "X97M", 15: "PP97M", 16: "FreeBSD", 17: "OS2", 18: "Win98", 19: "Win2K", 20: "AutoIt",
        21: "WinCE", 22: "SymbOS", 23: "WinHLP", 24: "MSIL", 25: "INF", 26: "SunOS", 27: "Netware", 28: "DOS32", 29: "MacOS_X", 30: "AppleScript"
    }
    SUFFIX_TABLE = {
        1: ".dr", 2: ".intd", 3: ".remnants", 4: "@mm", 5: ".dam", 6: ".plugin", 7: ".pak", 8: ".gen", 9: ".worm", 10: ".dll", 11: "@m", 12: ".ldr", 13: ".kit"
    }
    @staticmethod
    def _hx(data: bytes):
        return " ".join(f"{b:02X}" for b in data)
    @staticmethod
    def _decode_ascii(data: bytes):
        data = data.rstrip(b"\x00")
        return "".join(chr(b) if 0x20 <= b <= 0x7E else f"\\x{b:02X}" for b in data)
    @classmethod
    def _unpack_virus_name(cls, raw: bytes):
        raw = raw.rstrip(b"\x00")
        if not raw:
            return "", None
        if raw[0] & 0x80 and len(raw) >= 2 and raw[1] != 0:
            packed = (raw[0] << 8) | raw[1]
            category_index = (packed >> 10) & 0x1F
            platform_index = (packed >> 5) & 0x1F
            suffix_index = (packed >> 1) & 0x0F
            family = cls._decode_ascii(raw[2:])
            category = cls.CATEGORY_TABLE.get(category_index)
            platform = cls.PLATFORM_TABLE.get(platform_index)
            suffix = cls.SUFFIX_TABLE.get(suffix_index, "") if suffix_index else ""
            parts = []
            if category:
                parts.append(category + (":" if platform else ""))
            if platform:
                parts.append(platform + "/")
            parts.append(family)
            if suffix:
                parts.append(suffix)
            name = "".join(parts)
            meta = {
                "packed": packed,
                "category_index": category_index,
                "platform_index": platform_index,
                "suffix_index": suffix_index,
                "bit0": packed & 1
            }
            return name, meta
        return cls._decode_ascii(raw), None
    @classmethod
    def parse(cls, record: SignatureRecord):
        data = record.content
        lines = []
        if len(data) < 12:
            return [f"    [!] THREAT_BEGIN content too short: {len(data)} byte(s)"]
        signature_id = int.from_bytes(data[0:4], "little")
        dependency_count = int.from_bytes(data[4:6], "little")
        extra_info_count = int.from_bytes(data[6:8], "little")
        field08 = int.from_bytes(data[8:10], "little")
        name_size = int.from_bytes(data[10:12], "little")
        name_start = 12
        name_end = name_start + name_size
        lines.append(f"    SignatureId: 0x{signature_id:08X}")
        if name_end > len(data):
            name_raw = data[name_start:]
            threat_name, _ = cls._unpack_virus_name(name_raw)
            lines.append(f'    ThreatName: "{threat_name}"')
            lines.append(f"    [!] ThreatName truncated: expected {name_size} byte(s), got {len(name_raw)}")
            return lines
        name_raw = data[name_start:name_end]
        threat_name, _ = cls._unpack_virus_name(name_raw)
        lines.append(f'    ThreatName: "{threat_name}"')
        p = name_end
        if p + 2 > len(data):
            if p != len(data):
                lines.append(f"    [!] ReservedAfterName truncated: {len(data) - p} byte(s)")
            return lines
        reserved = data[p:p + 2]
        p += 2
        dependency_bytes = dependency_count * 4
        if p + dependency_bytes > len(data):
            available = max(0, len(data) - p)
            count = available // 4
            deps = [int.from_bytes(data[p + i * 4:p + i * 4 + 4], "little") for i in range(count)]
            if deps:
                lines.append("    Dependencies: " + " | ".join(f"0x{x:08X}" for x in deps))
            lines.append(f"    [!] Dependencies truncated: expected {dependency_count}, got {count}")
            return lines
        deps = [int.from_bytes(data[p + i * 4:p + i * 4 + 4], "little") for i in range(dependency_count)]
        p += dependency_bytes
        if deps:
            lines.append("    Dependencies: " + " | ".join(f"0x{x:08X}" for x in deps))
        extra_info_bytes = extra_info_count * 2
        if p + extra_info_bytes > len(data):
            available = max(0, len(data) - p)
            count = available // 2
            entries = [int.from_bytes(data[p + i * 2:p + i * 2 + 2], "little") for i in range(count)]
            if entries:
                lines.append("    ExtraInfoEntries: " + " | ".join(f"0x{x:04X}" for x in entries))
            lines.append(f"    [!] ExtraInfoEntries truncated: expected {extra_info_count}, got {count}")
            return lines
        entries = [int.from_bytes(data[p + i * 2:p + i * 2 + 2], "little") for i in range(extra_info_count)]
        p += extra_info_bytes
        # Chỉ giữ các field chưa rõ semantics để tiếp tục reverse; field đã hiểu chỉ lưu kết quả cuối.
        if field08:
            lines.append(f"    Field08: 0x{field08:04X}")
        if reserved != b"\x00\x00":
            lines.append(f"    ReservedAfterName: {cls._hx(reserved)}")
        if entries:
            lines.append("    ExtraInfoEntries: " + " | ".join(f"0x{x:04X}" for x in entries))
        remaining = len(data) - p
        if remaining == 0:
            return lines
        if remaining < 2:
            lines.append(f"    [!] Trailer truncated: {remaining} byte(s)")
            return lines
        field_a = data[p]
        field_b = data[p + 1]
        p += 2
        lines.append(f"    FieldA: 0x{field_a:02X}")
        lines.append(f"    FieldB: 0x{field_b:02X}")
        remaining = len(data) - p
        if remaining == 0:
            return lines
        if remaining < 4:
            lines.append(f"    [!] Optional trailer truncated: {remaining} byte(s)")
            return lines
        field_c = int.from_bytes(data[p:p + 2], "little")
        field_d = int.from_bytes(data[p + 2:p + 4], "little")
        lines.append(f"    FieldC: 0x{field_c:04X}")
        lines.append(f"    FieldD: 0x{field_d:04X}")
        return lines
class ThreatEndSignatureParser:
    @staticmethod
    def parse(record: SignatureRecord):
        data = record.content
        if len(data) < 4:
            return [f"    [!] THREAT_END content too short: {len(data)} byte(s)", f"    Rule Data: {' '.join(f'{b:02X}' for b in data)}"]
        signature_id = int.from_bytes(data[:4], "little")
        lines = [f"    ui32SignatureId: 0x{signature_id:08X}"]
        return lines
class RegKeySignatureParser:
    HK_TYPES = {1: "HKEY_CLASSES_ROOT", 2: "HKEY_CURRENT_USER", 3: "HKEY_LOCAL_MACHINE", 4: "HKEY_USERS"}
    @staticmethod
    def _decode_reg_string(data: bytes):
        data = data.rstrip(b"\x00")
        if not data:
            return ""
        try:
            s = data.decode("utf-8")
            return "".join(c if c.isprintable() else "".join(f"\\x{x:02X}" for x in c.encode("utf-8")) for c in s)
        except UnicodeDecodeError:
            return "".join(chr(x) if 0x20 <= x <= 0x7E else f"\\x{x:02X}" for x in data)
    @classmethod
    def parse(cls, record: SignatureRecord):
        data = record.content
        if len(data) < 4:
            return [f"    [!] REGKEY content too short: {len(data)} byte(s)"]
        hk_type = int.from_bytes(data[0:2], "little")
        reg_string_size = int.from_bytes(data[2:4], "little")
        string_end = 4 + reg_string_size
        reg_raw = data[4:min(string_end, len(data))]
        reg_string = cls._decode_reg_string(reg_raw).lstrip("\\/")
        hk_name = cls.HK_TYPES.get(hk_type, f"UNKNOWN_HKEY(0x{hk_type:04X})")
        formatted = f"{hk_name}\\{reg_string}" if reg_string else hk_name
        if string_end > len(data):
            return [formatted, f"    [!] REGKEY string truncated: expected {reg_string_size} byte(s), got {len(reg_raw)}"]
        return [formatted]
class FriendlyFileHashSignatureParser:
    @staticmethod
    def parse(record: SignatureRecord):
        return [record.content.hex()]
class FolderNameSignatureParser:
    # CSIDL -> canonical path token used when rendering folder/path signatures.
    # Values observed directly in g_predef_paths preserve Defender/LUM spelling.
    # Standard Windows CSIDL values absent from that table use normalized %token% names.
    PREDEF_PATHS = {
        0x0000: "%desktop%",
        0x0001: "%internet%",
        0x0002: "%programs%",
        0x0003: "%controls%",
        0x0004: "%printers%",
        0x0005: "%personal%",
        0x0006: "%favorites%",
        0x0007: "%startup%",
        0x0008: "%recent%",
        0x0009: "%sendto%",
        0x000A: "%bitbucket%",
        0x000B: "%startmenu%",
        0x000C: "%mydocuments%",
        0x000D: "%mymusic%",
        0x000E: "%myvideo%",
        0x0010: "%desktopdirectory%",
        0x0011: "%drives%",
        0x0012: "%network%",
        0x0013: "%nethood%",
        0x0014: "%fonts%",
        0x0015: "%templates%",
        0x0016: "%common_startmenu%",
        0x0017: "%common_programs%",
        0x0018: "%common_startup%",
        0x0019: "%common_desktop%",
        0x001A: "%appdata%",
        0x001B: "%printhood%",
        0x001C: "%localappdata%",
        0x001D: "%altstartup%",
        0x001E: "%common_altstartup%",
        0x001F: "%common_favorites%",
        0x0020: "%internet_cache%",
        0x0021: "%cookies%",
        0x0022: "%history%",
        0x0023: "%programdata%",
        0x0024: "%windows%",
        0x0025: "%system%",
        0x0026: "%program_files%",
        0x0027: "%mypictures%",
        0x0028: "%userprofile%",
        0x0029: "%systemx86%",
        0x002A: "%program_filesx86%",
        0x002B: "%program_filescommon%",
        0x002C: "%program_filescommonx86%",
        0x002D: "%common_templates%",
        0x002E: "%common_documents%",
        0x002F: "%common_admin_tools%",
        0x0030: "%admin_tools%",
        0x0031: "%connections%",
        0x0035: "%common_music%",
        0x0036: "%common_pictures%",
        0x0037: "%common_video%",
        0x0038: "%CSIDLResources%",
        0x0039: "%CSIDLResourcesLocalized%",
        0x003A: "%common_oem_links%",
        0x003B: "%cd_burn%",
        0x003D: "%computersnearme%",
        0x003E: "%profiles%",
        0xFFFA: "%username%",
        0xFFFB: "%systemdrive%",
        0xFFFC: "%commonfiles%",
        0xFFFD: "%allusersprofile%",
        0xFFFE: "%temp%",
    }
    @staticmethod
    def _decode_folder_string(data: bytes):
        data = data.rstrip(b"\x00")
        if not data:
            return ""
        try:
            s = data.decode("utf-8")
            return "".join(c if c.isprintable() else "".join(f"\\x{x:02X}" for x in c.encode("utf-8")) for c in s)
        except UnicodeDecodeError:
            return "".join(chr(x) if 0x20 <= x <= 0x7E else f"\\x{x:02X}" for x in data)
    @classmethod
    def parse(cls, record: SignatureRecord):
        data = record.content
        if len(data) < 2:
            return [f"    [!] FOLDERNAME content too short: {len(data)} byte(s)"]
        csidl = int.from_bytes(data[:2], "little")
        folder = cls._decode_folder_string(data[2:]).lstrip("\\/")
        # 0xFFFF is Defender's raw/absolute-path sentinel: no predefined prefix is prepended.
        if csidl == 0xFFFF:
            return [folder]
        prefix = cls.PREDEF_PATHS.get(csidl, f"CSIDL(0x{csidl:04X})")
        return [f"{prefix}\\{folder}" if folder else prefix]

class MpLuaError(Exception):
    pass


class MpLuaReader:
    def __init__(self, data: bytes, base_offset: int = 0):
        self.data = data
        self.pos = 0
        self.base_offset = base_offset

    @property
    def absolute_pos(self):
        return self.base_offset + self.pos

    @property
    def remaining(self):
        return len(self.data) - self.pos

    def read(self, n, what="data"):
        if n < 0 or self.pos + n > len(self.data):
            raise MpLuaError(
                f"Unexpected EOF at offset 0x{self.absolute_pos:X} "
                f"while reading {what} ({n} byte(s) needed)"
            )
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self, what="u8"):
        return self.read(1, what)[0]

    def u32(self, what="u32"):
        return struct.unpack("<I", self.read(4, what))[0]

    def i64(self, what="i64"):
        return struct.unpack("<q", self.read(8, what))[0]


@dataclass
class MpLuaString:
    raw: bytes

    @classmethod
    def read(cls, r: MpLuaReader, what: str):
        # Defender MpLua uses a 32-bit string/source length even though the
        # embedded Lua header advertises size_t == 8.
        n = r.u32(f"{what} length")
        if n > r.remaining:
            raise MpLuaError(
                f"{what} at offset 0x{r.absolute_pos - 4:X} declares "
                f"length {n}, but only {r.remaining} byte(s) remain"
            )
        return cls(r.read(n, what))

    def export_lua51(self):
        return struct.pack("<Q", len(self.raw)) + self.raw


@dataclass
class MpLuaLocalVar:
    name: MpLuaString
    startpc: int
    endpc: int


@dataclass
class MpLuaProto:
    source: MpLuaString
    line_defined: int
    last_line_defined: int
    num_upvalues: int
    num_params: int
    is_vararg: int
    max_stack_size: int
    instructions: bytes
    constants: list = field(default_factory=list)
    protos: list = field(default_factory=list)
    line_info: list = field(default_factory=list)
    locals: list = field(default_factory=list)
    upvalue_names: list = field(default_factory=list)

    @classmethod
    def read(cls, r: MpLuaReader, depth=0):
        prefix = f"Proto[{depth}]"

        source = MpLuaString.read(r, f"{prefix}.source")
        line_defined = r.u32(f"{prefix}.line_defined")
        last_line_defined = r.u32(f"{prefix}.last_line_defined")

        num_upvalues = r.u8(f"{prefix}.num_upvalues")
        num_params = r.u8(f"{prefix}.num_params")
        is_vararg = r.u8(f"{prefix}.is_vararg")
        max_stack_size = r.u8(f"{prefix}.max_stack_size")

        instruction_count = r.u32(f"{prefix}.instruction_count")
        if instruction_count > r.remaining // 4:
            raise MpLuaError(
                f"{prefix} declares {instruction_count} instructions at "
                f"offset 0x{r.absolute_pos - 4:X}, exceeding remaining data"
            )
        instructions = r.read(instruction_count * 4, f"{prefix}.instructions")

        constant_count = r.u32(f"{prefix}.constant_count")
        constants = []
        for i in range(constant_count):
            cpos = r.absolute_pos
            ctype = r.u8(f"{prefix}.constant[{i}].type")

            if ctype == 0:
                constants.append(("nil", None))
            elif ctype == 1:
                constants.append(("bool", r.u8(f"{prefix}.constant[{i}].boolean")))
            elif ctype == 3:
                constants.append(("number", r.i64(f"{prefix}.constant[{i}].integer")))
            elif ctype == 4:
                constants.append((
                    "string",
                    MpLuaString.read(r, f"{prefix}.constant[{i}].string"),
                ))
            else:
                raise MpLuaError(
                    f"Unknown MpLua constant type {ctype} at offset 0x{cpos:X}"
                )

        proto_count = r.u32(f"{prefix}.proto_count")
        protos = [cls.read(r, depth + 1) for _ in range(proto_count)]

        line_info_count = r.u32(f"{prefix}.line_info_count")
        line_info = [
            r.u32(f"{prefix}.line_info[{i}]")
            for i in range(line_info_count)
        ]

        local_count = r.u32(f"{prefix}.local_count")
        locals_ = []
        for i in range(local_count):
            name = MpLuaString.read(r, f"{prefix}.local[{i}].name")
            startpc = r.u32(f"{prefix}.local[{i}].startpc")
            endpc = r.u32(f"{prefix}.local[{i}].endpc")
            locals_.append(MpLuaLocalVar(name, startpc, endpc))

        upvalue_name_count = r.u32(f"{prefix}.upvalue_name_count")
        upvalue_names = [
            MpLuaString.read(r, f"{prefix}.upvalue_name[{i}]")
            for i in range(upvalue_name_count)
        ]

        return cls(
            source=source,
            line_defined=line_defined,
            last_line_defined=last_line_defined,
            num_upvalues=num_upvalues,
            num_params=num_params,
            is_vararg=is_vararg,
            max_stack_size=max_stack_size,
            instructions=instructions,
            constants=constants,
            protos=protos,
            line_info=line_info,
            locals=locals_,
            upvalue_names=upvalue_names,
        )

    def export_lua51(self):
        out = bytearray()

        out += self.source.export_lua51()
        out += struct.pack("<II", self.line_defined, self.last_line_defined)
        out += struct.pack(
            "<BBBB",
            self.num_upvalues,
            self.num_params,
            self.is_vararg,
            self.max_stack_size,
        )

        if len(self.instructions) % 4:
            raise MpLuaError("Instruction blob is not 4-byte aligned")
        out += struct.pack("<I", len(self.instructions) // 4)
        out += self.instructions

        out += struct.pack("<I", len(self.constants))
        for kind, value in self.constants:
            if kind == "nil":
                out += b"\x00"
            elif kind == "bool":
                out += b"\x01" + bytes([value])
            elif kind == "number":
                out += b"\x03" + struct.pack("<d", float(value))
            elif kind == "string":
                out += b"\x04" + value.export_lua51()
            else:
                raise MpLuaError(f"Unsupported constant kind: {kind}")

        out += struct.pack("<I", len(self.protos))
        for proto in self.protos:
            out += proto.export_lua51()

        out += struct.pack("<I", len(self.line_info))
        for line in self.line_info:
            out += struct.pack("<I", line)

        out += struct.pack("<I", len(self.locals))
        for local in self.locals:
            out += local.name.export_lua51()
            out += struct.pack("<II", local.startpc, local.endpc)

        out += struct.pack("<I", len(self.upvalue_names))
        for name in self.upvalue_names:
            out += name.export_lua51()

        return bytes(out)


class MpLuaConverter:
    MPLUA_HEADER = b"\x1bLuaQ\x00\x01\x04\x08\x04\x08\x01"
    LUA51_HEADER = b"\x1bLuaQ\x00\x01\x04\x08\x04\x08\x00"

    @classmethod
    def convert_bytes(cls, data: bytes):
        if len(data) < len(cls.MPLUA_HEADER):
            raise MpLuaError("MpLua blob is too small")

        header = data[:len(cls.MPLUA_HEADER)]
        if header != cls.MPLUA_HEADER:
            raise MpLuaError(
                "Unexpected MpLua header: "
                f"{header.hex(' ').upper()}; expected "
                f"{cls.MPLUA_HEADER.hex(' ').upper()}"
            )

        r = MpLuaReader(
            data[len(cls.MPLUA_HEADER):],
            len(cls.MPLUA_HEADER),
        )
        proto = MpLuaProto.read(r)

        # Do not silently accept bytes that are not part of the parsed chunk.
        if r.remaining:
            raise MpLuaError(
                f"{r.remaining} trailing byte(s) remain after MpLua Proto"
            )

        return cls.LUA51_HEADER + proto.export_lua51()


class LuaStandaloneSignatureParser:
    HEADER_SIZE = 8

    @staticmethod
    def _hx(data: bytes):
        return " ".join(f"{b:02X}" for b in data)

    @staticmethod
    def _decode_name(data: bytes):
        if data.endswith(b"\x00"):
            data = data[:-1]
        return data.decode("utf-8", errors="replace")

    @staticmethod
    def _resolve_decompiler():
        configured = LUA_DECOMPILER_PATH.strip()
        if not configured:
            return None

        p = os.path.abspath(configured)
        if os.path.isfile(p):
            return p

        script_dir = os.path.dirname(os.path.abspath(__file__))
        beside = os.path.join(script_dir, configured)
        if os.path.isfile(beside):
            return beside

        return shutil.which(configured)

    @classmethod
    def _decompile_luac_file(cls, luac_path: str):
        exe = cls._resolve_decompiler()
        if not exe:
            raise MpLuaError(
                f"Lua decompiler not found: {LUA_DECOMPILER_PATH}"
            )

        proc = subprocess.run(
            [exe, "--dec", luac_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=LUA_DECOMPILER_TIMEOUT,
            check=False,
        )

        stdout = proc.stdout.decode("utf-8", errors="replace").strip()
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()

        if proc.returncode != 0:
            detail = stderr or stdout or f"exit code {proc.returncode}"
            raise MpLuaError(f"Lua decompiler failed: {detail}")

        if not stdout:
            raise MpLuaError(
                "Lua decompiler returned success but produced no source"
            )

        return stdout

    @classmethod
    def parse(
        cls,
        content: bytes,
        lua_index: int,
        drop_dir: str,
        cached_source=None,
        cached_mplua_sha256=None,
    ):
        if len(content) < cls.HEADER_SIZE:
            return (
                ["    [!] LUASTANDALONE RuleData is shorter than 8-byte blob header"],
                None,
                None,
            )

        name_length = content[0]
        category = content[1]
        metadata_size = int.from_bytes(content[2:4], "little")
        mplua_size = int.from_bytes(content[4:8], "little")

        name_start = cls.HEADER_SIZE
        name_end = name_start + name_length
        metadata_end = name_end + metadata_size
        mplua_end = metadata_end + mplua_size

        base_lines = [
            f"    LuaIndex: {lua_index}",
            f"    NameLength: 0x{name_length:02X} ({name_length})",
            f"    Category: 0x{category:02X}",
            f"    sizeofMetaData: 0x{metadata_size:04X} ({metadata_size})",
            f"    sizeofMPLua: 0x{mplua_size:08X} ({mplua_size})",
        ]

        if name_end > len(content):
            return base_lines + [
                "    [!] name[] exceeds RuleData boundary"
            ], None, None

        name = content[name_start:name_end]
        base_lines.append(f'    Name: "{cls._decode_name(name)}"')

        if metadata_end > len(content):
            return base_lines + [
                "    [!] MetaData[] exceeds RuleData boundary"
            ], None, None

        metadata = content[name_end:metadata_end]
        base_lines.append(f"    MetaData: {cls._hx(metadata)}")

        if mplua_end > len(content):
            return base_lines + [
                "    [!] MPLUA[] exceeds RuleData boundary"
            ], None, None

        mplua = content[metadata_end:mplua_end]
        trailing = content[mplua_end:]

        os.makedirs(drop_dir, exist_ok=True)

        # Stable LUASTANDALONE parse-order counter.
        stem = str(lua_index)
        mplua_path = os.path.join(drop_dir, f"{stem}.mplua")
        luac_path = os.path.join(drop_dir, f"{stem}.luac")

        lines = list(base_lines)
        lines.append(f"    LuaC File: {luac_path}")

        if trailing:
            lines.append(
                f"    [!] Trailing RuleData: {len(trailing)} byte(s): "
                f"{cls._hx(trailing)}"
            )

        source = None
        mplua_sha256 = hashlib.sha256(mplua).hexdigest()

        # The .mplua file is only an intermediate artifact. It is always
        # removed in finally, regardless of success/failure/cache reuse.
        try:
            with open(mplua_path, "wb") as f:
                f.write(mplua)

            cache_valid = (
                os.path.isfile(luac_path)
                and cached_source
                and cached_mplua_sha256 == mplua_sha256
            )

            if cache_valid:
                source = cached_source
                lines.append("    Src:")
                lines.append(source)
                return lines, source, mplua_sha256

            # Existing file with the same signature ID but a different MPLUA
            # must be regenerated, otherwise a shifted DB ID could reuse stale
            # bytecode/source.
            if (
                os.path.isfile(luac_path)
                and cached_mplua_sha256
                and cached_mplua_sha256 != mplua_sha256
            ):
                try:
                    os.remove(luac_path)
                except OSError:
                    pass

            if not os.path.isfile(luac_path):
                # Convert exactly MPLUA[sizeofMPLua]. No LuaQ scanning.
                luac = MpLuaConverter.convert_bytes(mplua)
                with open(luac_path, "wb") as f:
                    f.write(luac)

            # If .luac existed but no cached source survived, source cannot be
            # reconstructed without a decompiler; decompile once and cache it.
            source = cls._decompile_luac_file(luac_path)
            lines.append("    Src:")
            lines.append(source)
            return lines, source, mplua_sha256

        except Exception as e:
            lines.append("    Src:")
            lines.append(
                f"    [!] Lua parse/decompile error: "
                f"{type(e).__name__}: {e}"
            )
            return lines, None, mplua_sha256

        finally:
            try:
                os.remove(mplua_path)
            except FileNotFoundError:
                pass
            except OSError:
                pass

class PEHSTRSignatureParser:
    @staticmethod
    def _is_readable_utf16_text(s: str):
        # PEHSTR UTF-16 auto-rendering is intentionally limited to widened
        # printable ASCII. Non-ASCII Unicode is left as raw bytes.
        return bool(s) and all(0x20 <= ord(c) <= 0x7E for c in s)
    @staticmethod
    def _decode_rule_label(data: bytes):
        if not data:
            return ""
        try:
            s = data.decode("utf-8")
            return "".join(c if c.isprintable() else "".join(f"\\x{x:02x}" for x in c.encode("utf-8")) for c in s)
        except UnicodeDecodeError:
            return "".join(chr(x) if 0x20 <= x <= 0x7E else f"\\x{x:02x}" for x in data)
    @classmethod
    def _split_header_and_rule_data(cls, content: bytes):
        if len(content) < 7:
            return None
        label_end = content.find(b"\x00", 6)
        if label_end == -1:
            return None
        return cls._decode_rule_label(content[6:label_end]), content[label_end + 1:]
    @staticmethod
    def _detect_utf16(data):
        # Only recognize UTF-16 that is clearly an ASCII string widened to
        # UTF-16: every printable ASCII character must be separated by a NUL.
        #
        # Accepted examples:
        #   UTF-16LE: 41 00 42 00 43 00       -> "ABC"
        #   UTF-16BE: 00 41 00 42 00 43       -> "ABC"
        #
        # Rejected examples:
        #   6A 40 68 00 30 00 00 53 6A 00
        #   89 87 B0 00 00 00
        #
        # A single trailing UTF-16 NUL terminator is allowed, but embedded NUL
        # characters are not considered text here.
        if len(data) < 4 or len(data) % 2:
            return None

        probe = data[:-2] if data.endswith(b"\x00\x00") else data
        if len(probe) < 4 or len(probe) % 2:
            return None

        le_chars = probe[0::2]
        le_nulls = probe[1::2]
        if all(x == 0 for x in le_nulls) and all(0x20 <= x <= 0x7E for x in le_chars):
            return "utf-16le"

        be_nulls = probe[0::2]
        be_chars = probe[1::2]
        if all(x == 0 for x in be_nulls) and all(0x20 <= x <= 0x7E for x in be_chars):
            return "utf-16be"

        return None
    @classmethod
    def _decode_string(cls, data):
        if not data:
            return None
        enc = cls._detect_utf16(data)
        if enc:
            try:
                s = data.decode(enc)
            except UnicodeDecodeError:
                return None
            if not cls._is_readable_utf16_text(s):
                return None
            return f'u"{s}"'
        try:
            s = data.decode("utf-8")
            if s and sum(c.isprintable() for c in s) / len(s) > 0.8:
                escaped = "".join(c if c.isprintable() else "".join(f"\\x{x:02x}" for x in c.encode("utf-8")) for c in s)
                return f'"{escaped}"'
        except UnicodeDecodeError:
            pass
        if sum(0x20 <= x <= 0x7E for x in data) / len(data) > 0.8:
            escaped = "".join(chr(x) if 0x20 <= x <= 0x7E else f"\\x{x:02x}" for x in data)
            return f'"{escaped}"'
        return None
    @classmethod
    def _parse_rule_data(cls, data: bytes, number_of_subrules: int):
        lines = []
        i = 0
        for rule_index in range(1, number_of_subrules + 1):
            if i + 3 > len(data):
                lines.append(f"    [!] Truncated PEHSTR subrule header at offset 0x{i:X}")
                break
            low, high, size = data[i:i + 3]
            end = i + 3 + size
            if end > len(data):
                lines.append(f"    [!] Invalid PEHSTR subrule size {size} at offset 0x{i:X}")
                break
            subrule = data[i + 3:end]
            weight = int.from_bytes(bytes((low, high)), "little", signed=True)
            text = cls._decode_string(subrule)
            if text is not None:
                lines.append(f"    Subrule {rule_index}: Weight: {weight}, Size: {size}, [String] {text}")
            else:
                lines.append(f"    Subrule {rule_index}: Weight: {weight}, Size: {size}, Bytes: {subrule.hex()}")
            i = end
        return lines
    @classmethod
    def get_weight_stats(cls, content: bytes):
        if len(content) < 7:
            return None
        threshold = (content[3] << 8) | content[2]
        number_of_subrules = (content[5] << 8) | content[4]
        split = cls._split_header_and_rule_data(content)
        if split is None:
            return None
        _, data = split
        weights = []
        parsed = 0
        i = 0
        while parsed < number_of_subrules and i + 3 <= len(data):
            low, high, size = data[i:i + 3]
            end = i + 3 + size
            if end > len(data):
                break
            weights.append(int.from_bytes(bytes((low, high)), "little", signed=True))
            parsed += 1
            i = end
        return threshold, weights, parsed
    @classmethod
    def parse(cls, content: bytes):
        if len(content) < 7:
            return [f"    [!] PEHSTR content too short: {len(content)} byte(s)"]
        unknown = int.from_bytes(content[0:2], "little")
        threshold = (content[3] << 8) | content[2]
        number_of_subrules = (content[5] << 8) | content[4]
        split = cls._split_header_and_rule_data(content)
        if split is None:
            return [f"    [!] PEHSTR rule label is not null-terminated"]
        rule_label, rule_data = split
        lines = [f'    Unknown: {unknown}, Threshold Required: {threshold}, SubRules Number: {number_of_subrules}, Rule Label: "{rule_label}", Rule Data Length: {len(rule_data)}']
        lines.extend(cls._parse_rule_data(rule_data, number_of_subrules))
        return lines
class PEHSTRExtSignatureParser:
    # Debug logger for 90 09 / 90 0A backward-linearization.
    # Set to False to disable BEFORE/AFTER logs.
    LOG_BACKWARD_REORDER = True

    # Wildcard opcode -> minimum encoded length, including the leading 0x90 byte.
    # Opcodes with reverse-engineered layouts are parsed structurally.
    # Extended opcodes 0x20..0x2E are intentionally opaque for now and are
    # framed only as two-byte tokens [90 XX].
    WILDCARD_REQUIRED_LENGTH = {
        # kind_param_a: total encoded wildcard length, including 90 + opcode.
        # Keys are the numeric opcode values (0..33 / 0x00..0x21).
        0x00: 2, 0x01: 3, 0x02: 3, 0x03: 4, 0x04: 4, 0x05: 4,
        0x06: 0, 0x07: 4, 0x08: 4, 0x09: 4, 0x0A: 4,
        0x0B: 4, 0x0C: 4, 0x0D: 4, 0x0E: 4, 0x0F: 4,
        0x10: 4, 0x11: 4, 0x12: 4,
        0x13: 2, 0x14: 2, 0x15: 2, 0x16: 2, 0x17: 3, 0x18: 2,
        0x19: 4, 0x1A: 4, 0x1B: 3,
        0x1C: 4, 0x1D: 4, 0x1E: 4, 0x1F: 4,

        # 90 20..90 2E are currently opaque/unknown extended wildcard opcodes.
        # Only frame the opcode itself as [90 XX]; do not interpret or consume
        # any following operand bytes until their layouts are reverse-engineered.
        0x20: 2, 0x21: 2, 0x22: 2, 0x23: 2, 0x24: 2,
        0x25: 2, 0x26: 2, 0x27: 2, 0x28: 2, 0x29: 2,
        0x2A: 2, 0x2B: 2, 0x2C: 2, 0x2D: 2, 0x2E: 2,
    }
    @staticmethod
    def _is_readable_utf16_text(s: str):
        # PEHSTR UTF-16 auto-rendering is intentionally limited to widened
        # printable ASCII. Non-ASCII Unicode is left as raw bytes.
        return bool(s) and all(0x20 <= ord(c) <= 0x7E for c in s)
    @staticmethod
    def _hx(data):
        return " ".join(f"{x:02X}" for x in data)
    @staticmethod
    def _decode_rule_label(data: bytes):
        if not data:
            return ""
        try:
            s = data.decode("utf-8")
            return "".join(c if c.isprintable() else "".join(f"\\x{x:02x}" for x in c.encode("utf-8")) for c in s)
        except UnicodeDecodeError:
            return "".join(chr(x) if 0x20 <= x <= 0x7E else f"\\x{x:02x}" for x in data)
    @classmethod
    def _split_header_and_rule_data(cls, content: bytes):
        if len(content) < 7:
            return None
        label_end = content.find(b"\x00", 6)
        if label_end == -1:
            return None
        return cls._decode_rule_label(content[6:label_end]), content[label_end + 1:]
    @staticmethod
    def _detect_utf16(data):
        # Only recognize UTF-16 that is clearly an ASCII string widened to
        # UTF-16: every printable ASCII character must be separated by a NUL.
        #
        # Accepted examples:
        #   UTF-16LE: 41 00 42 00 43 00       -> "ABC"
        #   UTF-16BE: 00 41 00 42 00 43       -> "ABC"
        #
        # Rejected examples:
        #   6A 40 68 00 30 00 00 53 6A 00
        #   89 87 B0 00 00 00
        #
        # A single trailing UTF-16 NUL terminator is allowed, but embedded NUL
        # characters are not considered text here.
        if len(data) < 4 or len(data) % 2:
            return None

        probe = data[:-2] if data.endswith(b"\x00\x00") else data
        if len(probe) < 4 or len(probe) % 2:
            return None

        le_chars = probe[0::2]
        le_nulls = probe[1::2]
        if all(x == 0 for x in le_nulls) and all(0x20 <= x <= 0x7E for x in le_chars):
            return "utf-16le"

        be_nulls = probe[0::2]
        be_chars = probe[1::2]
        if all(x == 0 for x in be_nulls) and all(0x20 <= x <= 0x7E for x in be_chars):
            return "utf-16be"

        return None
    @classmethod
    def _fmt_info(cls, data):
        if not data:
            return "", True
        enc = cls._detect_utf16(data)
        if enc:
            try:
                s = data.decode(enc).rstrip("\x00")
            except UnicodeDecodeError:
                return cls._hx(data), False
            if not cls._is_readable_utf16_text(s):
                return cls._hx(data), False
            return f'u"{s}"', True
        try:
            s = data.decode("utf-8")
            if s and sum(c.isprintable() for c in s) / len(s) > 0.8:
                escaped = "".join(c if c.isprintable() else "".join(f"\\x{x:02x}" for x in c.encode("utf-8")) for c in s)
                return f'"{escaped}"', True
        except UnicodeDecodeError:
            pass
        if sum(0x20 <= x <= 0x7E for x in data) / len(data) > 0.8:
            escaped = "".join(chr(x) if 0x20 <= x <= 0x7E else f"\\x{x:02x}" for x in data)
            return f'"{escaped}"', True
        return cls._hx(data), False
    @classmethod
    def _fmt(cls, data):
        return cls._fmt_info(data)[0]
    @classmethod
    def _fmt_inline_info(cls, data):
        value, is_text = cls._fmt_info(data)
        if is_text and value.startswith('u"') and value.endswith('"'):
            value = value[2:-1]
        elif is_text and value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        return value.replace('"', '\"'), is_text
    @classmethod
    def _fmt_inline(cls, data):
        return cls._fmt_inline_info(data)[0]
    @staticmethod
    def _fmt_wildcard_bytes(data):
        return "".join(chr(x) if 0x20 <= x <= 0x7E else f"\\x{x:02x}" for x in data)
    @classmethod
    def _fmt_wildcard_payload(cls, data, encoding=None, text_mode=True):
        if not text_mode:
            return cls._hx(data)
        if encoding and data and len(data) % 2 == 0 and cls._detect_utf16(data) == encoding:
            try:
                s = data.decode(encoding).rstrip("\x00")
                if cls._is_readable_utf16_text(s):
                    return s
            except UnicodeDecodeError:
                pass
        return cls._fmt_wildcard_bytes(data)
    @staticmethod
    def _format_regex_pattern(pattern, case_insensitive=False):
        if 0x2D in pattern:
            def endpoint(x):
                c = chr(x)
                return c if 0x20 <= x <= 0x7E and c not in "\\]-^" else f"\\x{x:02x}"

            ranges = []
            seen = set()

            def add_range(start, end):
                item = (start, end)
                if item not in seen:
                    seen.add(item)
                    ranges.append(item)

            for i in range(0, len(pattern), 3):
                start, end = pattern[i], pattern[i + 2]

                # 90 05 range regexes are case-insensitive. Canonicalize ASCII
                # alphabetic ranges so either a-z or A-Z is stored as [a-zA-Z].
                if case_insensitive:
                    if 0x41 <= start <= 0x5A and 0x41 <= end <= 0x5A:
                        add_range(start + 0x20, end + 0x20)
                        add_range(start, end)
                        continue
                    if 0x61 <= start <= 0x7A and 0x61 <= end <= 0x7A:
                        add_range(start, end)
                        add_range(start - 0x20, end - 0x20)
                        continue

                add_range(start, end)

            return "".join(f"{endpoint(start)}-{endpoint(end)}" for start, end in ranges)
        return "|".join(f"{x:02X}" for x in pattern)
    @classmethod
    def _format_regex_class(cls, pattern, case_insensitive=False):
        return f"[{cls._format_regex_pattern(pattern, case_insensitive=case_insensitive)}]"
    @classmethod
    def _format_90_04(cls, xx, pattern):
        # 90 04 XX YY <pattern>: match exactly XX bytes by regex.
        regex_class = cls._format_regex_class(pattern)
        return regex_class if xx == 1 else f"{regex_class}{{{xx}}}"
    @classmethod
    def _format_90_05(cls, xx, pattern):
        # 90 05 XX YY <pattern>: match up to XX bytes by regex.
        # Range expressions (those containing '-') are case-insensitive.
        regex_class = cls._format_regex_class(pattern, case_insensitive=(0x2D in pattern))
        return f"{regex_class}{{0,{xx}}}"
    @classmethod
    def _format_90_19(cls, xx, pattern):
        # 90 19 XX YY <pattern>: match exactly XX bytes that are NOT members
        # of the completed regex/byte-set expression whose encoded length is YY.
        #
        # The matcher builds an exclusion bitmap: specified literals/ranges are
        # marked and therefore rejected.  When the next byte is '-', consume a
        # three-byte range X-Y; otherwise consume one literal byte into the same
        # excluded character class.
        def endpoint(x):
            c = chr(x)
            return c if 0x20 <= x <= 0x7E and c not in "\\]-^" else f"\\x{x:02x}"

        parts = []
        i = 0
        while i < len(pattern):
            if i + 2 < len(pattern) and pattern[i + 1] == 0x2D:
                parts.append(f"{endpoint(pattern[i])}-{endpoint(pattern[i + 2])}")
                i += 3
            else:
                parts.append(endpoint(pattern[i]))
                i += 1

        regex_class = f"[^{''.join(parts)}]"
        return regex_class if xx == 1 else f"{regex_class}{{{xx}}}"
    @classmethod
    def _read_wildcard_token(cls, data, i):
        if i + 1 >= len(data) or data[i] != 0x90:
            return None
        op = data[i + 1]
        if op == 0x90:
            required_length = 2
        else:
            required_length = cls.WILDCARD_REQUIRED_LENGTH.get(op)
            # 0 means this opcode has no valid encoded length in kind_param_a.
            if required_length is None or required_length == 0:
                return None
        if i + required_length > len(data):
            return None
        token = {"kind": "wildcard", "op": op}
        if op in (0x01, 0x02):
            token["xx"] = data[i + 2]
            size = required_length
        elif op in (0x07, 0x08):
            token["xx"] = int.from_bytes(data[i + 2:i + 4], "little")
            size = required_length
        elif op in (
            0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x1C, 0x1D, 0x1E, 0x1F,
        ):
            # 90 <op> XX YY: XX YY is a uint16 little-endian byte count.
            token["xx"] = int.from_bytes(data[i + 2:i + 4], "little")
            size = required_length
        elif op == 0x03:
            xx, yy = data[i + 2:i + 4]
            size = required_length + xx + yy
            if i + size > len(data):
                return None
            token["xx"] = xx
            token["yy"] = yy
            token["seq_a"] = data[i + required_length:i + required_length + xx]
            token["seq_b"] = data[i + required_length + xx:i + size]
        elif op in (0x04, 0x05):
            xx, yy = data[i + 2:i + 4]
            if xx == 0 or yy == 0:
                return None
            size = required_length + yy
            if i + size > len(data):
                return None
            pattern = data[i + required_length:i + size]
            if 0x2D in pattern and (yy % 3 != 0 or not all(pattern[j + 1] == 0x2D for j in range(0, yy, 3))):
                return None
            token["xx"] = xx
            token["yy"] = yy
            token["pattern"] = pattern
        elif op == 0x19:
            # 90 19 XX YY <regex>: exact XX bytes excluding the completed set.
            # YY is the encoded length of the regex/byte-set payload.
            xx, yy = data[i + 2:i + 4]
            if xx == 0 or yy == 0:
                return None
            size = required_length + yy
            if i + size > len(data):
                return None
            token["xx"] = xx
            token["yy"] = yy
            token["pattern"] = data[i + required_length:i + size]
        elif op == 0x17:
            # 90 17 XX <length_1 ... length_XX> <alternative payloads...>
            #
            # XX is the number of alternatives. Each following length byte
            # contains the encoded byte length of one alternative. The
            # alternatives are stored consecutively after the length table and
            # may themselves contain nested wildcards.
            count = data[i + 2]
            lengths_start = i + required_length
            lengths_end = lengths_start + count
            if lengths_end > len(data):
                return None

            lengths = list(data[lengths_start:lengths_end])
            payload_size = sum(lengths)
            size = required_length + count + payload_size
            if i + size > len(data):
                return None

            alternatives = []
            p = lengths_end
            for alt_size in lengths:
                alt_end = p + alt_size
                alternatives.append(data[p:alt_end])
                p = alt_end

            token["xx"] = count
            token["lengths"] = lengths
            token["alternatives"] = alternatives
        elif op == 0x1B:
            # 90 1B XX: XX is a zero-based backreference index within the
            # current subrule's wildcard/backref context.
            token["xx"] = data[i + 2]
            size = required_length
        else:
            size = required_length
        token["size"] = size
        token["raw"] = data[i:i + size]
        return token

    @classmethod
    def _is_wildcard(cls, data, i):
        return cls._read_wildcard_token(data, i) is not None

    @staticmethod
    def _byte_word(count):
        return "byte" if count == 1 else "bytes"

    @classmethod
    def _format_counted_bytes(cls, count):
        return f"{count} {cls._byte_word(count)}"

    @classmethod
    def _make_literal_token(cls, raw):
        value, is_text = cls._fmt_inline_info(raw)
        return {
            "kind": "literal",
            "raw": raw,
            "value": value,
            "is_text": is_text,
        }

    @classmethod
    def _logical_match_max_len(cls, token):
        """Return the maximum contiguous input-byte count represented by token.

        This is used only to linearize 90 09 / 90 0A for display.  Exact
        fixed-length wildcards contribute their actual matched input size, not
        their encoded rule-byte size.  Variable-length wildcards contribute
        their declared upper bound.
        """
        kind = token.get("kind")
        if kind == "literal":
            return len(token.get("raw", b""))
        if kind == "padding":
            return token.get("count", 0)
        if kind != "wildcard":
            return None

        op = token["op"]

        if op in (
            0x01, 0x02, 0x07, 0x08,
            0x04, 0x05, 0x19,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x1C, 0x1D, 0x1E, 0x1F,
        ):
            return token.get("xx")

        if op == 0x90:
            return 1

        # These consume a signed displacement from input before repositioning.
        if op == 0x14:
            return 1
        if op == 0x15:
            return 2
        if op == 0x16:
            return 4

        # 90 09 / 90 0A themselves are control operators and do not represent
        # bytes that should be copied into the reconstructed linear pattern.
        if op in (0x09, 0x0A):
            return 0

        # Branch-follow, choices and backrefs do not have a single statically
        # known contiguous byte length here.
        return None

    @classmethod
    def _split_token_for_logical_bytes(cls, token, take):
        """Split a deterministic token after `take` matched input bytes.

        Returns (left, right), where either side may be None.  The split is
        purely for display/reordering and does not modify the original raw
        wildcard list.
        """
        total = cls._logical_match_max_len(token)
        if total is None or take <= 0 or take >= total:
            return None, None

        kind = token.get("kind")

        if kind == "literal":
            raw = token["raw"]
            return (
                cls._make_literal_token(raw[:take]),
                cls._make_literal_token(raw[take:]),
            )

        if kind == "padding":
            left = dict(token)
            right = dict(token)
            left["count"] = take
            right["count"] = total - take
            return left, right

        if kind != "wildcard":
            return None, None

        op = token["op"]

        # Only exact-count wildcards can be split without changing their
        # semantics.  Up-to wildcards remain atomic.
        exact_count_ops = {
            0x01, 0x07, 0x04, 0x19,
            0x0B, 0x0D, 0x0F, 0x11,
            0x1C, 0x1E,
        }
        if op not in exact_count_ops:
            return None, None

        left = dict(token)
        right = dict(token)
        left["xx"] = take
        right["xx"] = total - take
        return left, right

    @classmethod
    def _take_logical_prefix(cls, tokens, wanted):
        """Take up to `wanted` matched input bytes from the token sequence."""
        captured = []
        remainder = list(tokens)
        remaining = wanted

        while remainder and remaining > 0:
            token = remainder[0]
            logical_len = cls._logical_match_max_len(token)

            if logical_len is None:
                break

            # Zero-width control token: keep it with the captured rule fragment
            # and continue until actual input bytes are accounted for.
            if logical_len == 0:
                captured.append(remainder.pop(0))
                continue

            if logical_len <= remaining:
                captured.append(remainder.pop(0))
                remaining -= logical_len
                continue

            left, right = cls._split_token_for_logical_bytes(token, remaining)
            if left is None:
                break

            captured.append(left)
            remainder[0] = right
            remaining = 0

        return captured, remainder, wanted - remaining

    @classmethod
    def _debug_render_token(cls, token):
        """Render one token for the 90 09/90 0A BEFORE/AFTER logger."""
        kind = token.get("kind")

        if kind == "literal":
            raw = token.get("raw", b"")
            value, is_text = cls._fmt_inline_info(raw)
            return value if is_text else cls._hx(raw)

        if kind == "padding":
            return cls._render_padding_token(token)

        if kind != "wildcard":
            return str(token)

        op = token.get("op")

        # Keep 90 09 / 90 0A visible in the BEFORE form.
        if op in (0x09, 0x0A):
            n = token.get("xx", 0)
            return f"[90 {op:02X} {n & 0xFF:02X} {(n >> 8) & 0xFF:02X}]"

        try:
            return cls._render_wildcard_token(
                token,
                None,
                False,
                [],
                [],
                0,
            )
        except Exception:
            raw = token.get("raw", b"")
            return f"[{cls._hx(raw)}]"

    @classmethod
    def _debug_render_tokens(cls, tokens):
        return " ".join(
            part
            for part in (cls._debug_render_token(token) for token in tokens)
            if part
        )

    @classmethod
    def _log_backward_change(cls, before_tokens, after_tokens):
        return

    @classmethod
    def _apply_backward_reordering(cls, tokens):
        """Linearize 90 09 / 90 0A for database display.

        For:
            etc1 90 09 N etc2
        take N logical input bytes from the beginning of etc2 and move them in
        front of etc1. If etc2 describes fewer than N bytes, insert:
            [Exact K byte(s)]

        90 0A is the same display transformation but pads the missing distance
        with:
            [Upto K byte(s)]

        If LOG_BACKWARD_REORDER is enabled, log the complete subrule/token
        sequence before processing and after all 90 09/90 0A transformations.
        """
        tokens = list(tokens)

        has_backward = any(
            token.get("kind") == "wildcard"
            and token.get("op") in (0x09, 0x0A)
            for token in tokens
        )
        before_tokens = list(tokens) if has_backward else None

        guard = 0
        while guard < 64:
            guard += 1
            index = next(
                (
                    i for i, token in enumerate(tokens)
                    if token.get("kind") == "wildcard"
                    and token.get("op") in (0x09, 0x0A)
                ),
                None,
            )
            if index is None:
                break

            control = tokens[index]
            wanted = control.get("xx", 0)
            before = tokens[:index]
            after = tokens[index + 1:]

            captured, remainder, captured_len = cls._take_logical_prefix(
                after, wanted
            )
            missing = max(0, wanted - captured_len)

            pad = []
            if missing:
                pad.append({
                    "kind": "padding",
                    "count": missing,
                    "mode": "exact" if control["op"] == 0x09 else "upto",
                })

            tokens = captured + pad + before + remainder

        if has_backward:
            cls._log_backward_change(before_tokens, tokens)

        return tokens

    @classmethod
    def _render_padding_token(cls, token):
        count = token["count"]
        label = "Exact" if token["mode"] == "exact" else "Upto"
        return f"[{label} {cls._format_counted_bytes(count)}]"

    @classmethod
    def _render_nested_payload(cls, data, rule_encoding, text_mode, wildcards, backref_registry, depth=0):
        # Dynamic byte strings (90 03 alternatives and 90 17 branches) may
        # themselves contain encoded wildcards.  Tokenize the nested stream,
        # apply the same 90 09 / 90 0A backward linearization used at top level,
        # then recursively render every remaining wildcard.
        if not data or depth >= 32:
            return cls._fmt_wildcard_payload(data, rule_encoding, text_mode)

        tokens = []
        i = start = 0

        while i < len(data):
            token = cls._read_wildcard_token(data, i)
            if token is None:
                i += 1
                continue

            if i > start:
                tokens.append(cls._make_literal_token(data[start:i]))

            wildcards.append(cls._hx(token["raw"]))

            if token["op"] == 0x00:
                tail_start = i + token["size"]
                if tail_start < len(data):
                    tokens.append(cls._make_literal_token(data[tail_start:]))
                break

            tokens.append(token)
            i += token["size"]
            start = i
        else:
            if start < len(data):
                tokens.append(cls._make_literal_token(data[start:]))

        if not tokens:
            return cls._fmt_wildcard_payload(data, rule_encoding, text_mode)

        tokens = cls._apply_backward_reordering(tokens)

        rendered = []
        for token in tokens:
            kind = token.get("kind")

            if kind == "literal":
                rendered.append(
                    cls._fmt_wildcard_payload(
                        token["raw"], rule_encoding, text_mode
                    )
                )
                continue

            if kind == "padding":
                rendered.append(cls._render_padding_token(token))
                continue

            nested_registry = list(backref_registry)
            if token["op"] not in (0x00, 0x90):
                token["wildcard_index"] = len(nested_registry)
                value = cls._render_wildcard_token(
                    token,
                    rule_encoding,
                    text_mode,
                    wildcards,
                    nested_registry,
                    depth + 1,
                )
                nested_registry.append({"token": token, "rendered": value})
            else:
                value = cls._render_wildcard_token(
                    token,
                    rule_encoding,
                    text_mode,
                    wildcards,
                    nested_registry,
                    depth + 1,
                )
            rendered.append(value)

        separator = "" if text_mode else " "
        return separator.join(x for x in rendered if x)

    @classmethod
    def _render_wildcard_token(cls, token, rule_encoding, text_mode, wildcards, backref_registry, depth=0):
        op = token["op"]
        if op in (0x01, 0x07):
            return f"[{cls._format_counted_bytes(token['xx'])}]"
        if op in (0x02, 0x08):
            return f"[0-{token['xx']} {cls._byte_word(token['xx'])}]"

        typed_wildcards = {
            0x0B: ("CRLF", False),
            0x0C: ("CRLF", True),
            0x0D: ("WhiteSpace", False),
            0x0E: ("WhiteSpace", True),
            0x0F: ("Numeric", False),
            0x10: ("Numeric", True),
            0x11: ("Alphabetic", False),
            0x12: ("Alphabetic", True),
            0x1C: ("Alphanumeric", False),
            0x1D: ("Alphanumeric", True),
            0x1E: ("HexSet", False),
            0x1F: ("HexSet", True),
        }
        typed = typed_wildcards.get(op)
        if typed is not None:
            wildcard_type, upto = typed
            if upto:
                return f"[Upto {cls._format_counted_bytes(token['xx'])} {wildcard_type}]"
            return f"[{cls._format_counted_bytes(token['xx'])} {wildcard_type}]"

        if op == 0x03:
            # Each 90 03 alternative is a separate runtime branch. Start both
            # from the same current per-subrule backref state.
            seq_a = cls._render_nested_payload(
                token["seq_a"], rule_encoding, text_mode, wildcards, list(backref_registry), depth
            )
            seq_b = cls._render_nested_payload(
                token["seq_b"], rule_encoding, text_mode, wildcards, list(backref_registry), depth
            )
            return f"[({seq_a} | {seq_b})]"
        if op == 0x04:
            return cls._format_90_04(token["xx"], token["pattern"])
        if op == 0x05:
            return cls._format_90_05(token["xx"], token["pattern"])
        if op == 0x17:
            # 90 17 contains complete nested rule fragments. Parse each branch
            # recursively using the same logic as nested 90 03 payloads.
            # Every alternative starts from the same current per-subrule state.
            alternatives = [
                cls._render_nested_payload(
                    alt,
                    rule_encoding,
                    text_mode,
                    wildcards,
                    list(backref_registry),
                    depth,
                )
                for alt in token["alternatives"]
            ]
            return f"[({' | '.join(alternatives)})]"
        if op == 0x13:
            return "[Mandatory JMP/JCC/JCXZ ADDR]"
        if op == 0x18:
            return "[Optional JMP/JCC/JCXZ ADDR]"
        if op == 0x14:
            return "[Relative int8 from input]"
        if op == 0x15:
            return "[Relative int16 from input]"
        if op == 0x16:
            return "[Relative int32 from input]"
        if op == 0x19:
            return cls._format_90_19(token["xx"], token["pattern"])
        if op == 0x1B:
            index = token["xx"]
            # 90 1B XX clones the wildcard identified by the zero-based
            # wildcard index within the current subrule.
            return f"[Cloning wildcard {index}]"
        if op == 0x90:
            # 90 90 is an escaped literal 0x90 byte in the matched data.
            return "90"
        return f"[{cls._hx(token['raw'])}]"

    @classmethod
    def _parse_wildcards(cls, data: bytes, number_of_subrules: int, wildcard_mode: bool = True):
        lines = []
        wildcards = []
        # Backreference state is deliberately local to this _parse_wildcards()
        # call. _parse_pehstr_ext() calls this once per subrule, so indexes reset
        # to zero when the parser advances to the next subrule.
        backref_registry = []
        def parse_by_wildcard():
            i = start = 0
            tokens = []
            terminated = False
            while i < len(data):
                token = cls._read_wildcard_token(data, i)
                if token is None:
                    i += 1
                    continue
                if i > start:
                    raw = data[start:i]
                    value, is_text = cls._fmt_inline_info(raw)
                    tokens.append(cls._make_literal_token(raw))
                op = token["op"]
                wildcards.append(cls._hx(token["raw"]))
                if op == 0x00:
                    terminated = True
                    start = i + token["size"]
                    break
                tokens.append(token)
                i += token["size"]
                start = i
            if not terminated and start < len(data):
                raw = data[start:]
                value, is_text = cls._fmt_inline_info(raw)
                tokens.append(cls._make_literal_token(raw))
            if not tokens:
                return terminated, False

            tokens = cls._apply_backward_reordering(tokens)

            literals = [t for t in tokens if t["kind"] == "literal"]
            text_mode = bool(literals) and all(t["is_text"] for t in literals)
            encodings = [cls._detect_utf16(t["raw"]) for t in literals]
            encodings = [enc for enc in encodings if enc]
            rule_encoding = max(set(encodings), key=encodings.count) if encodings else None
            rendered = []
            for token in tokens:
                if token["kind"] == "literal":
                    rendered.append(token["value"] if text_mode else cls._hx(token["raw"]))
                    continue

                if token["kind"] == "padding":
                    rendered.append(cls._render_padding_token(token))
                    continue

                # The matcher increments its backref/wildcard index for normal
                # wildcard opcodes. 90 00 (terminator) and 90 90 (escaped
                # literal 0x90) are handled before that counter and do not count.
                if token["op"] not in (0x00, 0x90):
                    token["wildcard_index"] = len(backref_registry)
                    value = cls._render_wildcard_token(
                        token, rule_encoding, text_mode, wildcards, backref_registry
                    )
                    backref_registry.append({"token": token, "rendered": value})
                else:
                    value = cls._render_wildcard_token(
                        token, rule_encoding, text_mode, wildcards, backref_registry
                    )
                rendered.append(value)
            if text_mode:
                lines.append(f'        [Rule] "{"".join(rendered)}"')
            else:
                lines.append(f"        [Rule] {' '.join(rendered)}")
            return terminated, text_mode
        def parse_by_subrules():
            pos = count = 0
            all_text = True
            while pos < len(data) and count < number_of_subrules:
                while pos < len(data) and data[pos] == 0:
                    pos += 1
                if pos >= len(data):
                    break
                enc = cls._detect_utf16(data[pos:])
                if enc:
                    end = pos
                    while end + 1 < len(data):
                        if data[end:end + 2] == b"\x00\x00" and (end - pos) % 2 == 0:
                            break
                        end += 2
                    next_pos = end + 2 if end + 1 < len(data) else len(data)
                else:
                    end = data.find(b"\x00", pos)
                    if end == -1:
                        end = len(data)
                        next_pos = end
                    else:
                        next_pos = end + 1
                chunk = data[pos:end]
                if chunk:
                    count += 1
                    value, is_text = cls._fmt_info(chunk)
                    all_text &= is_text
                    if is_text:
                        lines.append(f"        [String {count}] {value}")
                pos = next_pos
            return False, all_text and count > 0
        if not wildcard_mode:
            terminated, is_text = parse_by_subrules()
            return lines, terminated, is_text, wildcards
        has_wildcard = any(cls._is_wildcard(data, i) for i in range(len(data) - 1))
        terminated, is_text = parse_by_wildcard() if has_wildcard else parse_by_subrules()
        return lines, terminated, is_text, wildcards
    @classmethod
    def _parse_pehstr_ext(cls, data: bytes, number_of_subrules: int):
        lines = []
        wildcards = []
        i = parsed = 0
        while i < len(data) and parsed < number_of_subrules:
            if i == len(data) - 2 and data.endswith(b"\x00\x00"):
                break
            if i + 4 > len(data):
                lines.append(f"    [!] Truncated PEHSTR_EXT header at offset 0x{i:X}")
                break
            low, high, size = data[i:i + 3]
            pattern_flag = data[i + 3]
            flag_size = 1
            if pattern_flag & 0x80:
                if i + 5 > len(data):
                    lines.append(f"    [!] Truncated 2-byte Pattern Flag at offset 0x{i + 3:X}")
                    break
                pattern_flag |= data[i + 4] << 8
                flag_size = 2
            subrule_start = i + 3 + flag_size
            end = subrule_start + size
            if end > len(data):
                lines.append(f"    [!] Invalid subrule size {size} at offset 0x{i:X}")
                break
            subrule = data[subrule_start:end]
            weight = int.from_bytes(bytes((low, high)), "little", signed=True)
            wildcard_mode = bool(pattern_flag & 0x2)
            sub_lines, terminated, is_text, sub_wildcards = cls._parse_wildcards(subrule, abs(weight), wildcard_mode)
            wildcards.extend(sub_wildcards)
            rule_lines = [line.strip() for line in sub_lines if '[Rule]' in line]
            string_lines = [line.strip() for line in sub_lines if '[String' in line]
            flag_text = f"0x{pattern_flag:X}"
            if sub_wildcards and rule_lines:
                lines.append(f"    Subrule {parsed + 1}: Weight: {weight}, Size: {size}, Pattern Flag: {flag_text}, " + " | ".join(rule_lines))
            elif is_text and string_lines:
                lines.append(f"    Subrule {parsed + 1}: Weight: {weight}, Size: {size}, Pattern Flag: {flag_text}, " + " | ".join(string_lines))
            else:
                lines.append(f"    Subrule {parsed + 1}: Weight: {weight}, Size: {size}, Pattern Flag: {flag_text}, Bytes: {subrule.hex()}")
            parsed += 1
            i = end
        return lines, wildcards
    @classmethod
    def get_weight_stats(cls, content: bytes):
        if len(content) < 7:
            return None
        threshold = (content[3] << 8) | content[2]
        number_of_subrules = (content[5] << 8) | content[4]
        split = cls._split_header_and_rule_data(content)
        if split is None:
            return None
        _, data = split
        weights = []
        parsed = 0
        i = 0
        while parsed < number_of_subrules and i < len(data):
            if i == len(data) - 2 and data.endswith(b"\x00\x00"):
                break
            if i + 4 > len(data):
                break
            low, high, size = data[i:i + 3]
            pattern_flag = data[i + 3]
            flag_size = 1
            if pattern_flag & 0x80:
                if i + 5 > len(data):
                    break
                flag_size = 2
            end = i + 3 + flag_size + size
            if end > len(data):
                break
            weights.append(int.from_bytes(bytes((low, high)), "little", signed=True))
            parsed += 1
            i = end
        return threshold, weights, parsed
    @classmethod
    def parse(cls, content: bytes):
        if len(content) < 7:
            return [f"    [!] PEHSTR_EXT content too short: {len(content)} byte(s)"], []
        unknown = int.from_bytes(content[0:2], "little")
        threshold = (content[3] << 8) | content[2]
        number_of_subrules = (content[5] << 8) | content[4]
        split = cls._split_header_and_rule_data(content)
        if split is None:
            return [f"    [!] PEHSTR_EXT rule label is not null-terminated"], []
        rule_label, rule_data = split
        lines = [f'    Unknown: {unknown}, Threshold Required: {threshold}, SubRules Number: {number_of_subrules}, Rule Label: "{rule_label}", Rule Data Length: {len(rule_data)}']
        sub_lines, wildcards = cls._parse_pehstr_ext(rule_data, number_of_subrules)
        lines.extend(sub_lines)
        return lines, wildcards
class ThreatDatabase:
    @staticmethod
    def _extract_src(parsed_text):
        if not parsed_text:
            return None
        marker = "    Src:"
        pos = parsed_text.find(marker)
        if pos < 0:
            return None
        source = parsed_text[pos + len(marker):].lstrip("\r\n")
        if not source or source.lstrip().startswith("[!]"):
            return None
        return source

    @classmethod
    def _load_previous_lua_cache(cls, db_path):
        cache = {}
        if not os.path.isfile(db_path):
            return cache

        conn = None
        try:
            conn = sqlite3.connect(db_path)
            columns = {
                row[1]
                for row in conn.execute("PRAGMA table_info(lua_cache)")
            }
            # Current cache format is keyed only by LUASTANDALONE parse order.
            if {"lua_index", "mplua_sha256", "source"}.issubset(columns):
                for lua_index, mplua_sha256, source in conn.execute(
                    "SELECT lua_index, mplua_sha256, source FROM lua_cache"
                ):
                    if source and mplua_sha256:
                        cache[int(lua_index)] = (str(mplua_sha256), source)
        except sqlite3.Error:
            pass
        finally:
            if conn is not None:
                conn.close()

        return cache

    def __init__(self, db_path="Threats.db"):
        self.db_path = db_path

        # Keep decompiled Lua source across parser runs even though the regular
        # threat/signature database is rebuilt from scratch.
        previous_lua_cache = self._load_previous_lua_cache(db_path)

        if os.path.exists(db_path):
            os.remove(db_path)

        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript("""
            CREATE TABLE threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_index INTEGER NOT NULL UNIQUE,
                start_offset TEXT NOT NULL,
                end_offset TEXT,
                complete INTEGER NOT NULL,
                signature_count INTEGER NOT NULL
            );
            CREATE TABLE signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_id INTEGER NOT NULL,
                signature_index INTEGER NOT NULL,
                offset TEXT NOT NULL,
                sig_type INTEGER NOT NULL,
                sig_name TEXT NOT NULL,
                size_low INTEGER NOT NULL,
                size_high INTEGER NOT NULL,
                size INTEGER NOT NULL,
                content BLOB NOT NULL,
                parsed_text TEXT,
                contains_wildcard TEXT,
                FOREIGN KEY(threat_id) REFERENCES threats(id) ON DELETE CASCADE
            );
            CREATE TABLE lua_cache (
                lua_index INTEGER PRIMARY KEY,
                mplua_sha256 TEXT NOT NULL,
                source TEXT NOT NULL
            );
            CREATE INDEX idx_signatures_threat_id ON signatures(threat_id);
            CREATE INDEX idx_signatures_type ON signatures(sig_type);
        """)

        if previous_lua_cache:
            self.conn.executemany(
                "INSERT OR REPLACE INTO lua_cache(lua_index, mplua_sha256, source) VALUES (?, ?, ?)",
                [
                    (lua_index, mplua_sha256, source)
                    for lua_index, (mplua_sha256, source) in previous_lua_cache.items()
                ],
            )

        self.conn.commit()

    def get_lua_source(self, lua_index):
        row = self.conn.execute(
            "SELECT mplua_sha256, source FROM lua_cache WHERE lua_index = ?",
            (int(lua_index),),
        ).fetchone()
        return (row[0], row[1]) if row else (None, None)

    def save_lua_source(self, lua_index, mplua_sha256, source):
        if not source or not mplua_sha256:
            return
        self.conn.execute(
            "INSERT OR REPLACE INTO lua_cache(lua_index, mplua_sha256, source) VALUES (?, ?, ?)",
            (int(lua_index), str(mplua_sha256), source),
        )
        self.conn.commit()

    def save_threat(self, threat: ThreatRecord):
        end_offset = None
        if threat.signatures:
            last = threat.signatures[-1]
            end_offset = last.offset + 4 + last.size
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO threats(threat_index, start_offset, end_offset, complete, signature_count) VALUES (?, ?, ?, ?, ?)",
            (threat.threat_id, f"0x{threat.start_offset:X}", f"0x{end_offset:X}" if end_offset is not None else None, int(threat.complete), len(threat.signatures))
        )
        threat_db_id = cur.lastrowid
        cur.executemany(
            "INSERT INTO signatures(threat_id, signature_index, offset, sig_type, sig_name, size_low, size_high, size, content, parsed_text, contains_wildcard) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (threat_db_id, i, f"0x{sig.offset:X}", sig.sig_type, sig.sig_name, sig.size_low, sig.size_high, sig.size, sqlite3.Binary(sig.content), "\n".join(sig.parsed_lines), sig.contains_wildcard)
                for i, sig in enumerate(threat.signatures, 1)
            ]
        )
        self.conn.commit()

    def close(self):
        self.conn.close()

class DefenderSignatureStreamParser:
    def __init__(self, db_path="Threats.db", weight_log_path=WEIGHT_ANOMALY_LOG, weight_anomaly_ratio=WEIGHT_ANOMALY_RATIO):
        self.db = ThreatDatabase(db_path)
        self.weight_log_path = weight_log_path
        self.weight_anomaly_ratio = weight_anomaly_ratio
        with open(self.weight_log_path, "w", encoding="utf-8"):
            pass
        self.current_threat: Optional[ThreatRecord] = None
        self.threat_counter = 0
        self._source_data = b""

        # LUASTANDALONE-only counter, reset for each parser run.
        # The same input/order yields the same filenames/cache keys:
        #   lua_drop/0.luac, lua_drop/1.luac, ...
        self.lua_blob_counter = 0
        self.lua_drop_dir = os.path.join(
            os.path.dirname(os.path.abspath(db_path)),
            "lua_drop",
        )
        os.makedirs(self.lua_drop_dir, exist_ok=True)

        self.handlers = {
            0x61: PEHSTRSignatureParser,
            0xBD: LuaStandaloneSignatureParser,
        }

        # All Defender HSTR_EXT signature families share the same extended
        # subrule/wildcard parser. This includes PEHSTR_EXT/PEHSTR_EXT2 and
        # ELF/MACHO/DOS/MACRO/DEX/JAVA/AR/SWF/AUTOIT/INNO/CMD/MDB/DMG variants.
        for _sig_type, _sig_name in SIGNATURE_TYPES.items():
            if "HSTR_EXT" in _sig_name:
                self.handlers[_sig_type] = PEHSTRExtSignatureParser
        self.record_handlers = {THREAT_BEGIN: ThreatBeginSignatureParser, THREAT_END: ThreatEndSignatureParser, FILEPATH: FolderNameSignatureParser, FOLDERNAME: FolderNameSignatureParser, REGKEY: RegKeySignatureParser, ASEP_FILEPATH: FolderNameSignatureParser, ASEP_FOLDERNAME: FolderNameSignatureParser, FRIENDLYFILE_SHA256: FriendlyFileHashSignatureParser, FRIENDLYFILE_SHA512: FriendlyFileHashSignatureParser}
    def _parse_signature_content(self, record: SignatureRecord):
        handler = self.handlers.get(record.sig_type)
        record_handler = self.record_handlers.get(record.sig_type)
        try:
            if record_handler:
                record.parsed_lines = record_handler.parse(record)
            elif record.sig_type == 0xBD:
                lua_index = self.lua_blob_counter
                self.lua_blob_counter += 1

                cached_hash, cached_source = self.db.get_lua_source(lua_index)
                result, source, mplua_sha256 = LuaStandaloneSignatureParser.parse(
                    record.content,
                    lua_index,
                    self.lua_drop_dir,
                    cached_source=cached_source,
                    cached_mplua_sha256=cached_hash,
                )
                record.parsed_lines = result

                if source and mplua_sha256:
                    self.db.save_lua_source(
                        lua_index,
                        mplua_sha256,
                        source,
                    )
            elif handler:
                result = handler.parse(record.content)
                if isinstance(result, tuple):
                    record.parsed_lines, wildcards = result
                    if wildcards:
                        record.contains_wildcard = " | ".join(dict.fromkeys(wildcards))
                else:
                    record.parsed_lines = result
                if hasattr(handler, "get_weight_stats"):
                    stats = handler.get_weight_stats(record.content)
                    if stats is not None:
                        record.threshold_required, record.subrule_weights, record.parsed_subrule_count = stats
            else:
                record.parsed_lines = CommonSignatureParser.parse(record)
        except Exception as e:
            record.parsed_lines = [f"    [!] Parser error: {type(e).__name__}: {e}"]
        return record
    def _start_threat(self, record: SignatureRecord):
        if self.current_threat is not None:
            self._finish_threat(complete=False)
        self.threat_counter += 1
        self.current_threat = ThreatRecord(self.threat_counter, record.offset)
        self.current_threat.add_signature(record)
    def _validate_signature_offset(self, sig: SignatureRecord):
        if sig.offset < 0 or sig.offset + 4 > len(self._source_data):
            return False, None, None
        actual_type = self._source_data[sig.offset]
        actual_size_low = self._source_data[sig.offset + 1]
        actual_size_high = int.from_bytes(self._source_data[sig.offset + 2:sig.offset + 4], "little")
        actual_size = (actual_size_high << 8) | actual_size_low
        return actual_type == sig.sig_type and actual_size == sig.size, actual_type, actual_size
    def _log_weight_anomalies(self, threat: ThreatRecord):
        entries = []
        for sig in threat.signatures:
            threshold = sig.threshold_required
            if threshold is None or not sig.subrule_weights:
                continue
            valid_offset, actual_type, actual_size = self._validate_signature_offset(sig)
            if not valid_offset:
                actual_type_text = "EOF" if actual_type is None else f"0x{actual_type:02X}"
                actual_size_text = "EOF" if actual_size is None else str(actual_size)
                entries.append(f"[DESYNC] Offset=0x{sig.offset:X} ExpectedSig={sig.sig_name}(0x{sig.sig_type:02X}) ExpectedSize={sig.size} ActualType={actual_type_text} ActualSize={actual_size_text}")
                continue
            for subrule_index, weight in enumerate(sig.subrule_weights, 1):
                anomalous = weight > 0 if threshold == 0 else weight > threshold * self.weight_anomaly_ratio
                if not anomalous:
                    continue
                ratio = "INF" if threshold == 0 else f"{weight / threshold:.2f}x"
                entries.append(f"Offset=0x{sig.offset:X} Sig={sig.sig_name}(0x{sig.sig_type:02X}) Subrule={subrule_index} Threshold={threshold} Weight={weight} Ratio={ratio} Threat={threat.threat_id}")
        if entries:
            with open(self.weight_log_path, "a", encoding="utf-8") as f:
                f.write("\n".join(entries) + "\n")
    def _finish_threat(self, complete=True):
        if self.current_threat is None:
            return
        self.current_threat.complete = complete
        self._log_weight_anomalies(self.current_threat)
        self.db.save_threat(self.current_threat)
        self.current_threat = None
    def parse(self, data: bytes):
        self._source_data = data
        index = 0
        while index < len(data):
            if index + 4 > len(data):
                break
            sig_type = data[index]
            size_low = data[index + 1]
            size_high = int.from_bytes(data[index + 2:index + 4], "little")
            size = (size_high << 8) | size_low
            end = index + 4 + size
            if end > len(data):
                break
            content = data[index + 4:end]

            record = SignatureRecord(
                index,
                sig_type,
                SIGNATURE_TYPES.get(sig_type, "Unknown"),
                size,
                content,
                size_low,
                size_high,
            )
            self._parse_signature_content(record)
            if sig_type == THREAT_BEGIN:
                self._start_threat(record)
            elif self.current_threat is not None:
                if sig_type == THREAT_END and self.current_threat.signatures:
                    begin_record = self.current_threat.signatures[0]
                    if begin_record.sig_type == THREAT_BEGIN and len(begin_record.content) >= 4 and len(record.content) >= 4:
                        begin_signature_id = int.from_bytes(begin_record.content[:4], "little")
                        end_signature_id = int.from_bytes(record.content[:4], "little")
                        if begin_signature_id != end_signature_id:
                            record.parsed_lines.append(f"    [!] SignatureId mismatch: THREAT_BEGIN=0x{begin_signature_id:08X}, THREAT_END=0x{end_signature_id:08X}")
                self.current_threat.add_signature(record)
                if sig_type == THREAT_END:
                    self._finish_threat(complete=True)
            index = end
        if self.current_threat is not None:
            self._finish_threat(complete=False)
        return self.threat_counter
    def close(self):
        self.db.close()
def main():
    base_vdm_path = os.path.abspath(BASE_VDM_PATH)
    delta_vdm_path = os.path.abspath(DELTA_VDM_PATH)
    base_decompressed_path = os.path.abspath(BASE_DECOMPRESSED_PATH) if BASE_DECOMPRESSED_PATH else _auto_decompressed_path(base_vdm_path)
    delta_decompressed_path = os.path.abspath(DELTA_DECOMPRESSED_PATH) if DELTA_DECOMPRESSED_PATH else _auto_decompressed_path(delta_vdm_path)
    if MERGED_DECOMPRESSED_PATH:
        merged_decompressed_path = os.path.abspath(MERGED_DECOMPRESSED_PATH)
    else:
        merged_decompressed_path = os.path.splitext(base_vdm_path)[0] + "_merged.decompressed"
    db_path = os.path.abspath(OUTPUT_DB) if OUTPUT_DB else os.path.splitext(merged_decompressed_path)[0] + ".db"
    weight_log_path = os.path.abspath(WEIGHT_LOG_FILE) if WEIGHT_LOG_FILE else os.path.splitext(db_path)[0] + "_WeightAnomaly.log"
    base = _unpack_vdm_to_file(base_vdm_path, base_decompressed_path)
    delta = _unpack_vdm_to_file(delta_vdm_path, delta_decompressed_path)
    merged = DeltaMerger.merge(base, delta, verbose=MERGE_VERBOSE)
    with open(merged_decompressed_path, "wb") as f:
        f.write(merged)
    parser = DefenderSignatureStreamParser(db_path, weight_log_path=weight_log_path)
    parse_success = False
    try:
        threat_count = parser.parse(merged)
        parse_success = True
    finally:
        parser.close()
    if parse_success and DELETE_BASE_DELTA_DECOMPRESSED_AFTER_PARSE:
        for temp_path in (base_decompressed_path, delta_decompressed_path):
            try:
                os.remove(temp_path)
            except FileNotFoundError:
                pass
            except OSError:
                pass
if __name__ == "__main__":
    main()