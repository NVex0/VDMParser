# Windows Defender's Rules Database Parser

Currently supports these signatures:

SIGNATURE_TYPE_THREAT_BEGIN

SIGNATURE_TYPE_THREAT_END

SIGNATURE_TYPE_FOLDERNAME

SIGNATURE_TYPE_FILEPATH

SIGNATURE_TYPE_ASEP_FILEPATH

SIGNATURE_TYPE_ASEP_FOLDERNAME

SIGNATURE_TYPE_REGKEY

SIGNATURE_TYPE_PEHSTR

SIGNATURE_TYPE_FRIENDLYFILE_SHA512

SIGNATURE_TYPE_FRIENDLYFILE_SHA256

SIGNATURE_TYPE_VDLL_X86

SIGNATURE_TYPE_LUASTANDALONE

SIGNATURE_TYPE_DBVAR

SIGNATURE_TYPE_KCRCE

SIGNATURE_TYPE_KCRCEX

SIGNATURE_TYPE_SIGTREE

SIGNATURE_TYPE_SIGTREE_EXT

SIGNATURE_TYPE_SIGTREE_BM

SIGNATURE_TYPE_STATIC

SIGNATURE_TYPE_PESTATIC

SIGNATURE_TYPE_PESTATICEX

SIGNATURE_TYPE_KVIR32

SIGNATURE_TYPE_POLYVIR32

SIGNATURE_TYPE_LOCALHASH

SIGNATURE_TYPE_NDAT

SIGNATURE_TYPE_NSCRIPT_CURE

SIGNATURE_TYPE_DEFAULTS

SIGNATURE_TYPE_PEPCODE

SIGNATURE_TYPE_PUA_APPMAP

SIGNATURE_TYPE_FOPEX

SIGNATURE_TYPE_PEBMPAT

SIGNATURE_TYPE_AAGGREGATOR

SIGNATURE_TYPE_KPAT

SIGNATURE_TYPE_KPATEX

Generic binary parsing for unsupported/unknown binary-oriented signature types.

Generic text/string parsing for selected text-oriented signature types.

Supports every HSTR_EXT variant currently present in the signature type map.

THREAT_BEGIN / THREAT_END

SIGNATURE_TYPE_THREAT_BEGIN currently parses:

ThreatID

Threat name

MPTHREAT_CATEGORY as a friendly category name

Span rule counts

MPTHREAT_SEVERITY as a friendly severity name

MPTHREAT_ACTION as a friendly action name

Threat short description

Threat advice description

Example:

ThreatID: 0x00000645
ThreatName: "Dialer:Win32/Aconti"
Category: Dialer
Span 1 - Rule Count: 5
Severity: Severe
Action: Quarantine
ThreatShortDescription: "This program dials toll numbers to gain access to adult content."
ThreatAdviseDescription: "Remove this software immediately."

For normal span entries:

0x4005 -> 0x4005 & 0x3FFF -> 5

For multiple spans:

0x4004 | 0x0001

Span 1 - Rule Count: 4
Span 2 - Rule Count: 1

Special infrastructure-style entries ending in 0xFF are currently preserved as raw values instead of being converted to rule counts.

SIGNATURE_TYPE_THREAT_END parses the corresponding ThreatID and the parser checks for ThreatID mismatches between THREAT_BEGIN and THREAT_END.

DBVAR

SIGNATURE_TYPE_DBVAR is parsed as:

struct DBVAR {
    BYTE varLength;
    BYTE varName[varLength];
    BYTE unknown[];
    // followed by nested signature records
};

The parser searches for the earliest offset after varName from which the remaining data can be parsed as valid signature records.

Nested rules are parsed recursively as normal signatures.

SQLite stores nested DBVAR rules in the same signatures table using:

parent_signature_id
depth

to preserve the parent/child relationship.

KCRCE

SIGNATURE_TYPE_KCRCE currently uses the following reversed base structure:

typedef union KCRCEParam {
    uint32_t raw;

    struct {
        uint32_t crc2_length  : 16;
        uint32_t crc2_offset  : 12;
        uint32_t unknown28    : 1;
        uint32_t unknown29    : 1;
        uint32_t require_fastcrc : 1;
        uint32_t strict_crc2     : 1;
    };
} KCRCEParam;

typedef struct KCRCE {
    uint32_t fast_crc;
    uint32_t crc1;
    uint32_t crc2;
    KCRCEParam param;
} KCRCE;

A 16-byte KCRCE rule contains only the base structure.

If additional data follows, it is currently parsed as:

BYTE metadataLength;
BYTE metadataName[metadataLength];

The metadata name uses the same packed/prefixed threat-name parser as THREAT_BEGIN.

LUASTANDALONE

SIGNATURE_TYPE_LUASTANDALONE currently uses:

struct LUASTANDALONE {
    BYTE  nameLength;
    BYTE  Category;
    WORD  sizeofMetaData;
    DWORD sizeofMPLua;
    BYTE  name[nameLength];
    BYTE  MetaData[sizeofMetaData];
    BYTE  MPLUA[sizeofMPLua];
};

The embedded MpLua blob is processed as:

MPLUA
  -> Microsoft Defender MpLua normalization
  -> standard Lua 5.1 .luac
  -> cLuaDecompiler
  -> source stored in SQLite

Only the final .luac file is retained in lua_drop/; the temporary .mplua file is removed after processing.

A persistent SQLite cache uses the Lua rule counter and MPLUA SHA-256 to avoid running the decompiler again when the corresponding .luac and cached source already exist.

STATIC

SIGNATURE_TYPE_STATIC is treated as an exact raw byte pattern and is currently rendered as hex.

Example:

Hex: DE AD BE EF 01 02 03 04

It is not treated as a hash list.

Heuristic parsers

The following parsers currently retain dump-driven/heuristic layouts ported from andreacristaldi/DefenderRuleParser and will be refined as their real semantics are reversed:

SIGNATURE_TYPE_KCRCEX

SIGNATURE_TYPE_SIGTREE

SIGNATURE_TYPE_SIGTREE_EXT

SIGNATURE_TYPE_SIGTREE_BM

SIGNATURE_TYPE_PESTATIC

SIGNATURE_TYPE_PESTATICEX

SIGNATURE_TYPE_KVIR32

SIGNATURE_TYPE_POLYVIR32

SIGNATURE_TYPE_LOCALHASH

SIGNATURE_TYPE_NDAT

SIGNATURE_TYPE_FOPEX

SIGNATURE_TYPE_PEBMPAT

SIGNATURE_TYPE_AAGGREGATOR

SIGNATURE_TYPE_KPAT

SIGNATURE_TYPE_KPATEX

Supported HSTR_EXT wildcards:

90 00 -> 90 05 are already mentioned here: https://retooling.io/blog/an-unexpected-journey-into-microsoft-defenders-signature-world

90 07 XX YY: uint16 little-endian version of 90 01

90 08 XX YY: uint16 little-endian version of 90 02

90 09 XX YY: Match exact YYXX bytes, forward following backward

90 0A XX YY: Match up to YYXX bytes, forward following backward

90 0B XX YY: Match exact YYXX CRLF bytes

90 0C XX YY: Match up to YYXX CRLF bytes

90 0D: Match exact WhiteSpace

90 0E: Match up to WhiteSpace

90 0F: Match exact Numeric

90 10: Match up to Numeric

90 11: Match exact Alphabetic

90 12: Match up to Alphabetic

90 13: Mandatory JMP/JCC/JCXZ ADDR

90 14: Relative int8 displacement read from input

90 15: Relative int16 displacement read from input

90 16: Relative int32 displacement read from input

90 17 NN ...: OR/choice wildcard with NN alternatives and an embedded length table

90 18: Optional JMP/JCC/JCXZ ADDR

90 19 XX YY <set>: Match exactly XX bytes not belonging to the supplied completed set

90 1B XX: Cloning/backreference wildcard

90 1C: Match exact Alphanumeric

90 1D: Match up to Alphanumeric

90 1E: Match exact HexSet

90 1F: Match up to HexSet

90 20 -> 90 2E: Currently treated as unknown two-byte wildcard opcodes and rendered as [90 XX]; following bytes are not consumed as operands

90 90: Represents the literal byte 0x90

Additional HSTR_EXT behavior:

Nested 90 03 and 90 17 payloads are parsed recursively.

90 19 is an exclude/not-in set, not an include set.

90 09 and 90 0A are rendered using logical matched-input byte counts rather than encoded wildcard byte lengths.

UTF-16 strings are only decoded when the byte pattern clearly represents printable ASCII widened by alternating NUL bytes, reducing false positives.

To do:

Reverse the real semantics of heuristic signature parsers currently ported from DefenderRuleParser.

Reverse 90 20 -> 90 2E wildcard semantics and replace the current unknown-opcode rendering.

Continue identifying undocumented fields and flags in THREAT_BEGIN, DBVAR, KCRCEX, SIGTREE-family, PESTATIC-family, and other signature types.

Add dedicated parsers for signature types that still use generic binary/text fallback handling.
