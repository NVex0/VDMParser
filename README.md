## Windows Defender's Rules Database Parser

Currently supports these signatures:
+ SIGNATURE_TYPE_THREAT_BEGIN
+ SIGNATURE_TYPE_THREAT_END
+ SIGNATURE_TYPE_FOLDERNAME
+ SIGNATURE_TYPE_FILEPATH
+ SIGNATURE_TYPE_ASEP_FILEPATH
+ SIGNATURE_TYPE_REGKEY
+ SIGNATURE_TYPE_PEHSTR
+ SIGNATURE_TYPE_FRIENDLYFILE_SHA512
+ SIGNATURE_TYPE_FRIENDLYFILE_SHA256
+ SIGNATURE_TYPE_VDLL_X86
+ SIGNATURE_TYPE_LUASTANDALONE
+ Supports every HSTR/HSTR_EXT variant.

Supported HSTR_EXT wildcards:
+ 90 00 -> 90 05 are already mentioned here: https://retooling.io/blog/an-unexpected-journey-into-microsoft-defenders-signature-world
+ 90 07: uint16 version of 90 01
+ 90 08: uint16 version of 90 02
+ 90 09 XX YY: Match exact YYXX bytes, forward following backward
+ 90 0A XX YY: Match up to YYXX bytes, forward following backward
+ 90 0B XX YY: Match exact YYXX CRLF bytes
+ 90 0C XX YY: Match up to YYXX CRLF bytes
+ 90 0D XX YY: Match exact YYXX WhiteSpace bytes
+ 90 0E XX YY: Match up to YYXX WhiteSpace bytes
+ 90 0F XX YY: Match exact YYXX Numeric bytes
+ 90 10 XX YY: Match up to YYXX Numeric bytes
+ 90 11 XX YY: Match exact YYXX Alphabetic bytes
+ 90 12 XX YY: Match up to YYXX Alphabetic bytes
+ 90 13: Mandatory JMP ADDR
+ 90 14: Relative jmp by UINT8 input
+ 90 15: Relative jmp by UINT16 input
+ 90 16: Relative jmp by UINT32 input
+ 90 18: Optional JMP ADDR
+ 90 19 XX YY: Match exact XX bytes, except the completed regex length YY
+ 90 1C XX YY: Match exact YYXX Alphanumeric bytes
+ 90 1D XX YY: Match up to YYXX Alphanumeric bytes
+ 90 1E XX YY: Match exact YYXX HexSet bytes
+ 90 1F XX YY: Match up to YYXX HexSet bytes
+ 90 90: Represents the literal byte 0x90.

To do:
+ Observing extracted VDM reveals there are more wildcards than just those up to 0x20. A future update will parse wildcards starting from 90 20.
+ Add more parsing modules for different signatures.
+ Fix the `!InfrastructureShared` and `!Infrastructure` formats.

