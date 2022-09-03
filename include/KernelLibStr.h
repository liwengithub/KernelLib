#pragma once

#include <ntdef.h>
#include <ntifs.h>
#include <WinDef.h>

typedef struct _STR_PARSE_COMMIND_LINE
{
	WCHAR Cmd[MAX_PATH + 1];
}STR_PARSE_COMMIND_LINE;

//Str
BOOLEAN		StrIsAnsiStrVaild(PANSI_STRING pAnsiStr);
BOOLEAN		StrIsUnicodeVaild(PUNICODE_STRING pUnicodeStr);
BOOLEAN		StrWCharToChar(IN PWCHAR WStr, OUT PCHAR Str, IN ULONG CchStr);
BOOLEAN		StrCharToWChar(IN PCHAR Str, OUT PWCHAR WStr, IN ULONG CchWStr);
BOOLEAN		StrAnsiToChar(IN PANSI_STRING pAnsistr, OUT PCHAR Str, IN ULONG CchStr);
BOOLEAN		StrUnicodeToWChar(IN PUNICODE_STRING pUnicodeStr, OUT PWCHAR WStr, IN ULONG CchWStr);
BOOLEAN		StrUnicodeToChar(IN PUNICODE_STRING pUnicodeStr, OUT PSTR Str, IN ULONG CchStr);
BOOLEAN		StrPathToName(WCHAR* Path, UINT32 Len);
ULONG		StrUnicodeToInteger(PUNICODE_STRING pUnicodeStr);
BOOLEAN		StrIntegerToUnicode(ULONG Value, PUNICODE_STRING pUnicodeStr);
PCHAR		StrSearchI(const char* Str1, const char* Str2);
PCHAR		StrSearchI2(const PCHAR Str1, const PCHAR Str2, int pos);
PWCHAR		StrWSearchI(const PWCHAR WStr1, const PWCHAR WStr2);
BOOLEAN		StrReplaceI(char *SrcStr, char *Pattern, char *Replaced, char *DestStr);
BOOLEAN		StrFormatVaListA(const char* Formats, CHAR* Buf, ULONG BufSize, va_list lst);
BOOLEAN		StrFormatA(const CHAR* Formats, CHAR* Buf, ULONG BufSize, ...);
BOOLEAN		StrFormatVaListW(const WCHAR* Formats, WCHAR* Buf, ULONG BufSize, va_list lst);
BOOLEAN		StrFormatW(const WCHAR* Formats, WCHAR* Buf, ULONG BufSize, ...);
BOOLEAN		StrReplaceW(const wchar_t *SrcStr, const wchar_t *Pattern, const wchar_t *Replaced, wchar_t *DestStr);
BOOLEAN		StrSubstrW(const WCHAR* Str, WCHAR* SubStr, int SubStrLen, int Start, int Count);
BOOLEAN		StrParseCmdlineW(const WCHAR* Cmdline, int CmdlineLen, STR_PARSE_COMMIND_LINE* pCmds, int* pCount);