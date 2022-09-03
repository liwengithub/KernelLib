#include "KernelLibStr.h"
#include <Ntstrsafe.h>

BOOLEAN StrIsAnsiStrVaild(PANSI_STRING pAnsiStr)
{
	if (ARGUMENT_PRESENT(pAnsiStr) && ARGUMENT_PRESENT(pAnsiStr->Buffer) &&
		pAnsiStr->MaximumLength >= pAnsiStr->Length)
	{
		return TRUE;
	}
	return FALSE;
}

BOOLEAN StrIsUnicodeVaild(PUNICODE_STRING pUnicodeStr)
{
	if (ARGUMENT_PRESENT(pUnicodeStr) && ARGUMENT_PRESENT(pUnicodeStr->Buffer) &&
		pUnicodeStr->MaximumLength >= pUnicodeStr->Length)
	{
		return TRUE;
	}
	return FALSE;
}

BOOLEAN StrWCharToChar(IN PWCHAR WStr, OUT PCHAR Str, IN ULONG CchStr)
{
	UNICODE_STRING UnicodeString = { 0 };
	ANSI_STRING AnsiString = { 0 };
	NTSTATUS Status = 0;
	if (!WStr || !Str || CchStr == 0){
		return FALSE;
	}
	RtlInitUnicodeString(&UnicodeString, WStr);
	RtlUnicodeStringToAnsiString(&AnsiString, &UnicodeString, TRUE);//PAGE_POOL
	Status = RtlStringCchCopyNA(Str, CchStr, AnsiString.Buffer, AnsiString.Length / sizeof(CHAR));
	RtlFreeAnsiString(&AnsiString);
	return NT_SUCCESS(Status) ? TRUE : FALSE;
}

BOOLEAN StrCharToWChar(IN PCHAR Str, OUT PWCHAR WStr, IN ULONG CchWStr)
{
	UNICODE_STRING UnicodeString = { 0 };
	ANSI_STRING AnsiString = { 0 };
	NTSTATUS Status = 0;
	if (!Str || !WStr || CchWStr == 0){
		return FALSE;
	}
	RtlInitAnsiString(&AnsiString, Str);
	RtlAnsiStringToUnicodeString(&UnicodeString, &AnsiString, TRUE);
	Status = RtlStringCchCopyNW(WStr, CchWStr, UnicodeString.Buffer, UnicodeString.Length / sizeof(WCHAR));
	RtlFreeUnicodeString(&UnicodeString);
	return NT_SUCCESS(Status) ? TRUE : FALSE;
}

BOOLEAN StrAnsiToChar(IN PANSI_STRING pAnsistr, OUT PCHAR Str, IN ULONG CchStr)
{
	NTSTATUS Status = RtlStringCchCopyNA(Str, CchStr, pAnsistr->Buffer, pAnsistr->Length / sizeof(CHAR));
	return NT_SUCCESS(Status) ? TRUE : FALSE;
}

BOOLEAN StrUnicodeToWChar(IN PUNICODE_STRING pUnicodeStr, OUT PWCHAR WStr, IN ULONG CchWStr)
{
	NTSTATUS Status = RtlStringCchCopyNW(WStr, CchWStr, pUnicodeStr->Buffer, pUnicodeStr->Length / sizeof(WCHAR));
	return NT_SUCCESS(Status) ? TRUE : FALSE;
}

BOOLEAN StrUnicodeToChar(IN PUNICODE_STRING pUnicodeStr, OUT PSTR Str, IN ULONG CchStr)
{
	ANSI_STRING AnsiStr = { 0 };
	NTSTATUS Status = 0;
	if (!pUnicodeStr || !Str || CchStr == 0){
		return FALSE;
	}
	RtlUnicodeStringToAnsiString(&AnsiStr, pUnicodeStr, TRUE);
	Status = RtlStringCchCopyNA(Str, CchStr, AnsiStr.Buffer, AnsiStr.Length / sizeof(CHAR));
	RtlFreeAnsiString(&AnsiStr);
	return NT_SUCCESS(Status) ? TRUE : FALSE;
}

BOOLEAN StrPathToName(WCHAR* Path, UINT32 Len)
{
	UINT i = 0;
	if (Len == 0) {
		return FALSE;
	}

	for (i = Len - 1; i > 0; i--)
	{
		if ((Path[i] == L'\\' || Path[i] == L'/'))
		{
			if (i + 1 < Len)
			{
				RtlMoveMemory(Path, &Path[i + 1], (Len - i) * sizeof(WCHAR));
				Path[Len - i] = L'\0';
				return TRUE;
			}
			break;
		}
	}
	return FALSE;
}

ULONG StrUnicodeToInteger(PUNICODE_STRING pUnicodeStr)
{
	ULONG Number = 0;
	NTSTATUS Status = RtlUnicodeStringToInteger(pUnicodeStr, 10, &Number);
	return NT_SUCCESS(Status) ? Number : 0;
}

BOOLEAN StrIntegerToUnicode(ULONG Value, PUNICODE_STRING pUnicodeStr)
{	
	NTSTATUS Status = RtlIntegerToUnicodeString(Value, 10, pUnicodeStr);
	return NT_SUCCESS(Status) ? TRUE : FALSE;
}

PCHAR StrSearchI(const char* Str1, const char* Str2)
{
	char *cp = (char *)Str1;
	char *s1, *s2;
	if (!*Str2) return((char *)Str1);
	while (*cp)
	{
		s1 = cp;
		s2 = (char *)Str2;
		while (*s1 && *s2 && !(tolower(*s1) - tolower(*s2))) s1++, s2++;
		if (!*s2) return(cp);
		cp++;
	}
	return(NULL);
}

PCHAR StrSearchI2(const PCHAR Str1, const PCHAR Str2, int pos)
{
	char *cp = (char *)Str1;
	char *s1, *s2;
	if (!*Str2) return((char *)Str1);
	if (pos > strlen(Str1))return NULL;
	while (pos--)
	{
		cp++;
	}
	while (*cp)
	{
		s1 = cp;
		s2 = (char *)Str2;
		while (*s1 && *s2 && !(tolower(*s1) - tolower(*s2))) s1++, s2++;
		if (!*s2) return(cp);
		cp++;
	}
	return(NULL);
}

PWCHAR StrWSearchI(const PWCHAR WStr1, const PWCHAR WStr2)
{
	wchar_t *cp = (wchar_t *)WStr1;
	wchar_t *s1, *s2;
	if (!*WStr2) return((wchar_t *)WStr1);
	while (*cp)
	{
		s1 = cp;
		s2 = (wchar_t *)WStr2;
		while (*s1 && *s2 && !(tolower(*s1) - tolower(*s2))) s1++, s2++;
		if (!*s2) return(cp);
		cp++;
	}
	return(NULL);
}

BOOLEAN StrReplaceI(char *SrcStr, char *Pattern, char *Replaced, char *DestStr)
{
	char *ch;
	char *cp = SrcStr;

	if (!SrcStr || !Pattern || !Replaced || !DestStr
		|| !(ch = StrSearchI(cp, Pattern))
		)
	{
		return FALSE;
	}

	while (ch != NULL)
	{
		strncat(DestStr, cp, ch - cp);
		strcat(DestStr, Replaced);

		cp = ch + strlen(Pattern);
		ch = StrSearchI(cp, Pattern);
	}

	if (cp != NULL){
		strcat(DestStr, cp);
	}
	return TRUE;
}

BOOLEAN StrFormatVaListA(const char* Formats, CHAR* Buf, ULONG BufSize, va_list lst)
{
	if (Buf == NULL || BufSize == 0) {
		return FALSE;
	}
	RtlZeroMemory(Buf, BufSize);
	NTSTATUS Status = RtlStringCbVPrintfA(Buf, BufSize, Formats, lst);
	return NT_SUCCESS(Status) ? TRUE : FALSE;
}

BOOLEAN StrFormatA(const CHAR* Formats, CHAR* Buf, ULONG BufSize, ...)
{
	if (Buf == NULL || BufSize == 0) {
		return FALSE;
	}
	va_list lst;
	va_start(lst, BufSize);
	BOOLEAN Result = StrFormatVaListA(Formats, Buf, BufSize, lst);
	va_end(lst);
	return Result;
}

BOOLEAN StrFormatVaListW(const WCHAR* Formats, WCHAR* Buf, ULONG BufSize, va_list lst)
{
	if (Buf == NULL || BufSize == 0) {
		return FALSE;
	}
	RtlZeroMemory(Buf, BufSize);
	NTSTATUS Status = RtlStringCbVPrintfW(Buf, BufSize, Formats, lst);
	return NT_SUCCESS(Status) ? TRUE : FALSE;
}

BOOLEAN StrFormatW(const WCHAR* Formats, WCHAR* Buf, ULONG BufSize, ...)
{
	if (Buf == NULL || BufSize == 0) {
		return FALSE;
	}
	va_list lst;
	va_start(lst, BufSize);
	BOOLEAN Result = StrFormatVaListW(Formats, Buf, BufSize, lst);
	va_end(lst);
	return Result;
}

BOOLEAN StrReplaceW(const wchar_t *SrcStr, const wchar_t *Pattern, const wchar_t *Replaced, wchar_t *DestStr)
{
	const wchar_t *ch;
	const wchar_t *cp = SrcStr;

	if (!SrcStr || !Pattern || !Replaced || !DestStr
		|| !(ch = wcsstr(cp, Pattern))
		)
	{
		return FALSE;
	}

	while (ch != NULL)
	{
		wcsncat(DestStr, cp, ch - cp);
		wcscat(DestStr, Replaced);

		cp = ch + wcslen(Pattern);
		ch = wcsstr(cp, Pattern);
	}

	if (cp != NULL) {
		wcscat(DestStr, cp);
	}
	return TRUE;
}

BOOLEAN StrSubstrW(const WCHAR* Str, WCHAR* SubStr, int SubStrLen, int Start, int Count)
{
	if (!Str || !SubStr || !Count || !SubStrLen || SubStrLen < Count) {
		return FALSE;
	}

	int i = Start;
	int j = 0;
	for (; i < Start + Count; i++, j++)
	{
		SubStr[j] = Str[i];
	}
	SubStr[Count] = L'\0';
	return TRUE;
}

BOOLEAN StrParseCmdlineW(const WCHAR* Cmdline, int CmdlineLen, STR_PARSE_COMMIND_LINE* pCmds, int* pCount)
{
	typedef enum
	{
		STATE_INIT,
		STATE_QUOTE_ING,
		STATE_QUOTE_FORMAT,
		STATE_PARAM_ING
	} ParseDfaState;

	if (!pCount) {
		return FALSE;
	}

	int Count = 0;
	int Index = 0;
	int StartPos = -1;
	ParseDfaState DfaState = STATE_INIT;

	while (Index < CmdlineLen)
	{
		switch (DfaState)
		{
		case STATE_INIT:
		{
			if (Cmdline[Index] == L' ')
			{
				// do nothing
			}
			else if (Cmdline[Index] == L'"')
			{
				DfaState = STATE_QUOTE_ING;
				StartPos = Index + 1;
			}
			else
			{
				DfaState = STATE_PARAM_ING;
				StartPos = Index;
			}
		}
		break;
		case STATE_QUOTE_ING:
		{
			if (Cmdline[Index] == L'\\')
			{
				DfaState = STATE_QUOTE_FORMAT;
			}
			else if (Cmdline[Index] == L'"')
			{
				DfaState = STATE_INIT;
				if (pCmds && Count < *pCount)
				{
					if (!StrSubstrW(Cmdline, pCmds[Count].Cmd, MAX_PATH, StartPos, Index - StartPos)) {
						return FALSE;
					}
				}
				Count++;

				StartPos = -1;
			}
			else
			{
				// do nothing
			}
		}
		break;
		case STATE_QUOTE_FORMAT:
		{
			DfaState = STATE_QUOTE_ING;
		}
		break;
		case STATE_PARAM_ING:
		{
			if (Cmdline[Index] == L' ')
			{
				DfaState = STATE_INIT;
				if (pCmds && Count < *pCount)
				{
					if (!StrSubstrW(Cmdline, pCmds[Count].Cmd, MAX_PATH, StartPos, Index - StartPos)) {
						return FALSE;
					}
				}
				Count++;
				StartPos = -1;
			}
			else
			{
				// do nothing
			}
		}
		break;
		}

		Index++;
	}
	if (StartPos != -1)
	{
		if (pCmds && Count < *pCount)
		{
			if (!StrSubstrW(Cmdline, pCmds[Count].Cmd, MAX_PATH, StartPos, CmdlineLen - StartPos)) {
				return FALSE;
			}
		}
		Count++;
	}
	*pCount = Count;
	return TRUE;
}