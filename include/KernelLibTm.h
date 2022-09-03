#pragma once
#include <ntifs.h>
#include <WinDef.h>

#define DELAY_ONE_MICROSECOND   ( -10 )
#define DELAY_ONE_MILLISECOND  ( DELAY_ONE_MICROSECOND * 1000 )

VOID TmSleep1(IN LONG ms);
VOID TmSleep2(IN LONG ms);
VOID TmGetTickCount(IN PULONG ms);
ULONG TmGenterateRandom();
VOID TmGetCurrentTime(PTIME_FIELDS pNowFields);