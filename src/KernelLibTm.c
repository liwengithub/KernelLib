#include "KernelLibTm.h"

VOID TmSleep1(IN LONG ms)
{
	LARGE_INTEGER interval;
	interval.QuadPart = DELAY_ONE_MILLISECOND;
	interval.QuadPart *= ms;
	KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

VOID TmSleep2(IN LONG ms)
{
	KEVENT			kEnentTemp;
	LARGE_INTEGER	waitTime;

	KeInitializeEvent(&kEnentTemp, SynchronizationEvent, FALSE);
	waitTime = RtlConvertLongToLargeInteger(-10 * ms * 1000);
	KeWaitForSingleObject(&kEnentTemp, Executive, KernelMode, FALSE, &waitTime);
}

VOID TmGetTickCount(IN PULONG ms)
{
	LARGE_INTEGER tick_count;
	ULONG inc = KeQueryTimeIncrement();
	KeQueryTickCount(&tick_count);
	tick_count.QuadPart *= inc;
	tick_count.QuadPart /= 10000;
	*ms = tick_count.LowPart;
}

ULONG TmGenterateRandom()
{
	static LARGE_INTEGER   FistTick = { 0 };
	if (FistTick.LowPart == 0){
		KeQueryTickCount(&FistTick);
	}
	return RtlRandomEx(&FistTick.LowPart);
}

VOID TmGetCurrentTime(PTIME_FIELDS pNowFields)
{
	LARGE_INTEGER SystemNow, Now;
	KeQuerySystemTime(&SystemNow);
	ExSystemTimeToLocalTime(&SystemNow, &Now);
	RtlTimeToTimeFields(&Now, pNowFields);
}

