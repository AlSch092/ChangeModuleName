// ChangeModuleName.cpp - Manipulate module names at runtime in running process for defense evasion and persistence
// By AlSch092 , for MITRE ATT&CK
// Researched in Spring 2023, submitted Sept. 2023

#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <Windows.h>
#include <Winternl.h>
#include <string>
#include <intrin.h>

typedef struct _MYPEB {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR Spare;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PEB_LDR_DATA* Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID FastPebLockRoutine;
	PVOID FastPebUnlockRoutine;
	ULONG EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID EventLogSection;
	PVOID EventLog;
	PVOID FreeList;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[0x2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	UCHAR Spare2[0x4];
	ULARGE_INTEGER CriticalSectionTimeout;
	ULONG HeapSegmentReserve;
	ULONG HeapSegmentCommit;
	ULONG HeapDeCommitTotalFreeThreshold;
	ULONG HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper; //PPS_POST_PREOCESS_INIT_ROUTINE?
	PVOID GdiDCAttributeList;
	PVOID LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	ULONG OSBuildNumber;
	ULONG OSPlatformId;
	ULONG ImageSubSystem;
	ULONG ImageSubSystemMajorVersion;
	ULONG ImageSubSystemMinorVersion;
	ULONG GdiHandleBuffer[0x22];
	PVOID ProcessWindowStation;
} MYPEB, *PMYPEB;

void ChangeModuleName(wchar_t* szModule, wchar_t* newName)
{
	PPEB PEB = (PPEB)__readgsqword(0x60);  //we are compiling as x64!
	_LIST_ENTRY* f = PEB->Ldr->InMemoryOrderModuleList.Flink;
	bool Found = FALSE;

	while (!Found)
	{
		PLDR_DATA_TABLE_ENTRY dataEntry = CONTAINING_RECORD(f, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		if (wcsstr(dataEntry->FullDllName.Buffer, szModule) != NULL)
		{
			wcscpy(dataEntry->FullDllName.Buffer, newName);
			Found = TRUE;
			return;
		}

		f = dataEntry->InMemoryOrderLinks.Flink;
	}
}

int main(int argc, char** argv)
{
	ChangeModuleName((wchar_t*)L"KERNEL32.DLL", (wchar_t*)L"Renamed.DLL"); //change K32 to something else
	ChangeModuleName((wchar_t*)L"USER32.DLL", (wchar_t*)L"Renamed.DLL"); //example of duplicate module names
	ChangeModuleName((wchar_t*)L"changeModuleName.exe", (wchar_t*)L""); //example of technique working on host EXE, and with a NULL string.
	system("pause");
	return 0;
}
