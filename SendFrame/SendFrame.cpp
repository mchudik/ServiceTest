// SendFrame.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <tchar.h>

#define WIDTH 1920
#define HEIGHT 1080
#define BUF_SIZE WIDTH * HEIGHT * 2
#define FPS 1000/33
TCHAR szName[] = TEXT("Global\\MyFileMappingObject");


BOOL SetPrivilege(
	HANDLE hToken,               // access token handle
	LPCTSTR lpszPrivilege,    // name of privilege to enable/disable
	BOOL bEnablePrivilege    // to enable (or disable privilege)
)
{
	// Token privilege structure
	TOKEN_PRIVILEGES tp;
	// Used by local system to identify the privilege
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,                // lookup privilege on local system
		lpszPrivilege,    // privilege to lookup
		&luid))               // receives LUID of privilege
	{
		printf("LookupPrivilegeValue() error: %u\n", GetLastError());
		return FALSE;
	} else
		printf("LookupPrivilegeValue() is OK\n");

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;

	// Don't forget to disable the privileges after you enabled them,
	// or have already completed your task. Don't mess up your system :o)
	if (bEnablePrivilege)
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		printf("tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED\n");
	} else
	{
		tp.Privileges[0].Attributes = 0;
		printf("tp.Privileges[0].Attributes = 0\n");
	}

	// Enable the privilege (or disable all privileges).
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE, // If TRUE, function disables all privileges, if FALSE the function modifies privilege based on the tp
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges() error: %u\n", GetLastError());
		return FALSE;
	} else
	{
		printf("AdjustTokenPrivileges() is OK, last error if any: %u\n", GetLastError());
		printf("Should be 0, means the operation completed successfully = ERROR_SUCCESS\n");
	}
	return TRUE;
}

BOOL CreateAndMapSharedMemory(HANDLE *hMapFile, LPCTSTR *pBuf)
{
	*hMapFile = CreateFileMapping(
		INVALID_HANDLE_VALUE,    // use paging file
		NULL,                    // default security
		PAGE_READWRITE,          // read/write access
		0,                       // maximum object size (high-order DWORD)
		BUF_SIZE,                // maximum object size (low-order DWORD)
		szName);                 // name of mapping object

	if (*hMapFile == NULL)
	{
		_tprintf(TEXT("Could not create file mapping object (%d).\n"),
			GetLastError());
		return FALSE;
	}
	*pBuf = (LPTSTR)MapViewOfFile(*hMapFile,   // handle to map object
		FILE_MAP_ALL_ACCESS, // read/write permission
		0,
		0,
		BUF_SIZE);

	if (*pBuf == NULL)
	{
		_tprintf(TEXT("Could not map view of file (%d).\n"),
			GetLastError());

		CloseHandle(*hMapFile);

		return FALSE;
	}
	return TRUE;
}
	
VOID UnMapSharedMemory(HANDLE hMapFile, LPCTSTR pBuf)
{

	UnmapViewOfFile(pBuf);
	CloseHandle(&hMapFile);
}

int _tmain()
{
	LPCTSTR lpszPrivilege = TEXT("SeCreateGlobalPrivilege");

	// Change this BOOL value to set/unset the SE_PRIVILEGE_ENABLED attribute
	BOOL bEnablePrivilege = TRUE;
	HANDLE hToken;

	// Open a handle to the access token for the calling process. That is this running program
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		printf("OpenProcessToken() error %u\n", GetLastError());
		return FALSE;
	} else
		printf("OpenProcessToken() is OK\n");

	// Call the user defined SetPrivilege() function to enable and set the needed privilege
	BOOL test = SetPrivilege(hToken, lpszPrivilege, bEnablePrivilege);
	printf("The SetPrivilege() return value: %d\n\n", test);

	//************************************************
	// TODO: Complete your task here
	//***********************************************

	HANDLE hMapFile;
	LPCTSTR pBuf;

	if (CreateAndMapSharedMemory(&hMapFile, &pBuf)) {

		BYTE pixel = 0;
		while (true) {
			memset((PVOID)pBuf, pixel, BUF_SIZE);
			_tprintf(TEXT("Frame [%dx%d] Sent with pixels set to [%d] at [%d] fps\n"), WIDTH, HEIGHT, pixel, FPS);
			pixel++;
			if (pixel == 256) pixel = 0;
			Sleep(FPS);
		}

		// Free the memory mapping
		UnMapSharedMemory(hMapFile, pBuf);
	}

	// After we have completed our task, don't forget to disable the privilege
	bEnablePrivilege = FALSE;
	BOOL test1 = SetPrivilege(hToken, lpszPrivilege, bEnablePrivilege);
	printf("The SetPrivilage() return value: %d\n", test1);

	return 0;
}
