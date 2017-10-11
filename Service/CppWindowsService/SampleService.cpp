/****************************** Module Header ******************************\
* Module Name:  SampleService.cpp
* Project:      CppWindowsService
* Copyright (c) Microsoft Corporation.
* 
* Provides a sample service class that derives from the service base class - 
* CServiceBase. The sample service logs the service start and stop 
* information to the Application event log, and shows how to run the main 
* function of the service in a thread pool worker thread.
* 
* This source is subject to the Microsoft Public License.
* See http://www.microsoft.com/en-us/openness/resources/licenses.aspx#MPL.
* All other rights reserved.
* 
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, 
* EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED 
* WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
\***************************************************************************/

#pragma region Includes
#include "SampleService.h"
#include "ThreadPool.h"
#pragma endregion

#include <stdio.h>
#include <conio.h>
#include <tchar.h>

#define WIDTH 1920
#define HEIGHT 1080
#define BUF_SIZE WIDTH * HEIGHT * 2
#define FPS 1000/33

LPCTSTR lpszPrivilege = TEXT("SeCreateGlobalPrivilege");
TCHAR szName[] = TEXT("Global\\MyFileMappingObject");
HANDLE hMapFile = nullptr;
HANDLE hToken = nullptr;
LPCTSTR pBuf = nullptr;
BYTE pixel = 0;

BOOL SetPrivilege(
	HANDLE hToken,           // access token handle
	LPCTSTR lpszPrivilege,   // name of privilege to enable/disable
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


CSampleService::CSampleService(PWSTR pszServiceName, 
							   BOOL fCanStop, 
							   BOOL fCanShutdown, 
							   BOOL fCanPauseContinue)
: CServiceBase(pszServiceName, fCanStop, fCanShutdown, fCanPauseContinue)
{
	m_fStopping = FALSE;

	// Create a manual-reset event that is not signaled at first to indicate 
	// the stopped signal of the service.
	m_hStoppedEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (m_hStoppedEvent == NULL)
	{
		throw GetLastError();
	}
}


CSampleService::~CSampleService(void)
{
	if (m_hStoppedEvent)
	{
		CloseHandle(m_hStoppedEvent);
		m_hStoppedEvent = NULL;
	}
}


//
//   FUNCTION: CSampleService::OnStart(DWORD, LPWSTR *)
//
//   PURPOSE: The function is executed when a Start command is sent to the 
//   service by the SCM or when the operating system starts (for a service 
//   that starts automatically). It specifies actions to take when the 
//   service starts. In this code sample, OnStart logs a service-start 
//   message to the Application log, and queues the main service function for 
//   execution in a thread pool worker thread.
//
//   PARAMETERS:
//   * dwArgc   - number of command line arguments
//   * lpszArgv - array of command line arguments
//
//   NOTE: A service application is designed to be long running. Therefore, 
//   it usually polls or monitors something in the system. The monitoring is 
//   set up in the OnStart method. However, OnStart does not actually do the 
//   monitoring. The OnStart method must return to the operating system after 
//   the service's operation has begun. It must not loop forever or block. To 
//   set up a simple monitoring mechanism, one general solution is to create 
//   a timer in OnStart. The timer would then raise events in your code 
//   periodically, at which time your service could do its monitoring. The 
//   other solution is to spawn a new thread to perform the main service 
//   functions, which is demonstrated in this code sample.
//
void CSampleService::OnStart(DWORD dwArgc, LPWSTR *lpszArgv)
{
	// Log a service start message to the Application log.
	WriteEventLogEntry(L"CppWindowsService in OnStart", 
		EVENTLOG_INFORMATION_TYPE);

	// Open a handle to the access token for the calling process. That is this running program
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		WriteEventLogEntry(L"CppWindowsService Error in OpenProcessToken()!",
			EVENTLOG_ERROR_TYPE);
	} else {
		WriteEventLogEntry(L"CppWindowsService OpenProcessToken() succeeded!",
			EVENTLOG_INFORMATION_TYPE);
	}

	// Call the user defined SetPrivilege() function to enable and set the needed privilege
	if (SetPrivilege(hToken, lpszPrivilege, TRUE)) {
		WriteEventLogEntry(L"CppWindowsService SetPrivilege() succeeded!",
			EVENTLOG_INFORMATION_TYPE);
	} else {
		WriteEventLogEntry(L"CppWindowsService Error in SetPrivilege()!",
			EVENTLOG_ERROR_TYPE);
	}

	// Create and map shared memory
	if (CreateAndMapSharedMemory(&hMapFile, &pBuf)) {
		WriteEventLogEntry(L"CppWindowsService Mapped Memory OK!",
			EVENTLOG_INFORMATION_TYPE);
	} else {
		WriteEventLogEntry(L"CppWindowsService Could not Map Memory!",
			EVENTLOG_ERROR_TYPE);
	}

	// Queue the main service function for execution in a worker thread.
	CThreadPool::QueueUserWorkItem(&CSampleService::ServiceWorkerThread, this);
}


//
//   FUNCTION: CSampleService::ServiceWorkerThread(void)
//
//   PURPOSE: The method performs the main function of the service. It runs 
//   on a thread pool worker thread.
//
void CSampleService::ServiceWorkerThread(void)
{
	// Starting sending the frames
	if (hMapFile != nullptr && pBuf != nullptr) {
		WriteEventLogEntry(L"CppWindowsService Starting writing to shared memory",
			EVENTLOG_INFORMATION_TYPE);
	}

	// Periodically check if the service is stopping.
	while (!m_fStopping)
	{
		// Perform main service function here...

		// Send a frame at a time at FPS framerate
		if (hMapFile != nullptr && pBuf != nullptr) {
			memset((PVOID)pBuf, pixel, BUF_SIZE);
			pixel++;
			if (pixel == 256) pixel = 0;
			Sleep(FPS);
		}
	}

	// Ending sending the frames
	if (hMapFile != nullptr && pBuf != nullptr) {
		WriteEventLogEntry(L"CppWindowsService Ending writing to shared memory",
			EVENTLOG_INFORMATION_TYPE);
	}

	// Signal the stopped event.
	SetEvent(m_hStoppedEvent);
}


//
//   FUNCTION: CSampleService::OnStop(void)
//
//   PURPOSE: The function is executed when a Stop command is sent to the 
//   service by SCM. It specifies actions to take when a service stops 
//   running. In this code sample, OnStop logs a service-stop message to the 
//   Application log, and waits for the finish of the main service function.
//
//   COMMENTS:
//   Be sure to periodically call ReportServiceStatus() with 
//   SERVICE_STOP_PENDING if the procedure is going to take long time. 
//
void CSampleService::OnStop()
{
	// Log a service stop message to the Application log.
	WriteEventLogEntry(L"CppWindowsService in OnStop", 
		EVENTLOG_INFORMATION_TYPE);

	// Indicate that the service is stopping and wait for the finish of the 
	// main service function (ServiceWorkerThread).
	m_fStopping = TRUE;
	if (WaitForSingleObject(m_hStoppedEvent, INFINITE) != WAIT_OBJECT_0)
	{
		throw GetLastError();
	}

	// Free the memory mapping
	if (hMapFile != nullptr && pBuf != nullptr) {
		UnMapSharedMemory(hMapFile, pBuf);
		WriteEventLogEntry(L"CppWindowsService Unmapped shared memory",
			EVENTLOG_INFORMATION_TYPE);
	}

	// After we have completed our task, don't forget to disable the privilege
	if (SetPrivilege(hToken, lpszPrivilege, FALSE)) {
		WriteEventLogEntry(L"CppWindowsService SetPrivilege() back succeeded!",
			EVENTLOG_INFORMATION_TYPE);
	} else {
		WriteEventLogEntry(L"CppWindowsService Error in SetPrivilege() back!",
			EVENTLOG_ERROR_TYPE);
	}
}