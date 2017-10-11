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
#include <aclapi.h>

#define WIDTH 1920
#define HEIGHT 1080
#define BUF_SIZE WIDTH * HEIGHT * 2
#define FPS 1000/33

TCHAR szName[] = TEXT("Global\\MyFileMappingObject");
HANDLE hMapFile = nullptr;
HANDLE hToken = nullptr;
LPCTSTR pBuf = nullptr;
BYTE pixel = 0;

BOOL CreateAndMapSharedMemory(HANDLE *hMapFile, LPCTSTR *pBuf, LPSECURITY_ATTRIBUTES lpAttributes)
{
	*hMapFile = CreateFileMapping(
		INVALID_HANDLE_VALUE,    // use paging file
		lpAttributes,            // security attributes or NULL for default security
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

BOOL CreateAndMapSharedMemoryWithSecurity(HANDLE *hMapFile, LPCTSTR *pBuf)
{

	DWORD dwRes, dwDisposition;
	PSID pUserSID = NULL, pAdminSID = NULL;
	PACL pACL = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	EXPLICIT_ACCESS ea[2];
	SID_IDENTIFIER_AUTHORITY SIDAuthUser = SECURITY_LOCAL_SID_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
	SECURITY_ATTRIBUTES sa;
	LONG lRes;
	HKEY hkSub = NULL;
	BOOL retval = FALSE;

	// Create a well-known SID for the Logged on User.
	if (!AllocateAndInitializeSid(&SIDAuthUser, 1,
		SECURITY_LOCAL_LOGON_RID,
		0, 0, 0, 0, 0, 0, 0,
		&pUserSID))
	{
		_tprintf(_T("AllocateAndInitializeSid Error %u\n"), GetLastError());
		goto Cleanup;
	}

	// Initialize an EXPLICIT_ACCESS structure for an ACE.
	// The ACE will allow Logged on User to access shared memory.
	ZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));
	ea[0].grfAccessPermissions = FILE_MAP_ALL_ACCESS;
	ea[0].grfAccessMode = SET_ACCESS;
	ea[0].grfInheritance = NO_INHERITANCE;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea[0].Trustee.ptstrName = (LPTSTR)pUserSID;

	// Create a SID for the BUILTIN\Administrators group.
	if (!AllocateAndInitializeSid(&SIDAuthNT, 2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&pAdminSID))
	{
		_tprintf(_T("AllocateAndInitializeSid Error %u\n"), GetLastError());
		goto Cleanup;
	}

	// Initialize an EXPLICIT_ACCESS structure for an ACE.
	// The ACE will allow the Administrators group full access to the shared memory
	ea[1].grfAccessPermissions = FILE_MAP_ALL_ACCESS;
	ea[1].grfAccessMode = SET_ACCESS;
	ea[1].grfInheritance = NO_INHERITANCE;
	ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[1].Trustee.ptstrName = (LPTSTR)pAdminSID;

	// Create a new ACL that contains the new ACEs.
	dwRes = SetEntriesInAcl(2, ea, NULL, &pACL);
	if (ERROR_SUCCESS != dwRes)
	{
		_tprintf(_T("SetEntriesInAcl Error %u\n"), GetLastError());
		goto Cleanup;
	}

	// Initialize a security descriptor.  
	pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR,
		SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (NULL == pSD)
	{
		_tprintf(_T("LocalAlloc Error %u\n"), GetLastError());
		goto Cleanup;
	}

	if (!InitializeSecurityDescriptor(pSD,
		SECURITY_DESCRIPTOR_REVISION))
	{
		_tprintf(_T("InitializeSecurityDescriptor Error %u\n"),
			GetLastError());
		goto Cleanup;
	}

	// Add the ACL to the security descriptor. 
	if (!SetSecurityDescriptorDacl(pSD,
		TRUE,     // bDaclPresent flag   
		pACL,
		FALSE))   // not a default DACL 
	{
		_tprintf(_T("SetSecurityDescriptorDacl Error %u\n"),
			GetLastError());
		goto Cleanup;
	}

	// Initialize a security attributes structure.
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = pSD;
	sa.bInheritHandle = FALSE;

	// Use the security attributes to set the security descriptor 
	retval = CreateAndMapSharedMemory(hMapFile, pBuf, &sa);

Cleanup:

	if (pUserSID)
		FreeSid(pUserSID);
	if (pAdminSID)
		FreeSid(pAdminSID);
	if (pACL)
		LocalFree(pACL);
	if (pSD)
		LocalFree(pSD);
	if (hkSub)
		RegCloseKey(hkSub);

	return retval;

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

	// Create and map shared memory
	if (CreateAndMapSharedMemoryWithSecurity(&hMapFile, &pBuf)) {
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
}