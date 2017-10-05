#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <string>
#include <memory>
#include "pipe.h"

bool initialize_pipe_sa(SECURITY_ATTRIBUTES& sa)
{
	bool succeeded = false;
	ZeroMemory(&sa, sizeof(SECURITY_ATTRIBUTES));
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	/*if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
		TEXT("S:(ML;;NW;;;LW)D:(A;;GRGW;;;WD)(A;;GRGW;;;S-1-15-2-1)"), //S-1-15-2-1 = ALL_APP_PACKAGES(UWP)
		SDDL_REVISION_1,
		&sa.lpSecurityDescriptor, NULL))
		return;
		*/
	PSECURITY_DESCRIPTOR pSD = nullptr;
	EXPLICIT_ACCESS ea[2];
	PSID pEveryoneSID = NULL, pAppPackagesSID = NULL, pLowSID = NULL;
	PACL pDacl = NULL, pSacl = NULL;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY sia = SECURITY_MANDATORY_LABEL_AUTHORITY;
	if (!AllocateAndInitializeSid(&SIDAuthWorld, 1,
		SECURITY_WORLD_RID,
		0, 0, 0, 0, 0, 0, 0,
		&pEveryoneSID))
		goto Cleanup;
	ZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));
	ea[0].grfAccessPermissions = GENERIC_READ | GENERIC_WRITE; //FILE_ALL_ACCESS
	ea[0].grfAccessMode = SET_ACCESS;
	ea[0].grfInheritance = NO_INHERITANCE;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea[0].Trustee.ptstrName = (LPTSTR)pEveryoneSID;
	//https://msdn.microsoft.com/en-us/library/cc980032.aspx

	//this code is used instead of the above as it's a lot simpler.
	int entries = 1;
	if (ConvertStringSidToSid(L"S-1-15-2-1", &pAppPackagesSID)) { //this was added so the dlls injected into UWP apps could communicate with the parent process.
		ea[1].grfAccessPermissions = GENERIC_READ | GENERIC_WRITE; //FILE_ALL_ACCESS
		ea[1].grfAccessMode = SET_ACCESS;
		ea[1].grfInheritance = NO_INHERITANCE;
		ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID; // TRUSTEE_IS_NAME(if ptstrName == L"ALL APPLICATION PACKAGES");
		ea[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
		ea[1].Trustee.ptstrName = (LPTSTR)pAppPackagesSID; //L"ALL APPLICATION PACKAGES"
		++entries;
	}
	if (SetEntriesInAcl(entries, ea, NULL, &pDacl) != ERROR_SUCCESS)
		goto Cleanup;
	pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
		goto Cleanup;
	if (!SetSecurityDescriptorDacl(pSD, TRUE, pDacl, FALSE))
		goto Cleanup;
	//build sacl to allow low integrity processes to access the pipe.

	DWORD dwACLSize = sizeof(ACL) + sizeof(SYSTEM_MANDATORY_LABEL_ACE) + GetSidLengthRequired(1);
	pSacl = (PACL)LocalAlloc(LPTR, dwACLSize);
	InitializeAcl(pSacl, dwACLSize, ACL_REVISION);
	AllocateAndInitializeSid(&sia, 1, SECURITY_MANDATORY_LOW_RID, 0, 0, 0, 0,
		0, 0, 0, &pLowSID); //pLowSID = low integrity sid

							//https://github.com/huku-/injectdso/blob/master/injectdll/pipe.c
							//http://stackoverflow.com/a/38414023

	if (!AddMandatoryAce(pSacl, ACL_REVISION, 0, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, pLowSID))
		goto Cleanup;
	if (!SetSecurityDescriptorSacl(pSD, TRUE, pSacl, FALSE))
		goto Cleanup;

	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = pSD;
	sa.bInheritHandle = FALSE;
	//note: the dacl/sacl we allocated will be used in the security descriptor so we must also make sure they aren't freed.
	pSD = nullptr; 
	pDacl = pSacl = nullptr;
	succeeded = true;
Cleanup:
	if (pDacl)
		LocalFree(pDacl);
	if (pSacl)
		LocalFree(pSacl);
	if (pEveryoneSID)
		FreeSid(pEveryoneSID);
	if (pAppPackagesSID)
		FreeSid(pAppPackagesSID);
	if (pLowSID)
		FreeSid(pLowSID);
	if (pSD)
		LocalFree(pSD);
	return succeeded;
}

pipe::server::server(const std::string & name)
{
	this->name = "\\\\.\\pipe\\" + name;
	hPipe = this->listen();
}

pipe::server::~server()
{
	this->close();
}

pipe::sPipeClientHandle pipe::server::accept()
{
	HANDLE hPipeTmp = listen();
	std::unique_ptr<OVERLAPPED> ovl(new OVERLAPPED);
	ZeroMemory(ovl.get(), sizeof(OVERLAPPED));
	ovl->hEvent = ::CreateEvent(nullptr, TRUE, FALSE, nullptr);
	ConnectNamedPipe(hPipe, ovl.get());
	int gle = GetLastError();
	if (gle != ERROR_IO_PENDING && gle != ERROR_PIPE_CONNECTED)
	{
		CancelIo(hPipe);
		if (ovl->hEvent)
			CloseHandle(ovl->hEvent);
		CloseHandle(hPipe);
		hPipe = hPipeTmp;
		return{ INVALID_HANDLE_VALUE };
	}
	else {
		if (gle == ERROR_IO_PENDING) {
			if (WaitForSingleObject(ovl->hEvent, 1000) != WAIT_OBJECT_0) {
				CancelIo(hPipe);
				CloseHandle(ovl->hEvent);
				CloseHandle(hPipe);
				hPipe = hPipeTmp;
				return{ INVALID_HANDLE_VALUE };
			}
			DWORD dwIgnore;
			if (!GetOverlappedResult(hPipe, ovl.get(), &dwIgnore, FALSE)) {
				CancelIo(hPipe);
				CloseHandle(ovl->hEvent);
				CloseHandle(hPipe);
				hPipe = hPipeTmp;
				return{ INVALID_HANDLE_VALUE };
			}
			CloseHandle(ovl->hEvent);
			ovl->hEvent = NULL;
		}
		HANDLE hTmp = hPipe;
		hPipe = hPipeTmp;
		return{ hTmp, std::move(ovl) };
	}
}

HANDLE pipe::server::listen()
{
	SECURITY_ATTRIBUTES sec;
	initialize_pipe_sa(sec);
	HANDLE h = CreateNamedPipeA(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, 512, 512, NULL, &sec);
	if (sec.lpSecurityDescriptor) {
		auto descriptor = reinterpret_cast<SECURITY_DESCRIPTOR*>(sec.lpSecurityDescriptor);
		sec.lpSecurityDescriptor = nullptr;
		LocalFree(descriptor->Dacl);
		LocalFree(descriptor->Sacl);
		LocalFree(descriptor);
	}
	return h;
}

pipe::client::client()
{
	hPipe = INVALID_HANDLE_VALUE;
}

pipe::client::client(sPipeClientHandle && handle)
{
	hPipe = handle.hClient;
	ovl = std::move(handle.ovl);
	bConnected = hPipe != INVALID_HANDLE_VALUE;
}

pipe::client::client(client && other):ovl(std::move(other.ovl))
{
	this->bConnected = other.bConnected;
	this->hPipe = other.hPipe;
	other.hPipe = INVALID_HANDLE_VALUE;
	other.bConnected = false;
}

pipe::client::~client()
{
	this->close();
}

bool pipe::client::connect(const std::string & name)
{
	if (hPipe != INVALID_HANDLE_VALUE) {
		::CloseHandle(hPipe);
		hPipe = INVALID_HANDLE_VALUE;
		bConnected = false;
	}
	auto pipename = "\\\\.\\pipe\\" + name;
	hPipe = CreateFileA(pipename.c_str(), GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	//bBusy = (GetLastError() == ERROR_PIPE_BUSY); //ERROR_PIPE_NOT_CONNECTED
	return (bConnected = hPipe != INVALID_HANDLE_VALUE);
}

bool pipe::client::wait(const std::string & name, DWORD timeout)
{
	auto pipe = "\\\\.\\pipe\\" + name;
	return (WaitNamedPipeA(pipe.c_str(), timeout) == TRUE);
}

bool pipe::client::read(LPVOID pBuffer, DWORD len)
{
	DWORD dwRead;
	BOOL bRead = ::ReadFile(hPipe, pBuffer, len, &dwRead, nullptr);
	bConnected = bRead == TRUE;
	return bRead && dwRead == len;
}

bool pipe::client::write(LPCVOID pBuffer, DWORD len)
{
	DWORD dwWritten;
	BOOL bWritten = ::WriteFile(hPipe, pBuffer, len, &dwWritten, nullptr);
	bConnected = bWritten == TRUE;
	return bWritten && dwWritten == len;
}
