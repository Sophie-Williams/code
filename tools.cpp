#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <list>
#include <memory>
#include <vector>
#include "tools.h"
#include <shellapi.h>
#include <codecvt>
#include <locale>
#include <VersionHelpers.h>
#include <lmcons.h>
#include <aclapi.h>

#include <objidl.h>
#include <gdiplus.h>

#include "registry.h"

#include <LM.h>
#include <sddl.h>

#include <TlHelp32.h>

//for tools::app::startup
#include <taskschd.h>
#include <comutil.h>

//for tools::file::patch
#include <algorithm>

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Version.lib") //Mincore.lib
#pragma comment(lib, "Gdiplus.lib")
#pragma comment(lib, "Advapi32.lib")

//for tools::app::startup
#pragma comment(lib, "Taskschd.lib")
#pragma comment(lib, "comsupp.lib") //#pragma comment(lib, "comsuppw.lib")  

using namespace Gdiplus;

#pragma region tools::app

std::list<std::string> tools::app::get_args()
{
	LPWSTR *szArglist;
	int nArgs;
	szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
	if (szArglist == nullptr)
		return std::list<std::string>();
	std::list<std::string> args;
	using convert_type = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_type, wchar_t> converter;
	for (int i = 0; i < nArgs; i++)
		args.push_back(converter.to_bytes(szArglist[i]));
	LocalFree(szArglist);
	return args;
}

std::list<std::wstring> tools::app::get_wargs()
{
	LPWSTR *szArglist;
	int nArgs;
	szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
	if (szArglist == nullptr)
		return std::list<std::wstring>();
	std::list<std::wstring> args;
	for (int i = 0; i < nArgs; i++)
		args.push_back(szArglist[i]);
	LocalFree(szArglist);
	return args;
}

std::string tools::app::get_filename()
{
	auto args = get_args();
	if (args.size() == 0)
		return "";
	return args.front();
}

std::wstring tools::app::get_wfilename()
{
	auto args = get_wargs();
	if (args.size() == 0)
		return L"";
	return args.front();
}

std::string tools::app::get_path()
{
	return tools::strip_filename(get_filename());
}

std::wstring tools::app::get_wpath()
{
	return tools::strip_filename(get_wfilename());
}

bool tools::app::stripzoneid()
{
	auto zoneid = get_wfilename() + L":Zone.Identifier";
	if (GetFileAttributes(zoneid.c_str()) == INVALID_FILE_ATTRIBUTES)
		return true;
	return ::DeleteFile(zoneid.c_str()) == TRUE;
}

bool tools::app::elevated()
{
	return process::elevated();
}

bool tools::app::startup(const std::wstring & task_name, bool bEnable)
{
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
		return false;
	hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	if (FAILED(hr)) {
		CoUninitialize();
		return false;
	}
	ITaskService* pService = nullptr;
	hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
	if (FAILED(hr)) {
		CoUninitialize();
		return false;
	}
	hr = pService->Connect(_variant_t(), _variant_t(),
		_variant_t(), _variant_t());
	if (FAILED(hr))
	{
		pService->Release();
		CoUninitialize();
		return false;
	}
	ITaskFolder *pRootFolder = NULL;
	hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
	if (FAILED(hr))
	{
		pService->Release();
		CoUninitialize();
		return false;
	}
	pRootFolder->DeleteTask(_bstr_t(task_name.c_str()), NULL);
	if (bEnable) {
		ITaskDefinition *pTask = NULL;
		hr = pService->NewTask(0, &pTask);
		if (FAILED(hr))
		{
			pRootFolder->Release();
			pService->Release();
			CoUninitialize();
			return false;
		}
		IRegistrationInfo *pRegInfo = NULL;
		hr = pTask->get_RegistrationInfo(&pRegInfo);
		if (SUCCEEDED(hr))
		{
			pRegInfo->put_Author(L"Greed");
			pRegInfo->Release();
		}
		IPrincipal *pPrincipal = NULL;
		hr = pTask->get_Principal(&pPrincipal);
		if (FAILED(hr))
		{
			pTask->Release();
			pRootFolder->DeleteTask(_bstr_t(task_name.c_str()), NULL);
			pRootFolder->Release();
			pService->Release();
			CoUninitialize();
			return false;
		}
		hr = pPrincipal->put_Id(_bstr_t(L"Principal1"));
		hr = pPrincipal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN); //https://msdn.microsoft.com/en-us/library/windows/desktop/aa383566(v=vs.85).aspx
		if (tools::app::elevated()) {
			hr = pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
			hr = pPrincipal->put_GroupId(_bstr_t(L"S-1-5-32-544")); // https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems --> maybe experiment with some more options?
		}
		else
			hr = pPrincipal->put_RunLevel(TASK_RUNLEVEL_LUA);
		hr = pPrincipal->put_DisplayName(_bstr_t(task_name.c_str()));
		pPrincipal->Release();
		if (FAILED(hr))
		{
			pTask->Release();
			pRootFolder->DeleteTask(_bstr_t(task_name.c_str()), NULL);
			pRootFolder->Release();
			pService->Release();
			CoUninitialize();
			return false;
		}
		ITaskSettings *pSettings = NULL;
		hr = pTask->get_Settings(&pSettings);
		if (FAILED(hr))
		{
			pTask->Release();
			pRootFolder->DeleteTask(_bstr_t(task_name.c_str()), NULL);
			pRootFolder->Release();
			pService->Release();
			CoUninitialize();
			return false;
		}

		hr = pSettings->put_StartWhenAvailable(VARIANT_TRUE);
		hr = pSettings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
		hr = pSettings->put_Enabled(VARIANT_TRUE);
		hr = pSettings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
		hr = pSettings->put_AllowDemandStart(VARIANT_TRUE);
		hr = pSettings->put_RunOnlyIfIdle(VARIANT_FALSE);
		hr = pSettings->put_RunOnlyIfNetworkAvailable(VARIANT_FALSE);

		hr = pSettings->put_WakeToRun(VARIANT_TRUE);
		hr = pSettings->put_AllowHardTerminate(VARIANT_FALSE);

		hr = pSettings->put_ExecutionTimeLimit(_bstr_t(L"PT0S")); //allow task to run indefinitely

		pSettings->Release();
		if (FAILED(hr))
		{
			pTask->Release();
			pRootFolder->DeleteTask(_bstr_t(task_name.c_str()), NULL);
			pRootFolder->Release();
			pService->Release();
			CoUninitialize();
			return false;
		}
		ITriggerCollection *pTriggerCollection = NULL;
		hr = pTask->get_Triggers(&pTriggerCollection);
		if (FAILED(hr))
		{
			pTask->Release();
			pRootFolder->DeleteTask(_bstr_t(task_name.c_str()), NULL);
			pRootFolder->Release();
			pService->Release();
			CoUninitialize();
			return false;
		}
		//pTriggerCollection->get_Count() -> if count > 0 skip
		ITrigger *pTrigger = NULL;
		hr = pTriggerCollection->Create(TASK_TRIGGER_LOGON/*TASK_TRIGGER_BOOT*/, &pTrigger);
		pTriggerCollection->Release();
		if (FAILED(hr))
		{
			pTask->Release();
			pRootFolder->DeleteTask(_bstr_t(task_name.c_str()), NULL);
			pRootFolder->Release();
			pService->Release();
			CoUninitialize();
			return false;
		}
		ILogonTrigger *pLogonTrigger = NULL;
		hr = pTrigger->QueryInterface(
			IID_ILogonTrigger, (void**)&pLogonTrigger);
		pTrigger->Release();
		if (FAILED(hr))
		{
			pTask->Release();
			pRootFolder->DeleteTask(_bstr_t(task_name.c_str()), NULL);
			pRootFolder->Release();
			pService->Release();
			CoUninitialize();
			return false;
		}

		if (tools::app::elevated())
			hr = pLogonTrigger->put_UserId(_bstr_t(L""));
		else
			hr = pLogonTrigger->put_UserId(_bstr_t(tools::user::username().c_str()));
		BSTR i = nullptr;
		pLogonTrigger->get_UserId(&i);
		pLogonTrigger->Release();

		IActionCollection *pActionCollection = NULL;
		hr = pTask->get_Actions(&pActionCollection);
		if (FAILED(hr))
		{
			pTask->Release();
			pRootFolder->DeleteTask(_bstr_t(task_name.c_str()), NULL);
			pRootFolder->Release();
			pService->Release();
			CoUninitialize();
			return false;
		}
		IAction *pAction = NULL;
		hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
		pActionCollection->Release();
		if (FAILED(hr))
		{
			pTask->Release();
			pRootFolder->DeleteTask(_bstr_t(task_name.c_str()), NULL);
			pRootFolder->Release();
			pService->Release();
			CoUninitialize();
			return false;
		}
		IExecAction *pExecAction = NULL;
		hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
		pAction->Release();
		if (FAILED(hr))
		{
			pTask->Release();
			pRootFolder->DeleteTask(_bstr_t(task_name.c_str()), NULL);
			pRootFolder->Release();
			pService->Release();
			CoUninitialize();
			return false;
		}
		hr = pExecAction->put_Path(_bstr_t(tools::app::get_wfilename().c_str()));
		hr = pExecAction->put_Arguments(_bstr_t(L"-X"));
		pExecAction->Release();
		if (FAILED(hr))
		{
			pTask->Release();
			pRootFolder->DeleteTask(_bstr_t(task_name.c_str()), NULL);
			pRootFolder->Release();
			pService->Release();
			CoUninitialize();
			return false;
		}

		IRegisteredTask *pRegisteredTask = NULL;
		hr = pRootFolder->RegisterTaskDefinition(
			_bstr_t(task_name.c_str()),
			pTask,
			TASK_CREATE_OR_UPDATE,
			_variant_t(),
			_variant_t(),
			TASK_LOGON_INTERACTIVE_TOKEN, //TASK_LOGON_SERVICE_ACCOUNT
			_variant_t(),
			&pRegisteredTask);
		pTask->Release();
		if (SUCCEEDED(hr))
			pRegisteredTask->Release();
	}
	pRootFolder->Release();
	pService->Release();
	CoUninitialize();
	return SUCCEEDED(hr);
}

bool tools::app::set_privilege(const std::wstring & privilege, const bool bEnable)
{
	return process::set_privilege(privilege, bEnable);
}

#pragma endregion

#pragma region ::tools::

std::wstring tools::expand_environment_strings(const std::wstring & s)
{
	std::wstring r;
	auto dwRequired = ExpandEnvironmentStrings(s.c_str(), nullptr, NULL);
	r.resize(dwRequired - 1);
	if (ExpandEnvironmentStrings(s.c_str(), &r[0], dwRequired) == dwRequired)
		return r;
	return s;
}

std::string tools::expand_environment_strings(const std::string & s)
{
	std::string r;
	auto dwRequired = ExpandEnvironmentStringsA(s.c_str(), nullptr, NULL);
	r.resize(dwRequired - 1);
	if (ExpandEnvironmentStringsA(s.c_str(), &r[0], dwRequired) == dwRequired)
		return r;
	return s;
}

std::string tools::strip_filename(const std::string & file)
{
	if (file.length() == 0)
		return "";
	auto s = file;
	for (auto i = s.length() - 1; i > 0; i--) {
		if (s[i] == '/' || s[i] == '\\') {
			s.resize(i + 1);
			return s;
		}
	}
	return file;
}

std::wstring tools::strip_filename(const std::wstring & file)
{
	if (file.length() == 0)
		return L"";
	auto s = file;
	for (auto i = s.length() - 1; i > 0; i--) {
		if (s[i] == L'/' || s[i] == L'\\') {
			s.resize(i + 1);
			return s;
		}
	}
	return file;
}

std::string tools::strip_path(const std::string & file)
{
	if (file.length() == NULL)
		return "";
	for (size_t i = file.length() - 1; i > 0; i--)
		if (file[i] == '/' || file[i] == '\\')
			return file.substr(i + 1);
	return "";
}

std::wstring tools::strip_path(const std::wstring & file)
{
	if (file.length() == NULL)
		return L"";
	for (size_t i = file.length() - 1; i > 0; i--)
		if (file[i] == L'/' || file[i] == L'\\')
			return file.substr(i + 1);
	return L"";
}

std::string tools::between(const std::string & search_str, const std::string & str1, const std::string & str2)
{
	auto pos = search_str.find(str1);
	if (pos == std::string::npos)
		return "";
	pos += str1.length();
	auto pos2 = search_str.find(str2, pos);
	if (pos2 == std::string::npos)
		return "";
	return search_str.substr(pos, pos2 - pos);
}

std::wstring tools::between(const std::wstring & search_str, const std::wstring & str1, const std::wstring & str2)
{
	auto pos = search_str.find(str1);
	if (pos == std::string::npos)
		return L"";
	pos += str1.length();
	auto pos2 = search_str.find(str2, pos);
	if (pos2 == std::string::npos)
		return L"";
	return search_str.substr(pos, pos2 - pos);
}

std::vector<std::string> tools::split(const std::string & search, char delim)
{
	std::vector<std::string> results;
	size_t oindex = 0, cindex;
	while ((cindex = search.find(delim, oindex)) != std::string::npos) {
		results.push_back(search.substr(oindex, cindex - oindex));
		oindex = cindex + 1;
	}
	if (oindex < search.length())
		results.push_back(search.substr(oindex));
	return results;
}

std::vector<std::wstring> tools::split(const std::wstring & search, wchar_t delim)
{
	std::vector<std::wstring> results;
	size_t oindex = 0, cindex;
	while ((cindex = search.find(delim, oindex)) != std::wstring::npos) {
		results.push_back(search.substr(oindex, cindex - oindex));
		oindex = cindex + 1;
	}
	if (oindex < search.length())
		results.push_back(search.substr(oindex));
	return results;
}

std::vector<std::string> tools::split(const std::string & search, const std::string & delim)
{
	std::vector<std::string> results;
	size_t oindex = 0, cindex;
	while ((cindex = search.find(delim, oindex)) != std::string::npos) {
		results.push_back(search.substr(oindex, cindex - oindex));
		oindex = cindex + delim.length();
	}
	if (oindex < search.length())
		results.push_back(search.substr(oindex));
	return results;
}

std::vector<std::wstring> tools::split(const std::wstring & search, const std::wstring & delim)
{
	std::vector<std::wstring> results;
	size_t oindex = 0, cindex;
	while ((cindex = search.find(delim, oindex)) != std::wstring::npos) {
		results.push_back(search.substr(oindex, cindex - oindex));
		oindex = cindex + delim.length();
	}
	if (oindex < search.length())
		results.push_back(search.substr(oindex));
	return results;
}

#pragma endregion

#pragma region tools::process

bool tools::process::isWoW64(HANDLE hProcess)
{
	FARPROC p = GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");
	if (!p)
		return false; //I believe this will occur on 32-bit Windows?

	BOOL bResult, bSuccess = ((BOOL(WINAPI*)(HANDLE, PBOOL))p)(hProcess, &bResult);
	if (!bSuccess)
		return false;
	if (bResult)
		return true;
	else
		return false;
}

bool tools::process::is_64(HANDLE hProcess)
{
	FARPROC p = GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");
	if (!p)
		return false;
	BOOL bResult, bSuccess = ((BOOL(WINAPI*)(HANDLE, PBOOL))p)(hProcess, &bResult);
	if (!bSuccess)
		return false;
	return (bResult == FALSE);
}

std::wstring tools::process::get_sid(DWORD dwPID)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPID);
	if (hProcess == NULL)
		return L"";
	std::wstring sid = get_sid(hProcess);
	::CloseHandle(hProcess);
	return sid;
}

std::wstring tools::process::get_sid(HANDLE hProcess)
{
	if (!hProcess)
		return L"";
	HANDLE hToken = NULL;
	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
		return L"";
	DWORD dwSize = MAX_PATH, dwSize2 = MAX_PATH;
	DWORD dwLength = 0;
	if (!GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwLength))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			CloseHandle(hToken);
			return L"";
		}
	}
	std::unique_ptr<BYTE> ptu(new BYTE[dwLength]);
	ZeroMemory(ptu.get(), dwLength);
	if (!GetTokenInformation(hToken, TokenUser, ptu.get(), dwLength, &dwLength))
	{
		CloseHandle(hToken);
		return L"";
	}
	CloseHandle(hToken);
	std::wstring sid;
	LPWSTR s;
	if (ConvertSidToStringSidW(reinterpret_cast<PTOKEN_USER>(ptu.get())->User.Sid, &s)) {
		sid = s;
		LocalFree(s);
	}
	return sid;
}

std::wstring tools::process::FullImageName(DWORD dwPID)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPID);
	if (hProcess == NULL)
		return L"";
	auto filename = FullImageName(hProcess);
	::CloseHandle(hProcess);
	return filename;
}

std::wstring tools::process::FullImageName(HANDLE hProcess)
{
	wchar_t wPath[MAX_PATH] = {};
	DWORD dwQuerySize = MAX_PATH;
	if (!QueryFullProcessImageName(hProcess, 0, wPath, &dwQuerySize))
		return L"";
	return wPath;
}

HICON tools::process::icon(DWORD dwPID)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPID);
	if (hProcess == NULL)
		return NULL;
	auto hIcon = icon(hProcess);
	::CloseHandle(hProcess);
	return hIcon;
}

HICON tools::process::icon(HANDLE hProcess)
{
	if (!hProcess)
		return NULL;
	auto filename = FullImageName(hProcess);
	if (filename.empty())
		return NULL;
	return file::icon(filename);
}

bool tools::process::kill(DWORD dwPID)
{
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, dwPID);
	if (hProcess == NULL)
		return false;
	bool bSuccess = kill(hProcess);
	::CloseHandle(hProcess);
	return bSuccess;
}

bool tools::process::kill(HANDLE hProcess)
{
	if (hProcess != 0) {
		if (TerminateProcess(hProcess, (DWORD)-1))
			return true;
	}
	return false;
}

bool tools::process::suspend(DWORD dwPID, bool bSuspend)
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); //requires #include <TlHelp32.h>
	if (hSnap == INVALID_HANDLE_VALUE)
		return false;
	bool bSuccess = false;
	THREADENTRY32 te32 = {};
	te32.dwSize = sizeof(THREADENTRY32);
	if (Thread32First(hSnap, &te32))
		do {
			if (te32.th32OwnerProcessID == dwPID)
			{
				HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
				if (hThread == NULL)
					continue;
				DWORD dwSuccess = bSuspend ? SuspendThread(hThread) : ResumeThread(hThread);
				CloseHandle(hThread);
				bSuccess = (dwSuccess != (DWORD)-1);
				if (!bSuccess)
					break;
			}
		} while (Thread32Next(hSnap, &te32));
		CloseHandle(hSnap);
		return bSuccess;
}

std::wstring tools::process::description(DWORD dwPID)
{
	return file::description(process::FullImageName(dwPID));
}

std::wstring tools::process::description(HANDLE hProcess)
{
	return file::description(process::FullImageName(hProcess));
}

std::wstring tools::process::version(DWORD dwPID)
{
	return file::version(process::FullImageName(dwPID));
}

std::wstring tools::process::version(HANDLE hProcess)
{
	return file::version(process::FullImageName(hProcess));
}

bool tools::process::elevated(HANDLE hProcess)
{
	HANDLE hToken;
	if (!OpenProcessToken(hProcess, TOKEN_QUERY/*TOKEN_READ*/, &hToken))
		return false;
	TOKEN_ELEVATION elevation;
	DWORD dwInfoLen;
	if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwInfoLen)) {
		CloseHandle(hToken);
		return false;
	}
	::CloseHandle(hToken);
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup;
	BOOL b = AllocateAndInitializeSid(
		&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&AdministratorsGroup);
	if (b)
	{
		if (!CheckTokenMembership(NULL, AdministratorsGroup, &b))
			b = FALSE;
		FreeSid(AdministratorsGroup);
	}
	return elevation.TokenIsElevated > 0 && b;
}

bool tools::process::set_privilege(const std::wstring & privilege, const bool bEnable, HANDLE hProcess)
{
	HANDLE hToken;
	if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;
	TOKEN_PRIVILEGES tkp;
	if (!LookupPrivilegeValue(nullptr, privilege.c_str(), &tkp.Privileges[0].Luid)) {
		CloseHandle(hToken);
		return FALSE;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : NULL;
	/*if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)
	|| GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
	CloseHandle(hToken);
	return FALSE;
	}*/
	AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr); 
	/*
	If the function succeeds, the return value is nonzero.
	To determine whether the function adjusted all of the specified privileges, call GetLastError, 
	which returns one of the following values when the function succeeds:

	Return code				Description
	ERROR_SUCCESS			The function adjusted all specified privileges.
	ERROR_NOT_ALL_ASSIGNED	The token does not have one or more of the privileges specified in the NewState parameter. The function may succeed with this error value even if no privileges were adjusted. The PreviousState parameter indicates the privileges that were adjusted.
	*/

	bool bSuccess = GetLastError() == ERROR_SUCCESS;
	CloseHandle(hToken);
	return bSuccess;
}

#pragma endregion

#pragma region tools::system

std::wstring tools::system::name(_COMPUTER_NAME_FORMAT format)
{
	wchar_t computername[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD dwLen = sizeof(computername) / sizeof(wchar_t);
	if (!GetComputerNameEx(format, computername, &dwLen))
		return L"";
	return computername;
}

std::wstring tools::system::domain()
{
	return system::name(ComputerNameDnsDomain);
}

std::wstring tools::system::fqdn()
{
	return system::name(ComputerNameDnsFullyQualified);
}

std::wstring tools::system::language()
{
	wchar_t locale[LOCALE_NAME_MAX_LENGTH];
	if (GetSystemDefaultLocaleName(locale, sizeof(locale) / sizeof(wchar_t)) == 0)
		return L"";
	return locale;
}

LANGID tools::system::langid()
{
	return GetSystemDefaultUILanguage(); //appears to return the same value as GetSystemDefaultLangID()
}

ULONGLONG tools::system::ram()
{
	//GetPhysicallyInstalledSystemMemory() is only for Vista SP1+
	/*
	ULONGLONG ullMem;
	if (GetPhysicallyInstalledSystemMemory(&ullMem))
		return ullMem;
	*/
	MEMORYSTATUSEX statex;
	statex.dwLength = sizeof(statex);
	GlobalMemoryStatusEx(&statex);
	return statex.ullTotalPhys;
}

::tools::system::OperatingSystems tools::system::OS()
{
	if (IsWindows10OrGreater()) {
		if (IsWindowsServer())
			return OperatingSystems::windows_server_2016;
		else
			return OperatingSystems::windows_10;
	}
	else
		if (IsWindows8Point1OrGreater()) {
			if (IsWindowsServer())
				return OperatingSystems::windows_server_2012R2;
			else
				return OperatingSystems::windows_8point1;
		}
		else if (IsWindows8OrGreater()) {
			if (IsWindowsServer())
				return OperatingSystems::windows_server_2012;
			else
				return OperatingSystems::windows_8;
		}
		else if (IsWindows7OrGreater()) {
			if (IsWindowsServer())
				return OperatingSystems::windows_server_2008R2;
			else {
				if (IsWindows7SP1OrGreater())
					return OperatingSystems::windows_7_SP1;
				else
					return OperatingSystems::windows_7;
			}
		}
		else if (IsWindowsVistaOrGreater()) {
			if (IsWindowsServer())
				return OperatingSystems::windows_server_2008;
			else {
				if (IsWindowsVistaSP2OrGreater())
					return OperatingSystems::windows_vista_SP2;
				else if (IsWindowsVistaSP1OrGreater())
					return OperatingSystems::windows_vista_SP1;
				else
					return OperatingSystems::windows_vista;
			}
		}
		else if (IsWindowsXPOrGreater()) {
			if (IsWindowsServer())
				return OperatingSystems::windows_server_2003;
			else {
				if (IsWindowsXPSP3OrGreater())
					return OperatingSystems::windows_XP_SP3;
				else if (IsWindowsXPSP2OrGreater())
					return OperatingSystems::windows_XP_SP2;
				else if (IsWindowsXPSP1OrGreater())
					return OperatingSystems::windows_XP_SP1;
				else
					return OperatingSystems::windows_XP;
			}
		}
		else
			return OperatingSystems::os_unknown;
}

std::wstring tools::system::OStoString(OperatingSystems system)
{
	switch (system) {
	case windows_10:
		return L"Windows 10";
		break;
	case windows_server_2016:
		return L"Windows Server 2016";
		break;
	case windows_8point1:
		return L"Windows 8.1";
		break;
	case windows_server_2012R2:
		return L"Windows Server 2012 R2";
		break;
	case windows_8:
		return L"Windows 8";
		break;
	case windows_server_2012:
		return L"Windows Server 2012";
		break;
	case windows_7:
		return L"Windows 7";
		break;
	case windows_7_SP1:
		return L"Windows 7 SP1";
		break;
	case windows_server_2008R2:
		return L"Windows Server 2008 R2";
		break;
	case windows_vista:
		return L"Windows Vista";
		break;
	case windows_vista_SP1:
		return L"Windows Vista SP1";
		break;
	case windows_vista_SP2:
		return L"Windows Vista SP2";
		break;
	case windows_server_2008:
		return L"Windows Server 2008";
		break;
	case windows_XP_SP3:
		return L"Windows XP SP3";
		break;
	case windows_XP_SP2:
		return L"Windows XP SP2";
		break;
	case windows_XP_SP1:
		return L"Windows XP SP1";
		break;
	case windows_XP:
		return L"Windows XP";
		break;
	case windows_server_2003:
		return L"Windows Server 2003";
		break;
	default:
		return L"<unknown>";
	}
}

/*
Tools::system::DeviceTypes Tools::system::type()
{
//https://msdn.microsoft.com/en-us/library/windows/desktop/ms724385(v=vs.85).aspx
//SM_TABLETPC(86) -
//Nonzero if the current operating system is the Windows XP Tablet PC edition
//or if the current operating system is Windows Vista or Windows 7 and the Tablet
//PC Input service is started; otherwise, 0. The SM_DIGITIZER setting indicates the
//type of digitizer input supported by a device running Windows 7 or Windows Server
//2008 R2. For more information, see Remarks.
if (GetSystemMetrics(SM_TABLETPC) != NULL)
return tablet;
//http://stackoverflow.com/a/4849574/6501682
SYSTEM_POWER_STATUS sps = {};
GetSystemPowerStatus(&sps);
if (sps.ACLineStatus == 255)
return desktop;
if (sps.ACLineStatus == 0 || sps.ACLineStatus == 1)
return laptop;
return DeviceTypes::unknown;
}
*/

bool tools::system::is_x64()
{
	SYSTEM_INFO si;
	GetNativeSystemInfo(&si);
	return ((si.wProcessorArchitecture & PROCESSOR_ARCHITECTURE_IA64) || (si.wProcessorArchitecture & PROCESSOR_ARCHITECTURE_AMD64));
}

std::list<std::wstring> tools::system::users()
{
	return network::users();
}

std::list<std::wstring> tools::system::groups()
{
	return network::groups();
}

std::list<std::wstring> tools::system::group_get_members(const std::wstring & group)
{
	return network::group_get_members(group);
}

std::wstring tools::system::get_sid_from_username(const std::wstring & username)
{
	return network::get_sid_from_username(username);
}

std::wstring tools::system::get_username_from_sid(const std::wstring & sid)
{
	return network::get_username_from_sid(sid);
}

std::wstring tools::system::get_domain_from_sid(const std::wstring & sid)
{
	return network::get_domain_from_sid(sid);
}

tools::network::domainuseraccount tools::system::get_domain_user_from_sid(const std::wstring & sid)
{
	return network::get_domain_user_from_sid(sid);
}

std::wstring tools::system::get_user_directory(const std::wstring & user)
{
	return get_user_sid_directory(get_sid_from_username(user));
}

std::wstring tools::system::get_user_sid_directory(const std::wstring & sid)
{
	std::wstring key_name = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\";
	key_name += sid;
	HKEY hKey;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, key_name.c_str(), 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
		DWORD dwLen = NULL, dwType;
		std::wstring value;
		if (::RegQueryValueEx(hKey, L"ProfileImagePath", nullptr, &dwType, nullptr, &dwLen) == ERROR_SUCCESS) {
			if (dwType != REG_EXPAND_SZ) {
				::RegCloseKey(hKey);
				return L"";
			}
			value.resize(dwLen / sizeof(wchar_t));
			if (::RegQueryValueEx(hKey, L"ProfileImagePath", nullptr, &dwType, (LPBYTE)&value[0], &dwLen) == ERROR_SUCCESS) {
				::RegCloseKey(hKey);
				return tools::expand_environment_strings(value) + L"\\"; //because it might be something like %SystemDrive%\Users
			}
		}
		RegCloseKey(hKey);
	}
	return L"";
}

#pragma endregion

#pragma region tools::user

std::wstring tools::user::username()
{
	wchar_t username[UNLEN + 1];
	DWORD dwLen = sizeof(username) / sizeof(wchar_t);
	if (!GetUserName(&username[0], &dwLen))
		return L"";
	return username;
}

std::wstring tools::user::language()
{
	wchar_t locale[LOCALE_NAME_MAX_LENGTH];
	if (GetUserDefaultLocaleName(locale, sizeof(locale) / sizeof(wchar_t)) == 0)
		return L"";
	return locale;	
}

LANGID tools::user::langid()
{
	return GetUserDefaultUILanguage(); //there's also GetThreadUILanguage() to get the langid of the thread.
}

std::wstring tools::user::lng_country(const std::wstring & lng)
{
	//LOCALE_SENGCOUNTRY is deprecated for Windows 7 & above, instead you should use LOCALE_SENGLISHCOUNTRYNAME; however you do not need to perform any checks for the os as they both define the same value.
	int size = GetLocaleInfoEx(lng.c_str(), LOCALE_SENGLISHCOUNTRYNAME, nullptr, NULL);
	std::wstring ws;
	ws.resize(size);
	if (GetLocaleInfoEx(lng.c_str(), LOCALE_SENGLISHCOUNTRYNAME, &ws[0], size) == 0)
		return L"";
	return ws;
}

std::wstring tools::user::lng_name(const std::wstring & lng)
{
	int size = GetLocaleInfoEx(lng.c_str(), LOCALE_SENGLISHDISPLAYNAME, nullptr, NULL);
	std::wstring ws;
	ws.resize(size);
	if (GetLocaleInfoEx(lng.c_str(), LOCALE_SENGLISHDISPLAYNAME, &ws[0], size) == 0)
		return L"";
	return ws;
}

struct sAccountPictureFile {
	std::wstring filename;
	ULONGLONG ullLastAccess;
};

std::list<sAccountPictureFile> win8_get_user_profile_picture_accountpicturems_files(const std::wstring& username)
{
	auto dir = tools::system::get_user_directory(username);
	if (dir.empty())
		return std::list<sAccountPictureFile>();
	dir += L"\\AppData\\Roaming\\Microsoft\\Windows\\AccountPictures\\";
	std::wstring search = dir + L"*.accountpicture-ms";
	WIN32_FIND_DATA fnd;
	HANDLE hFind = FindFirstFile(search.c_str(), &fnd);
	if (hFind == INVALID_HANDLE_VALUE)
		return std::list<sAccountPictureFile>();
	std::list<sAccountPictureFile> files;
	do {
		files.push_back({ dir + fnd.cFileName, *PULONGLONG(&fnd.ftLastAccessTime.dwLowDateTime) });
	} while (FindNextFile(hFind, &fnd));
	::FindClose(hFind);
	return files;
}

//to-do: maybe make a security wrapper
bool write_my_key_dacl(HKEY hKey)
{
	SECURITY_DESCRIPTOR sd;
	if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
		return false;
	PACL pOldACL;
	if (ERROR_SUCCESS != GetSecurityInfo(hKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, nullptr, nullptr, &pOldACL, nullptr, nullptr))
		return false;

	SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
	PSID pSIDAdmin = NULL;
	if (!AllocateAndInitializeSid(&SIDAuthNT, 2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&pSIDAdmin)) {
		LocalFree(pOldACL);
		return false;
	}

	EXPLICIT_ACCESS ea[1];
	ea[0].grfAccessPermissions = KEY_READ | WRITE_DAC;
	ea[0].grfAccessMode = SET_ACCESS;
	ea[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT; //NO_INHERITANCE
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[0].Trustee.ptstrName = (LPTSTR)pSIDAdmin;
	PACL pACL;
	if (SetEntriesInAcl(1, ea, pOldACL, &pACL) != ERROR_SUCCESS) {
		LocalFree(pOldACL);
		FreeSid(pSIDAdmin);
		return false;
	}
	if (!SetSecurityDescriptorDacl(&sd, TRUE, pACL, FALSE))
	{
		LocalFree(pOldACL);
		LocalFree(pACL);
		FreeSid(pSIDAdmin);
		return false;
	}
	//SetSecurityInfo()
	HRESULT r = RegSetKeySecurity(hKey, DACL_SECURITY_INFORMATION, &sd);
	LocalFree(pOldACL);
	LocalFree(pACL);
	FreeSid(pSIDAdmin);
	return r == ERROR_SUCCESS;
}

bool read_profile_pic_file(const std::wstring& filename, std::vector<BYTE>& data)
{
	HANDLE hFile = CreateFile(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;
	DWORD file_size = ::GetFileSize(hFile, nullptr);
	if (file_size > 1 * 1024 * 1024) { //or maybe limit to 256 Kib, depends...
		::CloseHandle(hFile);
		return false;
	}
	data.resize(file_size);
	DWORD dwRead;
	if (!::ReadFile(hFile, &data[0], file_size, &dwRead, nullptr)) {
		data.clear();
		::CloseHandle(hFile);
		return false;
	}
	::CloseHandle(hFile);
	return true;
}


std::vector<BYTE> tools::user::get_profile_picture(const std::wstring & username, int n)
{
	/*
	<Windows 7>

	<windows 8, Windows 8.1, Windows 10>
	first method is reading the files from registry:
	HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AccountPicture\Users\S-1-5-21-2471172580-176785103-431551346-1001
	Image192 = C:\Users\Public\AccountPictures\S-1-5-21-2471172580-176785103-431551346-1001\{BA2D8C13-42B4-4B41-87C3-16940F056B85}-Image192.jpg
	Image240
	Image32
	Image40
	Image448
	Image48
	Image96
	they all contain a jpg image
	the second method is extracting the image from the .accountpicture-ms file
	which is located in C:\Users\Greed\AppData\Roaming\Microsoft\Windows\AccountPictures
	note: they will keep the old profile images you set in that folder too, so we need to check the last access date to get the latest one.
	//http://www.aminedries.com/blog/working-with-windows-8-user-pictures-accountpicture-ms/
	//https://en.wikipedia.org/wiki/JPEG_File_Interchange_Format
	*/
	if (IsWindows8OrGreater()) {
		/*
		auto files = win8_get_user_profile_picture_accountpicturems_files(username);
		WString filename;
		ULONGLONG ullLast = NULL;
		for (auto& file : files) {
		if (file.ullLastAccess > ullLast)
		ullLast = file.ullLastAccess;
		}
		for (auto& file : files) {
		if (file.ullLastAccess == ullLast) {
		filename = file.filename;
		break;
		}
		}
		if (filename.empty())
		return false;
		HANDLE hFile = ::CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (hFile == INVALID_HANDLE_VALUE)
		return false;
		DWORD file_size = ::GetFileSize(hFile, nullptr);
		if (file_size > 2 * 1024 * 1024) {
		::CloseHandle(hFile);
		return false;
		}
		std::unique_ptr<BYTE[]> tmp(new BYTE[file_size]);
		DWORD dwRead;
		if (!::ReadFile(hFile, tmp.get(), file_size, &dwRead, nullptr)) {
		::CloseHandle(hFile);
		return false;
		}
		if (filename.find(L".accountpicture-ms") != String::npos) {
		String s;
		s.setexternalbuffer((PCHAR)tmp.get(), dwRead);
		size_t pos, offset = whichone == 0 ? 0 : 100;
		if ((pos = s.find("JFIF", offset)) != String::npos) {
		pos -= 6;
		String EOI("\xFF\xD9", 2);
		auto end = s.find(EOI, pos);
		if (end != String::npos) {
		//0 1 2 3 4 5
		//l o l a b c
		//pos = 3, end = 4
		//(4 + 2) - 3 = 3, we get abc
		size_t len = (end + 2) - pos;
		file = std::unique_ptr<BYTE>(new BYTE[len]);
		memcpy_s(file.get(), len, &tmp[pos], len);
		size = len;
		}
		}

		}
		else {
		file.reset(tmp.release());
		size = dwRead;
		}
		::CloseHandle(hFile);
		return file.get() != nullptr;
		*/
		Registry key;
		auto user_sid = tools::system::get_sid_from_username(username);
		if (user_sid.empty())
			return std::vector<BYTE>();
		if (key.open(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AccountPicture\\Users\\" + user_sid, KEY_QUERY_VALUE | KEY_WOW64_64KEY)) {
			std::wstring filename;
			DWORD dwLen;
			if (key.query_value_length(L"Image96", &dwLen)) {
				filename.resize(dwLen / sizeof(wchar_t));
				if (!key.query_value(L"Image96", nullptr, (PBYTE)&filename[0], &dwLen))
					filename = L"";
			}
			//RegGetValue(key.get(), nullptr, L"Image96",  )
			if (filename.empty())
				return std::vector<BYTE>();
			std::vector<BYTE> data;
			if (read_profile_pic_file(filename, data))
				return data;
		}
		else
			return std::vector<BYTE>();
	}
	else if (IsWindowsVistaOrGreater()/*IsWindows7OrGreater()*/) {
		Registry key;
		if (key.open(L"HKEY_LOCAL_MACHINE\\SAM", READ_CONTROL | WRITE_DAC)) {
			write_my_key_dacl(key.key());
		}
		if (key.open(L"HKEY_LOCAL_MACHINE\\SAM\\SAM", READ_CONTROL | WRITE_DAC)) {
			write_my_key_dacl(key.key());
		}
		if (key.open(L"HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\Names\\" + username, KEY_READ)) {
			DWORD id;
			if (!key.query_value_type(L"", &id))
				return std::vector<BYTE>();
			wchar_t buf[9];
			swprintf_s(buf, L"%08X", id);
			if (key.open(L"HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\" + std::wstring(buf), KEY_READ)) {
				DWORD type;
				if (!key.query_value_type(L"UserTile", &type))
					return std::vector<BYTE>();
				auto data = key.query_value(L"UserTile");
					return std::vector<BYTE>();
				if (data.size() < 12 + sizeof(DWORD))
					return std::vector<BYTE>();
				PDWORD payload_len = reinterpret_cast<PDWORD>(&data[12]);
				if (*payload_len + 12 + sizeof(DWORD) > data.size())
					return std::vector<BYTE>();
				//file = std::unique_ptr<BYTE>(new BYTE[size]);
				std::vector<BYTE> r;
				r.resize(*payload_len);
				memcpy_s(r.data(), r.size(), &data.data()[12 + sizeof(DWORD)], *payload_len);
				return data;
			}
			else
				return std::vector<BYTE>();
		}
		else {
			std::wstring filename = L"%temp%\\"; //too lazy to get it for the specific user, so we're just going to use expand_enviroment_strings()
			filename += username + L".bmp";
			filename = expand_environment_strings(filename);
			std::vector<BYTE> data;
			if (read_profile_pic_file(filename, data))
				return data;
		}
	}
	return std::vector<BYTE>();
}

std::wstring tools::user::temp_directory()
{
	std::wstring temp_dir;
	temp_dir.resize(MAX_PATH);
	if (GetTempPath(MAX_PATH, &temp_dir[0]) != 0)
		return temp_dir;
	return L"";
}

bool tools::user::isLocalAdmin()
{
	HANDLE hToken = INVALID_HANDLE_VALUE;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
		return false;
	DWORD dwSizeToken = NULL;
	GetTokenInformation(hToken, TokenGroups, NULL, dwSizeToken, &dwSizeToken);
	std::unique_ptr < TOKEN_GROUPS > pGroupInfo((TOKEN_GROUPS *)new BYTE[dwSizeToken]);
	if (GetTokenInformation(hToken, TokenGroups, pGroupInfo.get(), dwSizeToken, &dwSizeToken)) {
		bool bFound = false;
		for (UINT i = 0; i < pGroupInfo->GroupCount && !bFound; i++) {
			wchar_t name[256], domain[256];
			SID_NAME_USE SidType;
			DWORD n = sizeof(name) / sizeof(wchar_t), n2 = sizeof(domain) / sizeof(wchar_t);
			if (LookupAccountSid(NULL, pGroupInfo->Groups[i].Sid, name, &n, domain, &n2, &SidType)) {
				if (wcscmp(L"Administrators", name) == 0)
					bFound = true;
			}
		}
		::CloseHandle(hToken);
		return bFound;
	}
	return false;
}

#pragma endregion

#pragma region tools::file
namespace tools {
	namespace file {

		HICON icon(const std::wstring& filename)
		{
			SHFILEINFO FileInfo = {};
			SHGetFileInfo(filename.c_str(), 0, &FileInfo, sizeof(FileInfo), SHGFI_ICON | SHGFI_LARGEICON);
			return FileInfo.hIcon; //remember to destroy the icon when finished by calling DestroyIcon();
		}

		std::wstring description(const std::wstring& filename)
		{
			DWORD dwHandle;
			DWORD dwSize = GetFileVersionInfoSize(filename.c_str(), &dwHandle);
			if (dwSize == NULL)
				return L"";
			std::unique_ptr<BYTE[]> pBlock(new BYTE[dwSize]);
			if (!GetFileVersionInfo(filename.c_str(), dwHandle, dwSize, pBlock.get()))
				return L"";
			struct LANGANDCODEPAGE {
				WORD wLanguage;
				WORD wCodePage;
			} *lpTranslate;
			UINT cbTranslate;
			if (!VerQueryValue(pBlock.get(),
				TEXT("\\VarFileInfo\\Translation"),
				(LPVOID*)&lpTranslate,
				&cbTranslate))
				return L"";
			wchar_t SubBlock[64]; //exact should be 41
			swprintf_s(SubBlock, TEXT("\\StringFileInfo\\%04x%04x\\FileDescription"), lpTranslate->wLanguage, lpTranslate->wCodePage);
			/*
			// Read the file description for each language and code page.
			for (UINT i = 0; i < (cbTranslate / sizeof(struct LANGANDCODEPAGE)); i++) {
			swprintf_s(SubBlock, TEXT("\\StringFileInfo\\%04x%04x\\FileDescription"), lpTranslate[i].wLanguage, lpTranslate[i].wCodePage);
			}
			*/
			// Retrieve file description for language and code page "i". 
			UINT dwBytes;
			LPVOID lpBuffer;
			if (VerQueryValue(pBlock.get(),
				SubBlock,
				&lpBuffer,
				&dwBytes)) {
				return std::wstring((wchar_t*)lpBuffer); //, dwBytes / sizeof(wchar_t)
			}
			return L"";
		}

		std::wstring version(const std::wstring& filename)
		{
			DWORD dwHandle;
			DWORD dwSize = GetFileVersionInfoSize(filename.c_str(), &dwHandle);
			if (dwSize == NULL)
				return L"";
			std::unique_ptr<BYTE[]> pBlock(new BYTE[dwSize]);
			if (!GetFileVersionInfo(filename.c_str(), dwHandle, dwSize, pBlock.get()))
				return L"";
			LPVOID lpBuffer;
			UINT size;
			if (VerQueryValueW(pBlock.get(), L"\\", &lpBuffer, &size))
			{
				VS_FIXEDFILEINFO *verInfo = (VS_FIXEDFILEINFO *)lpBuffer;
				if (verInfo->dwSignature == 0xFEEF04BD) {
					wchar_t ver[24];
					swprintf_s(ver, L"%d.%d.%d.%d",
						(verInfo->dwFileVersionMS >> 16) & 0xffff,
						(verInfo->dwFileVersionMS >> 0) & 0xffff,
						(verInfo->dwFileVersionLS >> 16) & 0xffff,
						(verInfo->dwFileVersionLS >> 0) & 0xffff);
					return ver;
				}
			}
			return L"";
		}

		size_t binary_string_search(const std::string& s, const std::string& f)
		{
			if (f.length() == 0)
				return std::string::npos;
			auto last = (s.end() - (f.length() - 1));
			std::string::const_iterator n = s.begin();
			while ((n = std::find_if(n, last, [&](char v) -> bool { return f.at(0) == v; })) != last) {
				if (std::equal(n, n + f.length(), f.begin(), f.end()))
					return std::distance(s.begin(), n);
				n++;
			}
			return std::string::npos;
		}

		bool patch(const std::wstring & filename, const std::string & find, const std::string & replace)
		{
			HANDLE hFile = CreateFile(filename.c_str(), GENERIC_READ | GENERIC_WRITE, NULL, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
			if (hFile == INVALID_HANDLE_VALUE)
				return false;
			LARGE_INTEGER fs;
			if (!GetFileSizeEx(hFile, &fs)) {
				::CloseHandle(hFile);
				return false;
			}
			std::string s;
			s.resize(static_cast<size_t>(fs.QuadPart));
			DWORD dwRead;
			::ReadFile(hFile, &s[0], s.length(), &dwRead, nullptr);
			bool replaced = false;
			size_t n;
			if ((n = binary_string_search(s, find)) != std::string::npos) {
				LARGE_INTEGER offset;
				offset.QuadPart = n;
				::SetFilePointerEx(hFile, offset, nullptr, FILE_BEGIN);
				DWORD dwWritten;
				::WriteFile(hFile, replace.c_str(), replace.length() + 1, &dwWritten, nullptr);
				replaced = true;
			}
			::CloseHandle(hFile);
			return replaced;
		}

	}
}

#pragma endregion

#pragma region tools::image
int GetEncoderClsid(const std::wstring& format, CLSID* pClsid)
{
	UINT  num = 0;          // number of image encoders
	UINT  size = 0;         // size of the image encoder array in bytes

	GetImageEncodersSize(&num, &size);
	if (size == 0)
		return -1;  // Failure
	std::unique_ptr<BYTE> tmp(new BYTE[size]);
	if (!tmp)
		return -1;  // Failure
	ImageCodecInfo* pImageCodecInfo = reinterpret_cast<ImageCodecInfo*>(tmp.get());
	GetImageEncoders(num, size, pImageCodecInfo);
	for (UINT j = 0; j < num; ++j) {
		if (format == pImageCodecInfo[j].MimeType)
		{
			*pClsid = pImageCodecInfo[j].Clsid;
			return j;
		}
	}
	return -1;
}


std::vector<BYTE> tools::image::bmp_to_png(Gdiplus::Bitmap * bmp, ULONG uQuality)
{
	CLSID imageCLSID;
	EncoderParameters encoderParams;
	encoderParams.Count = 1;
	encoderParams.Parameter[0].NumberOfValues = 1;
	encoderParams.Parameter[0].Guid = EncoderQuality;
	
	encoderParams.Parameter[0].Type = EncoderParameterValueTypeLong;
	encoderParams.Parameter[0].Value = &uQuality;

	if (GetEncoderClsid(L"image/png", &imageCLSID) < 0)
		return std::vector<BYTE>();
	IStream *pStream = NULL;
	if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) == S_OK)
	{
		if (bmp->Save(pStream, &imageCLSID, uQuality > 0 ? &encoderParams : nullptr) == Ok) {
			ULARGE_INTEGER ulnSize;
			LARGE_INTEGER lnOffset;
			lnOffset.QuadPart = 0;
			if (pStream->Seek(lnOffset, STREAM_SEEK_END, &ulnSize) == S_OK)
				if (pStream->Seek(lnOffset, STREAM_SEEK_SET, NULL) == S_OK)
				{
					std::vector<BYTE> tmp;
					tmp.resize(static_cast<size_t>(ulnSize.QuadPart));
					ULONG ulBytesRead;
					if (pStream->Read(&tmp[0], tmp.size(), &ulBytesRead) == Ok) {
						pStream->Release();
						return tmp;
					}
				}
		}
		pStream->Release();
	}
	return std::vector<BYTE>();
}

#pragma endregion

#pragma region tools::screen

std::vector<BYTE> tools::screen::capture(int iWidth, int iHeight, ULONG quality)
{
	HDC hScreenDC = GetDC(NULL); //CreateDC(L"DISPLAY", NULL, NULL, NULL);
	if (hScreenDC == NULL)
		return std::vector<BYTE>();
	HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
	SetStretchBltMode(hMemoryDC, STRETCH_DELETESCANS);

	int x1, y1, x2, y2, w, h, nBPP = GetDeviceCaps(hScreenDC, BITSPIXEL);

	// get screen dimensions
	x1 = GetSystemMetrics(SM_XVIRTUALSCREEN);
	y1 = GetSystemMetrics(SM_YVIRTUALSCREEN);
	x2 = GetSystemMetrics(SM_CXVIRTUALSCREEN);
	y2 = GetSystemMetrics(SM_CYVIRTUALSCREEN);
	w = x2 - x1;
	h = y2 - y1;

	HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, iWidth, iHeight);
	HGDIOBJ old_obj = SelectObject(hMemoryDC, hBitmap);
	StretchBlt(hMemoryDC, 0, 0, iWidth, iHeight, hScreenDC, x1, y1, w, h, CAPTUREBLT | SRCCOPY);
	Bitmap *pScreenShot = new Bitmap(hBitmap, (HPALETTE)NULL);
	auto data = image::bmp_to_png(pScreenShot, quality);
	SelectObject(hMemoryDC, old_obj);
	DeleteDC(hMemoryDC);
	ReleaseDC(NULL, hScreenDC);
	DeleteObject(hBitmap);
	return data;
}

#pragma endregion

#pragma region tools::hicon


//ICON FORMAT: https://msdn.microsoft.com/en-us/library/ms997538.aspx / https://en.wikipedia.org/wiki/ICO_(file_format)
//pilfered code from: http://stackoverflow.com/a/15329195

typedef struct
{
	WORD idReserved; // must be 0
	WORD idType; // 1 = ICON, 2 = CURSOR
	WORD idCount; // number of images (and ICONDIRs)
} ICONHEADER;

typedef struct
{
	BYTE bWidth;
	BYTE bHeight;
	BYTE bColorCount;
	BYTE bReserved;
	WORD wPlanes; // for cursors, this field = wXHotSpot
	WORD wBitCount; // for cursors, this field = wYHotSpot
	DWORD dwBytesInRes;
	DWORD dwImageOffset; // file-offset to the start of ICONIMAGE
} ICONDIR;

UINT num_bitmap_bytes(BITMAP *pBitmap)
{
	int nWidthBytes = pBitmap->bmWidthBytes;
	if (nWidthBytes & 3)
		nWidthBytes = (nWidthBytes + 4) & ~3;
	return nWidthBytes * pBitmap->bmHeight;
}

BOOL GetIconBitmapInfo(HICON hIcon, ICONINFO *pIconInfo, BITMAP *pbmpColor, BITMAP *pbmpMask)
{
	if (!GetIconInfo(hIcon, pIconInfo))
		return FALSE;
	if (!GetObject(pIconInfo->hbmColor, sizeof(BITMAP), pbmpColor)) {
		DeleteObject(pIconInfo->hbmColor);
		DeleteObject(pIconInfo->hbmMask);
		return FALSE;
	}
	if (!GetObject(pIconInfo->hbmMask, sizeof(BITMAP), pbmpMask)) {
		DeleteObject(pIconInfo->hbmColor);
		DeleteObject(pIconInfo->hbmMask);
		return FALSE;
	}
	return TRUE;
}
DWORD GetIconSize(HICON hIcon)
{
	if (!hIcon)
		return NULL;
	DWORD dwBytes = 0;
	BITMAP bmpColor, bmpMask;
	ICONINFO iconInfo;
	if (!GetIconBitmapInfo(hIcon, &iconInfo, &bmpColor, &bmpMask))
		return NULL;
	dwBytes = num_bitmap_bytes(&bmpColor) + num_bitmap_bytes(&bmpMask);
	if (bmpColor.bmBitsPixel < 24) {
		//for RGB color table(BITMAPINFO::bmiColors) that comes after the BITMAPINFOHEADER
		dwBytes += sizeof(RGBQUAD) * (int)(1 << bmpColor.bmBitsPixel);
	}
	DeleteObject(iconInfo.hbmColor);
	DeleteObject(iconInfo.hbmMask);
	return sizeof(ICONHEADER) + sizeof(ICONDIR) + sizeof(BITMAPINFO::bmiHeader)/*BITMAPINFOHEADER*/ + dwBytes;
}

std::vector<BYTE> tools::hicon::extract_to_bmp(HICON hIcon)
{
	if (hIcon == NULL)
		return std::vector<BYTE>();
	DWORD dwSize = GetIconSize(hIcon);
	std::vector<BYTE> vec;
	vec.resize(dwSize);
	//icon header
	ICONHEADER* icoheader = reinterpret_cast<ICONHEADER*>(vec.data());
	icoheader->idCount = 1;
	icoheader->idReserved = NULL;
	icoheader->idType = 1; //type 1 = icon, type 2 = cursor.
	ICONDIR* pIconDir = reinterpret_cast<ICONDIR*>(vec.data() + sizeof(ICONHEADER));
	ICONINFO iconInfo;
	BITMAP bmpColor, bmpMask;
	UINT nImageBytes, nColorCount;

	if (!GetIconBitmapInfo(hIcon, &iconInfo, &bmpColor, &bmpMask))
		return std::vector<BYTE>();
	nImageBytes = num_bitmap_bytes(&bmpColor) + num_bitmap_bytes(&bmpMask);

	if (bmpColor.bmBitsPixel >= 8)
		nColorCount = 0;
	else
		nColorCount = 1 << (bmpColor.bmBitsPixel * bmpColor.bmPlanes);

	pIconDir->bWidth = (BYTE)bmpColor.bmWidth;
	pIconDir->bHeight = (BYTE)bmpColor.bmHeight;
	pIconDir->bColorCount = nColorCount;
	pIconDir->bReserved = 0;
	pIconDir->wPlanes = bmpColor.bmPlanes;
	pIconDir->wBitCount = bmpColor.bmBitsPixel;
	pIconDir->dwBytesInRes = sizeof(BITMAPINFOHEADER) + nImageBytes;
	pIconDir->dwImageOffset = sizeof(ICONHEADER) + sizeof(ICONDIR);
	HDC dc = GetDC(NULL);
	BITMAPINFO bmInfo = {};
	bmInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	bmInfo.bmiHeader.biBitCount = 0;
	if (!GetDIBits(dc, iconInfo.hbmColor, 0, 0, nullptr, &bmInfo, DIB_RGB_COLORS) ||
		bmInfo.bmiHeader.biSizeImage == 0)
	{
		DeleteObject(iconInfo.hbmColor);
		DeleteObject(iconInfo.hbmMask);
		ReleaseDC(NULL, dc);
		return std::vector<BYTE>();
	}
	//bmInfo.bmiHeader.biSizeImage == num_bitmap_bytes(&bmpColor)
	PBITMAPINFO pBMInfo = reinterpret_cast<PBITMAPINFO>(vec.data() + sizeof(ICONHEADER) + sizeof(ICONDIR));
	memcpy(pBMInfo, &bmInfo, sizeof(BITMAPINFOHEADER));
	pBMInfo->bmiHeader.biBitCount = bmpColor.bmBitsPixel;
	pBMInfo->bmiHeader.biCompression = BI_RGB;
	PBYTE bits = static_cast<PBYTE>(vec.data() + sizeof(ICONHEADER) + sizeof(ICONDIR) + sizeof(BITMAPINFOHEADER));
	if (bmpColor.bmBitsPixel < 24)
		bits += sizeof(RGBQUAD) * (int)(1 << bmpColor.bmBitsPixel);
	if (!GetDIBits(dc, iconInfo.hbmColor, 0, bmInfo.bmiHeader.biHeight, bits, pBMInfo, DIB_RGB_COLORS))
	{
		DeleteObject(iconInfo.hbmColor);
		DeleteObject(iconInfo.hbmMask);
		ReleaseDC(NULL, dc);
		return std::vector<BYTE>();
	}
	PBYTE maskBits = bits + pBMInfo->bmiHeader.biSizeImage;
	BITMAPINFO maskInfo = {};
	maskInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	maskInfo.bmiHeader.biBitCount = 0;
	if (!GetDIBits(dc, iconInfo.hbmMask, 0, 0, nullptr, &maskInfo, DIB_RGB_COLORS) ||
		maskInfo.bmiHeader.biBitCount != 1)
	{
		DeleteObject(iconInfo.hbmColor);
		DeleteObject(iconInfo.hbmMask);
		ReleaseDC(NULL, dc);
		return std::vector<BYTE>();
	}
	BITMAPINFO* pMaskInfo = (BITMAPINFO*)new BYTE[sizeof(BITMAPINFO) + 2 * sizeof(RGBQUAD)];
	memcpy(pMaskInfo, &maskInfo, sizeof(maskInfo));
	if (!GetDIBits(dc, iconInfo.hbmMask, 0, maskInfo.bmiHeader.biHeight, maskBits, pMaskInfo, DIB_RGB_COLORS))
	{
		delete[] pMaskInfo;
		DeleteObject(iconInfo.hbmColor);
		DeleteObject(iconInfo.hbmMask);
		ReleaseDC(NULL, dc);
		return std::vector<BYTE>();
	}
	delete[] pMaskInfo;
	DeleteObject(iconInfo.hbmColor);
	DeleteObject(iconInfo.hbmMask);
	ReleaseDC(NULL, dc);
	return vec;
}

#pragma endregion

#pragma region tools::window

HICON tools::window::icon(HWND hWnd)
{
	//for modern apps:
	//http://stackoverflow.com/questions/32122679/getting-icon-of-modern-windows-app-from-a-desktop-application/36559301

	HICON hIcon = (HICON)GetClassLongPtr(hWnd, GCL_HICON);
	if (hIcon == NULL)
		hIcon = reinterpret_cast<HICON>(::SendMessage(hWnd, WM_GETICON, ICON_BIG, 0));
	if (hIcon == NULL)
		hIcon = reinterpret_cast<HICON>(::SendMessage(hWnd, WM_GETICON, ICON_SMALL, 0)); //ICON_SMALL2
																						 //if (hIcon == NULL)
																						 //hIcon = (HICON)LoadImage(0, IDI_APPLICATION, IMAGE_ICON, 0, 0, LR_SHARED);//LoadIcon(NULL, IDI_APPLICATION);
	return hIcon;
}

std::wstring tools::window::text(HWND hWnd)
{
	std::wstring s;
	s.resize(GetWindowTextLength(hWnd));
	if (GetWindowText(hWnd, &s[0], s.length() + 1) == NULL)
		return L"";
	return s;
}

#pragma endregion

#pragma region tools::network

std::list<std::wstring> tools::network::users(const std::wstring & server)
{
	PNET_DISPLAY_USER p, pBuff;
	DWORD res, i = 0, dwRec;
	std::list<std::wstring> users;
	do {
		res = NetQueryDisplayInformation(server.c_str(), 1, i, 1000, MAX_PREFERRED_LENGTH, &dwRec, (PVOID*)&pBuff); //or use NetUserEnum
		if (res == ERROR_MORE_DATA || res == NERR_Success) {
			p = pBuff;
			for (; dwRec > 0; dwRec--, p++) {
				users.push_back(p->usri1_name);
				i = p->usri1_next_index;
			}
			NetApiBufferFree(pBuff);
		}
	} while (res == ERROR_MORE_DATA);

	return users;
}

std::list<std::wstring> tools::network::groups(const std::wstring & server)
{
	PLOCALGROUP_INFO_0 p, pBuff;
	DWORD res, i = 0, dwRec, dwTotal;
	DWORD dwResumeHandle = 0;
	std::list<std::wstring> groups;
	do {
		res = NetLocalGroupEnum(server.c_str(), 0, (LPBYTE*)&pBuff, MAX_PREFERRED_LENGTH, &dwRec, &dwTotal, &dwResumeHandle);
		if (res == ERROR_MORE_DATA || res == NERR_Success) {
			p = pBuff;
			for (; dwRec > 0 && p; dwRec--, p++) {
				groups.push_back(p->lgrpi0_name);
			}
			NetApiBufferFree(pBuff);
		}
	} while (res == ERROR_MORE_DATA);

	return groups;
}

std::list<std::wstring> tools::network::group_get_members(const std::wstring & group, const std::wstring & server)
{
	PLOCALGROUP_MEMBERS_INFO_1 p, pBuff;
	DWORD res, i = 0, dwRec, dwTotal;
	DWORD dwResumeHandle = 0;
	std::list<std::wstring> members;
	do {
		res = NetLocalGroupGetMembers(server.c_str(), group.c_str(), 1, (LPBYTE*)&pBuff, MAX_PREFERRED_LENGTH, &dwRec, &dwTotal, &dwResumeHandle);
		if (res == ERROR_MORE_DATA || res == NERR_Success) {
			p = pBuff;
			for (; dwRec > 0 && p; dwRec--, p++) {
				members.push_back(p->lgrmi1_name);
			}
			NetApiBufferFree(pBuff);
		}
	} while (res == ERROR_MORE_DATA);

	return members;
}

std::wstring tools::network::get_sid_from_username(const std::wstring & username, const std::wstring & server)
{
	/*
	PUSER_INFO_23 info;
	switch (NetUserGetInfo(server, username, 23, (LPBYTE*)&info)) {
	case NERR_Success:
	{
	LPWSTR s;
	if (ConvertSidToStringSid(info->usri23_user_sid, &s))
	return s;
	return L"";
	}
	break;
	default:
	return L"";
	}
	*/
	SID_NAME_USE SidType;
	std::unique_ptr<wchar_t> domain;
	DWORD cbSid = 32, dwDomainLen = 32;
	for (;;) {
		std::unique_ptr<BYTE> mem(new BYTE[cbSid]);
		PSID Sid = (PSID)mem.get();
		ZeroMemory(Sid, cbSid);
		domain = std::unique_ptr<wchar_t>(new wchar_t[dwDomainLen]);
		if (LookupAccountName(server.c_str(), username.c_str(), Sid, &cbSid, domain.get(), &dwDomainLen, &SidType)) {
			if (!IsValidSid(Sid))
				return std::wstring();
			LPWSTR s;
			if (ConvertSidToStringSid(Sid, &s)) {
				std::wstring result = s;
				LocalFree(s);
				return result;
			}
			else
				break;
		}
		else if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			break;
		FreeSid(Sid);
	}
	return L"";
}

std::wstring tools::network::get_username_from_sid(const std::wstring & sid, const std::wstring & server)
{
	PSID Sid;
	if (!ConvertStringSidToSid(sid.c_str(), &Sid))
		return L"";
	SID_NAME_USE SidType;
#define MAX_NAME 256
	wchar_t lpName[MAX_NAME], lpDomain[MAX_NAME];
	DWORD dwName = sizeof(lpName) / sizeof(wchar_t), dwDomain = sizeof(lpDomain) / sizeof(wchar_t);
	if (LookupAccountSid(server.c_str(), Sid, lpName, &dwName, lpDomain, &dwDomain, &SidType)) {
		LocalFree(Sid);
		return lpName;
	}
	//else if (GetLastError() == ERROR_NONE_MAPPED){} //mapping not available
	LocalFree(Sid);
	return std::wstring();
}

std::wstring tools::network::get_domain_from_sid(const std::wstring & sid, const std::wstring & server)
{
	PSID Sid;
	if (!ConvertStringSidToSid(sid.c_str(), &Sid))
		return L"";
	SID_NAME_USE SidType;
#define MAX_NAME 256
	wchar_t lpName[MAX_NAME], lpDomain[MAX_NAME];
	DWORD dwName = sizeof(lpName) / sizeof(wchar_t), dwDomain = sizeof(lpDomain) / sizeof(wchar_t);
	if (LookupAccountSid(server.c_str(), Sid, lpName, &dwName, lpDomain, &dwDomain, &SidType)) {
		LocalFree(Sid);
		return lpDomain;
	}
	LocalFree(Sid);
	return std::wstring();
}

tools::network::domainuseraccount tools::network::get_domain_user_from_sid(const std::wstring & sid, const std::wstring & server)
{
	PSID Sid;
	if (!ConvertStringSidToSid(sid.c_str(), &Sid))
		return{ L"", L"" };
	SID_NAME_USE SidType;
#define MAX_NAME 256
	wchar_t lpName[MAX_NAME], lpDomain[MAX_NAME];
	DWORD dwName = sizeof(lpName) / sizeof(wchar_t), dwDomain = sizeof(lpDomain) / sizeof(wchar_t);
	if (LookupAccountSid(server.c_str(), Sid, lpName, &dwName, lpDomain, &dwDomain, &SidType)) {
		LocalFree(Sid);
		return{ lpDomain, lpName };
	}
	LocalFree(Sid);
	return { L"", L"" };
}

#pragma endregion

#pragma region tools::clipboard

std::string tools::clipboard::get_clipboard_textA()
{
	if (!OpenClipboard(NULL))
		return "";
	HANDLE hData = GetClipboardData(CF_TEXT);
	if (hData == nullptr)
		return "";
	auto pszText = static_cast<char*>(GlobalLock(hData));
	if (pszText == nullptr)
		return "";
	std::string text(pszText);
	GlobalUnlock(hData);
	CloseClipboard();
	return text;
}

std::wstring tools::clipboard::get_clipboard_textW()
{
	if (!OpenClipboard(NULL))
		return L"";
	HANDLE hData = GetClipboardData(CF_UNICODETEXT);
	if (hData == nullptr)
		return L"";
	auto pszText = static_cast<wchar_t*>(GlobalLock(hData));
	if (pszText == nullptr)
		return L"";
	std::wstring text(pszText);
	GlobalUnlock(hData);
	CloseClipboard();
	return text;
}

#pragma endregion