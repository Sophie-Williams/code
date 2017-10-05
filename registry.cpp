#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <utility>
#include <string>
#include <list>
#include <vector>
#include "registry.h"
#include <exception>
#include <locale>
#include <codecvt>

static const wchar_t* wBaseKeys[] = { L"HKEY_LOCAL_MACHINE", L"HKEY_CURRENT_USER", L"HKEY_CLASSES_ROOT", L"HKEY_USERS", L"HKEY_CURRENT_CONFIG" };
static const char* BaseKeys[] = { "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "HKEY_CLASSES_ROOT", "HKEY_USERS", "HKEY_CURRENT_CONFIG" };
static const HKEY keys[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, HKEY_CLASSES_ROOT, HKEY_USERS, HKEY_CURRENT_CONFIG };

HKEY get_root_key(const std::string& key)
{
	for (int i = 0; i < _countof(keys); i++) {
		if (key.find(BaseKeys[i]) == 0)
			return keys[i];
	}
	return NULL;
}

HKEY get_root_key(const std::wstring& key)
{
	for (int i = 0; i < _countof(keys); i++) {
		if (key.find(wBaseKeys[i]) == 0)
			return keys[i];
	}
	return NULL;
}

Registry::Registry()
{
	hKey = NULL;
}

Registry::Registry(const std::wstring & key, DWORD samDesired) noexcept(false) :Registry()
{
	if (!open(key, samDesired))
		throw std::exception("Unable to open registry key.");
}

Registry::Registry(Registry && other):Registry()
{
	*this = std::move(other);
}

Registry::Registry(const Registry & other):Registry()
{
	*this = other;
}

Registry::~Registry()
{
	this->close();
}

void Registry::operator=(Registry && other)
{
	this->close();
	this->hKey = other.hKey;
	other.hKey = NULL;
}

void Registry::operator=(const Registry & other)
{
	//to-do: test
	this->close();
	HANDLE hDuplicate;
	if (DuplicateHandle(GetCurrentProcess(), other.hKey, GetCurrentProcess(), (LPHANDLE)&hDuplicate, NULL, FALSE, DUPLICATE_SAME_ACCESS))
		this->hKey = static_cast<HKEY>(hDuplicate);
}

bool Registry::open(const std::string& key, DWORD samDesired)
{
	if (opened())
		close();
	if (key.find('\\') == std::string::npos)
		return false;
	auto hRoot = get_root_key(key);
	if (!hRoot)
		return false;
	return (RegOpenKeyExA(hRoot, &key[key.find(L'\\') + 1], 0, samDesired, &hKey) == ERROR_SUCCESS);
}

bool Registry::open(const std::wstring& key, DWORD samDesired)
{
	if (opened())
		close();
	if (key.find(L'\\') == std::wstring::npos)
		return false;
	auto hRoot = get_root_key(key);
	if (!hRoot)
		return false;
	return (RegOpenKeyExW(hRoot, &key[key.find(L'\\') + 1], 0, samDesired, &hKey) == ERROR_SUCCESS);
}

bool Registry::delete_key(const std::string & key, bool bx64view)
{
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	return Registry::delete_key(converter.from_bytes(key), bx64view);
}

bool Registry::delete_key(const std::wstring & key, bool bx64view)
{
	if (key.find(L'\\') == std::string::npos)
		return false;
	DWORD dwFlag = bx64view ? KEY_WOW64_64KEY : KEY_WOW64_32KEY;
	HKEY hKey;
	LSTATUS r;
	if ((r = RegOpenKeyEx(get_root_key(key), &key[key.find(L'\\') + 1], 0, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | dwFlag, &hKey)) == ERROR_SUCCESS) {
		DWORD dwNumSubKeys;
		if (RegQueryInfoKey(hKey, nullptr, nullptr, nullptr, &dwNumSubKeys, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
			for (DWORD i = 0; i < dwNumSubKeys; i++) {
				TCHAR achKey[MAX_KEY_LENGTH] = {};
				DWORD cbKey = MAX_KEY_LENGTH;
				//I keep it at index 0 at all times due to the fact that when the key is deleted, the next key takes it's index(so index always equals 0).
				if (RegEnumKeyEx(hKey, 0, achKey, &cbKey, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
					std::wstring k = key;
					if (key.rfind(L"\\") != 0)
						k += L"\\";
					if (!delete_key(k + achKey, bx64view))
						break;
				}
			}
		}
		::RegCloseKey(hKey);
		return RegDeleteKeyEx(get_root_key(key), &key[key.find(L'\\') + 1], dwFlag, 0) == ERROR_SUCCESS;
	}
	else
		return (r == ERROR_FILE_NOT_FOUND); //it will return ERROR_FILE_NOT_FOUND if the registry key does not exist.
}

bool Registry::set_value(const std::wstring & name, DWORD dwDataType, const BYTE * lpData, DWORD cbData)
{
	if (!hKey)
		return false;
	return RegSetValueEx(hKey, name.c_str(), NULL, dwDataType, lpData, cbData) == ERROR_SUCCESS;
}

bool Registry::delete_value(const std::wstring & name)
{
	if (!hKey)
		return false;
	return ::RegDeleteValue(hKey, name.c_str()) == ERROR_SUCCESS;
}

bool Registry::query_value(const std::wstring & name, PDWORD type, PBYTE buffer, PDWORD cbBuffer)
{
	if (!hKey)
		return false;
	return RegQueryValueEx(hKey, name.c_str(), nullptr, type, buffer, cbBuffer) == ERROR_SUCCESS; //might return ERROR_MORE_DATA
}

bool Registry::query_value_type(const std::wstring & value, PDWORD type)
{
	if (type)
		*type = NULL;
	if (!hKey)
		return false;
	return ERROR_SUCCESS == RegQueryValueEx(hKey, value.c_str(), nullptr, type, nullptr, nullptr);
}

bool Registry::query_value_length(const std::wstring & value, PDWORD len)
{
	if (len)
		*len = NULL;
	if (!hKey)
		return false;
	return ERROR_SUCCESS == RegQueryValueEx(hKey, value.c_str(), nullptr, nullptr, nullptr, len);
}

std::vector<BYTE> Registry::query_value(const std::wstring & name, PDWORD type)
{
	DWORD len;
	if (!query_value_length(name, &len))
		return std::vector<BYTE>();
	std::vector<BYTE> tmp;
	tmp.resize(len);
	if (!query_value(name, type, &tmp[0], &len))
		return std::vector<BYTE>();
	return tmp;
}


bool Registry::create_subkey(const std::wstring & key, bool * bNew)
{
	if (!hKey)
		return false;
	HKEY hSubKey;
	DWORD dwDisposition;
	if (RegCreateKeyEx(hKey, key.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_READ, nullptr, &hSubKey, &dwDisposition) == ERROR_SUCCESS) {
		RegCloseKey(hSubKey);
		if (bNew)
			*bNew = (dwDisposition == REG_CREATED_NEW_KEY);
		return true;
	}
	else
		return false;
}

bool Registry::create_key(const std::wstring & key, DWORD samDesired, bool * bNew)
{
	if (opened())
		close();
	DWORD dwDisposition;
	if (RegCreateKeyEx(get_root_key(key), &key[key.find(L"\\") + 1], 0, nullptr, REG_OPTION_NON_VOLATILE, samDesired, nullptr, &hKey, &dwDisposition) == ERROR_SUCCESS) {
		if (bNew)
			*bNew = (dwDisposition == REG_CREATED_NEW_KEY);
		return true;
	}
	else
		return false;
}

sRegistryContainer Registry::enumerate()
{
	sRegistryContainer results;
	if (hKey == NULL)
		throw std::exception("Key not open");
	DWORD dwcSubKeys, dwcValues, dwMaxValueNameLen, dwMaxValueLen;
	LSTATUS result = RegQueryInfoKey(hKey, nullptr, nullptr, nullptr, &dwcSubKeys, nullptr, nullptr, &dwcValues, &dwMaxValueNameLen, &dwMaxValueLen, nullptr, nullptr/*last write time -- interesting, might use it in the future*/);
	if (result != ERROR_SUCCESS)
		throw std::exception("RegQueryInfoKey failed");
	std::wstring key;
	key.resize(MAX_KEY_LENGTH);
	for (DWORD i = 0; i < dwcSubKeys; i++) {
		DWORD cbName = MAX_KEY_LENGTH + 1;
		LSTATUS lRetCode = RegEnumKeyEx(hKey, i, &key[0], &cbName, nullptr, nullptr, nullptr, nullptr);
		if (lRetCode != ERROR_SUCCESS)
			break;
		results.keys.emplace_back(key.c_str(), cbName);
	}
	std::wstring value_name;
	value_name.resize(MAX_VALUE_NAME);
	for (DWORD i = 0; i < dwcValues; i++) {
		DWORD dwDataType;
		DWORD cbValue = MAX_VALUE_NAME;
		LSTATUS lRetCode = RegEnumValue(hKey, i, &value_name[0], &cbValue, nullptr, &dwDataType, nullptr, nullptr);
		//note: lRetCode might return ERROR_NO_MORE_ITEMS
		if (lRetCode != ERROR_SUCCESS)
			break;
		results.values.push_back({ std::wstring(value_name.c_str(), cbValue), dwDataType });
	}
	return results;
}

void Registry::close()
{
	if (hKey)
		::RegCloseKey(hKey);
	hKey = NULL;
}