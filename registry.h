#pragma once
#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

struct sValue {
	std::wstring name; //[MAX_VALUE_NAME]
	DWORD dwType;
};

struct sRegistryContainer {
	std::list<std::wstring> keys;
	std::list<sValue> values;
};

class Registry {
public:
	Registry();
	Registry(const std::wstring& key, DWORD samDesired) noexcept(false);
	Registry(Registry&& other);
	Registry(const Registry& other);
	~Registry();

	void operator=(Registry&& other);
	void operator=(const Registry& other);

	bool open(const std::string& key, DWORD samDesired);
	bool open(const std::wstring& key, DWORD samDesired);

	static bool delete_key(const std::string& key, bool bx64view = false); //bx64view -> is 64-bit view of registry ( read: https://msdn.microsoft.com/en-us/library/windows/desktop/aa384253(v=vs.85).aspx )
	static bool delete_key(const std::wstring& key, bool bx64view = false);

	bool set_value(const std::wstring& name, DWORD dwDataType, const BYTE *lpData, DWORD cbData);
	bool delete_value(const std::wstring& name);
	bool query_value(const std::wstring& name, PDWORD type, PBYTE buffer, PDWORD cbBuffer);
	bool query_value_type(const std::wstring& value, PDWORD type);
	bool query_value_length(const std::wstring& value, PDWORD len);
	std::vector<BYTE> query_value(const std::wstring& name, PDWORD type = nullptr);
	//std::string query_value_string(const std::string& name); //will throw exception if type != string
	//std::wstring query_value_string(const std::wstring& name); //will throw exception if type != string
	bool create_subkey(const std::wstring& key, bool* bNew = nullptr);
	bool create_key(const std::wstring& key, DWORD samDesired = KEY_READ, bool* bNew = nullptr);
	sRegistryContainer enumerate();

	void close();
	HKEY key() const { return hKey; };
	bool opened() const { return key() != NULL; };
private:
	HKEY hKey;

};