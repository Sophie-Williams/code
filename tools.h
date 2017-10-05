#pragma once

namespace Gdiplus { class Bitmap; };

namespace tools {
	namespace app {
		std::list<std::string> get_args();
		std::list<std::wstring> get_wargs();
		std::string get_filename();
		std::wstring get_wfilename();

		std::string get_path();
		std::wstring get_wpath();

		bool stripzoneid(); //deletes the Zone Identifier(this program came from another computer).
		bool elevated();
		bool startup(const std::wstring& task_name, bool bEnable);
		bool set_privilege(const std::wstring& privilege, const bool bEnable = true);
	};

	namespace network { struct domainuseraccount { std::wstring domain, user; }; };

	namespace system {
		std::wstring name(_COMPUTER_NAME_FORMAT format = ComputerNameNetBIOS); //system name
		std::wstring domain();
		std::wstring fqdn();
		std::wstring language();
		LANGID langid();
		ULONGLONG ram();
		enum OperatingSystems {
			os_unknown,
			windows_10,
			windows_server_2016,
			windows_8point1,
			windows_server_2012R2,
			windows_8,
			windows_server_2012,
			windows_7,
			windows_7_SP1,
			windows_server_2008R2,
			windows_vista,
			windows_vista_SP1,
			windows_vista_SP2,
			windows_server_2008,
			windows_XP_SP3,
			windows_XP_SP2,
			windows_XP_SP1,
			windows_XP,
			windows_server_2003
		};

		OperatingSystems OS();
		std::wstring OStoString(OperatingSystems system);
		bool is_x64();
		std::list<std::wstring> users();
		std::list<std::wstring> groups();
		std::list<std::wstring> group_get_members(const std::wstring& group);
		std::wstring get_sid_from_username(const std::wstring& username);
		std::wstring get_username_from_sid(const std::wstring& sid);
		std::wstring get_domain_from_sid(const std::wstring& sid);
		network::domainuseraccount get_domain_user_from_sid(const std::wstring& sid);
		std::wstring get_user_directory(const std::wstring& user);
		std::wstring get_user_sid_directory(const std::wstring& sid);
	};

	namespace user {
		std::wstring username();
		std::wstring language(); //returns the locale name for the language; you can convert it into a LCID by LocaleNameToLCID
		LANGID langid(); //you can convert it to a locale name by using LCIDToLocaleName
		std::wstring lng_country(const std::wstring& lng = language());
		std::wstring lng_name(const std::wstring& lng = language());
		std::vector<BYTE> get_profile_picture(const std::wstring& username = user::username(), int n = 0); //n -> 0 = for the 96x96 one, 1 = for the 448x448 one
		std::wstring temp_directory();
		bool isLocalAdmin();
	};

	namespace process {
		bool isWoW64(HANDLE hProcess);
		bool is_64(HANDLE hProcess);
		std::wstring get_sid(DWORD dwPID); //gets the process's corresponding account sid it's running under.
		std::wstring get_sid(HANDLE hProcess);
		std::wstring FullImageName(DWORD dwPID);
		std::wstring FullImageName(HANDLE hProcess);
		HICON icon(DWORD dwPID);
		HICON icon(HANDLE hProcess);
		bool kill(DWORD dwPID);
		bool kill(HANDLE hProcess);
		bool suspend(DWORD dwPID, bool bSuspend = true);
		std::wstring description(DWORD dwPID);
		std::wstring description(HANDLE hProcess);
		std::wstring version(DWORD dwPID);
		std::wstring version(HANDLE hProcess);

		bool elevated(HANDLE hProcess = GetCurrentProcess());
		bool set_privilege(const std::wstring& privilege, const bool bEnable = true, HANDLE hProcess = GetCurrentProcess());
	};

	namespace window {
		HICON icon(HWND hWnd);
		std::wstring text(HWND hWnd);
	};

	namespace network {
		std::list<std::wstring> users(const std::wstring& server = L"");
		std::list<std::wstring> groups(const std::wstring& server = L"");
		std::list<std::wstring> group_get_members(const std::wstring& group, const std::wstring& server = L"");
		std::wstring get_sid_from_username(const std::wstring& username, const std::wstring& server = L"");
		std::wstring get_username_from_sid(const std::wstring& sid, const std::wstring& server = L"");
		std::wstring get_domain_from_sid(const std::wstring& sid, const std::wstring& server = L"");
		domainuseraccount get_domain_user_from_sid(const std::wstring& sid, const std::wstring& server = L"");
	};

	namespace hicon {
		std::vector<BYTE> extract_to_bmp(HICON hIcon);
	}

	namespace file {
		HICON icon(const std::wstring& filename);
		std::wstring description(const std::wstring& filename);
		std::wstring version(const std::wstring& filename);
		bool patch(const std::wstring& filename, const std::string& find, const std::string& replace);
	};

	namespace image {
		std::vector<BYTE> bmp_to_png(Gdiplus::Bitmap *bmp, ULONG uQuality = 0); //warning: you must call GdiplusStartup before using bmp_to_png
	};

	namespace screen {
		std::vector<BYTE> capture(int iWidth, int iHeight, ULONG quality = 0);
	};

	namespace clipboard {
		std::string get_clipboard_textA();
		std::wstring get_clipboard_textW();
	}

	std::wstring expand_environment_strings(const std::wstring& s);
	std::string expand_environment_strings(const std::string& s);

	std::string strip_filename(const std::string& file);
	std::wstring strip_filename(const std::wstring& file);
	std::string strip_path(const std::string& file);
	std::wstring strip_path(const std::wstring& file);
	std::string between(const std::string& search_str, const std::string& str1, const std::string& str2);
	std::wstring between(const std::wstring& search_str, const std::wstring& str1, const std::wstring& str2);
	std::vector<std::string> split(const std::string& search, char delim);
	std::vector<std::wstring> split(const std::wstring& search, wchar_t delim);
	std::vector<std::string> split(const std::string& search, const std::string& delim);
	std::vector<std::wstring> split(const std::wstring& search, const std::wstring& delim);
};