#pragma once

namespace pipe {
	struct sPipeClientHandle {
		HANDLE hClient;
		std::unique_ptr<OVERLAPPED> ovl;
	};

	class client {
	public:
		client();
		client(sPipeClientHandle&& handle);
		client(client&& other);
		client(const client&) = delete;
		~client();
		void close() {
			if (hPipe != INVALID_HANDLE_VALUE) {
				FlushFileBuffers(hPipe); // Before disconnecting, the server can make sure data is not lost by calling the FlushFileBuffers function, which does not return until the client process has read all the data.
				if (ovl)
					DisconnectNamedPipe(hPipe);
				CloseHandle(hPipe);
			}
			hPipe = INVALID_HANDLE_VALUE;
		};
		bool connect(const std::string& name);
		bool wait(const std::string& name, DWORD timeout = 10000);
		template <typename T>
		T read(bool* bRead = nullptr);
		template <typename T>
		bool write(const T& data);
		bool read(LPVOID pBuffer, DWORD len);
		bool write(LPCVOID pBuffer, DWORD len);
		bool IsConnected() { return bConnected && hPipe != INVALID_HANDLE_VALUE; };
	private:
		HANDLE hPipe;
		std::unique_ptr<OVERLAPPED> ovl;
		bool bConnected;
	};

	class server {
	public:
		server(const std::string& name);
		~server();
		sPipeClientHandle accept();
		bool available() const { return hPipe != INVALID_HANDLE_VALUE; };
		void close() {
			if (hPipe != INVALID_HANDLE_VALUE)
				::CloseHandle(hPipe);
			hPipe = INVALID_HANDLE_VALUE;
		};
	private:
		HANDLE listen();
		HANDLE hPipe;
		std::string name;
	};
	template<typename T>
	inline T client::read(bool * bRead)
	{
		if (bRead != nullptr)
			*bRead = false;
		T tmp;
		DWORD dwRead;
		BOOL bSuccessfullyRead = ::ReadFile(hPipe, &tmp, sizeof(T), &dwRead, nullptr);
		if (!bSuccessfullyRead || dwRead != sizeof(T))
			return false;
		if (bRead != nullptr)
			*bRead = true;
		return tmp;
	}
	template<typename T>
	inline bool client::write(const T & data)
	{
		DWORD dwWritten;
		BOOL bWritten = ::WriteFile(hPipe, &data, sizeof(T), &dwWritten, nullptr);
		return bWritten && dwWritten == sizeof(T);
	}
};