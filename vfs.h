#pragma once

namespace vfs {

	class system;

	enum file_identifier_types:BYTE {
		integral,
		str
	};

	class id {
	public:
		id(DWORD id);
		id(const std::wstring& id);
		id(id&& other);
		id(const id& other);
		file_identifier_types type() const { return _type; };
		template <typename T> 
		T get() const;
	private:
		file_identifier_types _type;
		struct {
			std::wstring ws;
			DWORD dw;
		}_id;
	};

	template<>
	inline std::wstring id::get() const
	{
		if (type() == str)
			return _id.ws;
		throw std::exception("Type mismatch"); //return L"";
	}

	template<>
	inline DWORD id::get() const
	{
		if (type() == integral)
			return _id.dw;
		throw std::exception("Type mismatch"); //return NULL;
	}


	class file {
	public:
		file(id&& id, DWORD file_id, DWORD data_size, LONGLONG offset);
		file(file&& other);
		file(const file&) = delete;
		file_identifier_types type() const { return identifier.type(); };
		DWORD fid() const { return file_id; };
		DWORD get_size() const { return file_size; };
		template <typename T>
		T get_id() const { return identifier.get<T>(); };
		bool operator==(const file& other) { return this->fid() == other.fid(); };
	private:
		friend class system;
		DWORD file_id, file_size;
		LONGLONG offset;
		id identifier;
	};

	enum options {
		rd_wr,
		rd_only,
		wr_only
	};
	
	class system {
	public:
		system();
		~system();
		system(system&&) = delete;
		system(const system&) = delete;
		bool open(const std::string& filename, options mode = rd_wr);
		bool open(const std::wstring& filename, options mode = rd_wr);

		std::list<file>::iterator write(DWORD id, const std::vector<BYTE>& data);
		std::list<file>::iterator write(const std::wstring& id, const std::vector<BYTE>& data);
		virtual std::list<file>::iterator write(DWORD id, LPCVOID data, DWORD size);
		virtual std::list<file>::iterator write(const std::wstring& id, LPCVOID data, DWORD size);

		bool update(DWORD id, const std::vector<BYTE>& data);
		bool update(const std::wstring& id, const std::vector<BYTE>& data);
		bool update(DWORD id, LPCVOID data, DWORD size);
		bool update(const std::wstring& id, LPCVOID data, DWORD size);
		virtual bool update(const file& id, LPCVOID data, DWORD size);

		std::vector<BYTE> read(DWORD id);
		std::vector<BYTE> read(const std::wstring& id);
		virtual std::vector<BYTE> read(const file& id);

		void remove(const file& file);
		void remove(const std::wstring& id);
		void remove(DWORD id);

		std::list<file>::iterator erase(std::list<file>::iterator file);
		std::list<file>::iterator erase(const std::wstring& id);
		std::list<file>::iterator erase(DWORD id);

		std::list<file>::iterator find(const std::wstring& id);
		std::list<file>::iterator find(const DWORD& id);
		std::list<file>::iterator find_by_fid(const DWORD& fid);


		std::list<file>::iterator begin() { return files.begin(); };
		std::list<file>::iterator end() { return files.end(); };
		std::list<file>::const_iterator cbegin() const { return files.cbegin(); };
		std::list<file>::const_iterator cend() const { return files.cend(); };

		void clear();

		bool is_opened() { return hFile != INVALID_HANDLE_VALUE; };
		void close();
		void cleanup();
		options g_mode() const { return _mode; };
		size_t file_count() const { return files.size(); };
		//LONGLONG size_on_hd();
	private:
		void move_data(OVERLAPPED& ovl_old, OVERLAPPED& ovl_new, LONGLONG chunk_size);
		void parse_vfs();
		HANDLE hFile;
		size_t fid_counter;
		options _mode;
		std::list<file> files;
		std::wstring filename;
	};

	//to use encrypted_system you must #include <crypto.h> before #include <vfs.h>
#ifdef _CRYPTO_H

	class encrypted_system :public system {
	public:
		using system::system;
		void set(Crypto::AES&& encryption);
		using system::write;
		std::list<file>::iterator write(DWORD id, LPCVOID data, DWORD size) override;
		std::list<file>::iterator write(const std::wstring& id, LPCVOID data, DWORD size) override;
		using system::read;
		std::vector<BYTE> read(const file& id) override;
		bool update(const file& id, LPCVOID data, DWORD size) override;
	private:
		Crypto::AES encryption;
	};

#endif


};

inline vfs::options operator| (vfs::options a, vfs::options b) { return static_cast<vfs::options>(static_cast<int>(a) | static_cast<int>(b)); };