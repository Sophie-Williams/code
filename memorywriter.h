#pragma once

class MemoryWriter {
public:
	void write(LPCVOID data, size_t size);
	void reserve(size_t size) { data.reserve(size); };
	std::vector<BYTE>& get_data() { return data; };
private:
	std::vector<BYTE> data;
};