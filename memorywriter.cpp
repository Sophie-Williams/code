#include <Windows.h>
#include <vector>
#include "memorywriter.h"

void MemoryWriter::write(LPCVOID lpcData, size_t size)
{
	auto o = data.size();
	data.resize(o + size);
	memcpy(&data[o], lpcData, size);
}