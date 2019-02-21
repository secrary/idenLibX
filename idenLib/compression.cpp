#include "compression.h"

bool CompressFile(__in const fs::path& sigPathTmp, const fs::path& sigPath)
{
	FILE* hFile = nullptr;
	fopen_s(&hFile, sigPathTmp.string().c_str(), "rb");
	if (!hFile)
	{
		return false;
	}

	// file size
	fseek(hFile, 0L, SEEK_END);
	const auto fSize = ftell(hFile);
	rewind(hFile);
	// read file
	const auto fBuff = new BYTE[fSize];
	fread(fBuff, 1, fSize - 1, hFile); // without last new line \n (0xa)
	// zero (0x00) at the end
	fBuff[fSize - 1] = 0;
	// alloc for compressed data
	const auto cBufSize = ZSTD_compressBound(fSize);
	const auto cBuff = new BYTE[cBufSize];
	// compress data
	const auto cSize = ZSTD_compress(cBuff, cBufSize, fBuff, fSize, DEFAULT_COMPRESS_LEVEL);
	if (ZSTD_isError(cSize))
	{
		delete[] cBuff;
		delete[] fBuff;
		return false;
	}
	fclose(hFile);

	if (exists(sigPath))
	{
		fs::remove(sigPath);
	}
	fopen_s(&hFile, sigPath.string().c_str(), "wb");
	if (!hFile)
	{
		delete[] cBuff;
		delete[] fBuff;
		return false;
	}
	fwrite(cBuff, 1, cSize, hFile);

	delete[] cBuff;
	delete[] fBuff;
	fclose(hFile);

	return true;
}

_Success_(return)

bool DecompressFile(__in const fs::path& sigPath, PBYTE& decompressedData)
{
	FILE* hFile = nullptr;
	fopen_s(&hFile, sigPath.string().c_str(), "rb");
	if (!hFile)
	{
		return false;
	}
	// compressed size
	fseek(hFile, 0L, SEEK_END);
	const auto cSize = ftell(hFile);
	rewind(hFile);
	// read data
	const auto cBuff = new BYTE[cSize];
	if (!cBuff)
	{
		fclose(hFile);
		return false;
	}
	fread(cBuff, 1, cSize, hFile);
	// decompressed size
	const auto rSize = ZSTD_findDecompressedSize(cBuff, cSize);
	if (rSize == ZSTD_CONTENTSIZE_ERROR)
	{
		delete[] cBuff;
		fclose(hFile);
		return false;
	}
	if (rSize == ZSTD_CONTENTSIZE_UNKNOWN)
	{
		delete[] cBuff;
		fclose(hFile);
		return false;
	}
	decompressedData = new BYTE[rSize]; // +1 for 0x00
	if (!decompressedData)
	{
		delete[] cBuff;
		fclose(hFile);
		return false;
	}
	auto const dSize = ZSTD_decompress(decompressedData, rSize, cBuff, cSize);

	if (dSize != rSize)
	{
		delete[] cBuff;
		fclose(hFile);
		return false;
	}


	fclose(hFile);
	delete[] cBuff;
	return true;
}
