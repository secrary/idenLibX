#pragma once

#include "plugin.h"
#include <fstream>
#include <istream>
#include <sstream>
#include <iterator>
#include <Zydis/Zydis.h>
#include <filesystem>

namespace fs = std::experimental::filesystem;

#pragma comment(lib, "bcrypt")
#pragma comment(lib, "crypt32")
#pragma comment(lib, "Zydis")


#define SymExDir "SymEx"
#define NT_SUCCESS(_)				(((NTSTATUS)(_)) >= 0)
#define STATUS_SUCCESS				((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL			((NTSTATUS)0xC0000001L)

enum {
	IDEN_LIB,
	ABOUT
};

bool cbIdenLib(int argc, char* argv[]);

class Md5Hash
{
	BCRYPT_ALG_HANDLE phAlgorithm;
	PBYTE pbHashObject;
	PBYTE pbHash;
	BCRYPT_HASH_HANDLE hHash;
	DWORD cbHash;

public:
	NTSTATUS Status;
	Md5Hash();
	std::wstring HashData(__in PUCHAR data, __in ULONG szData);

	~Md5Hash();
};