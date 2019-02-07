#include "idenLib.h"

bool GetOpcodeBuf(__in PBYTE funcVa, __in const SIZE_T length, __out PBYTE& opcodeBuf, __out ULONG& sizeOfBuf)
{
	ZydisDecoder decoder;

	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_ADDRESS_WIDTH_32);

	ZyanUSize offset = 0;
	ZydisDecodedInstruction instruction;

	opcodeBuf = static_cast<PBYTE>(malloc(length)); // // we need to resize the buffer
	if (!opcodeBuf)
	{
		return false;
	}
	size_t counter = 0;
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, funcVa + offset, length - offset,
		&instruction)))
	{
		opcodeBuf[counter++] = instruction.opcode;

		offset += instruction.length;
	}
	opcodeBuf = static_cast<PBYTE>(realloc(opcodeBuf, counter));
	if (!opcodeBuf)
		return false;
	sizeOfBuf = counter;

	return counter != 0;
}

// http://www.martinbroadhurst.com/how-to-split-a-string-in-c.html
void Split(__in const std::string& str, __out std::vector<std::string>& cont)
{
	std::istringstream iss(str);
	std::copy(std::istream_iterator<std::string>(iss),
		std::istream_iterator<std::string>(),
		std::back_inserter(cont));
}

bool getSig(const fs::path& sig, std::unordered_map<std::wstring, std::wstring> &uniqHashFuncName)
{
	std::ifstream inputFile{ sig };
	std::string line;
	while (std::getline(inputFile, line))
	{
		std::vector<std::string> vec{};
		Split(line, vec);
		if (vec.size() != 2)
		{
			wprintf(L"[!] SIG file contains a malformed data, SIGpath: %s\n", sig.c_str());
			break;
		}
		// vec[0] md5_hash
		// vec[1] name
		std::wstring wHashStr(vec[0].begin(), vec[0].end());
		std::wstring wNameStr(vec[1].begin(), vec[1].end());
		uniqHashFuncName[wHashStr] = wNameStr;
	}
	inputFile.close(); // close handle

	return true;
}

bool cbIdenLib(int argc, char * argv[])
{
	DbgCmdExecDirect("analyze"); // Do function analysis.
	DbgCmdExecDirect("analyse_nukem"); // Do function analysis using nukem’s algorithm.

	auto hashVar = Md5Hash();
	size_t counter = 0;
	std::unordered_map<std::wstring, std::wstring> uniqHashFuncName;
	ListInfo functionList{};
	if (!Script::Function::GetList(&functionList)) {
		return false;
	}
	const auto fList = static_cast<Script::Function::FunctionInfo *>(functionList.data);

	const auto moduleBase = Script::Module::GetMainModuleBase();
	const auto moduleSize = DbgFunctions()->ModSizeFromAddr(moduleBase);
	const auto moduleMemory = static_cast<PBYTE>(Script::Misc::Alloc(moduleSize));

	if (!DbgMemRead(moduleBase, moduleMemory, moduleSize))
	{
		_plugin_logprintf("Couldn't read process memory for scan\n");
		return false;
	}

	const fs::path sigFolder{ SymExDir };
	if (!fs::exists(sigFolder)) {
		const auto path = fs::absolute(sigFolder).string().c_str();
		GuiAddLogMessage("[! idenLib] Following path does not exist:");
		GuiAddLogMessage(path);
		return false;
	}

	// get signatures
	std::error_code ec{};
	for (auto& p : fs::recursive_directory_iterator(sigFolder, ec))
	{
		if (ec.value() != STATUS_SUCCESS)
		{
			continue;
		}
		const auto& currentPath = p.path();
		if (fs::is_regular_file(currentPath, ec))
		{
			if (ec.value() != STATUS_SUCCESS)
			{
				continue;
			}

			getSig(currentPath, uniqHashFuncName);

		}
	}

	// apply sig
	CHAR funcName[MAX_LABEL_SIZE]{};
	for (auto i = 0; i < functionList.count; i++)
	{
		const auto codeStart = moduleBase + fList[i].rvaStart;
		if (DbgGetLabelAt(codeStart, SEG_DEFAULT, funcName)) {

			const auto codeSize = fList[i].rvaEnd - fList[i].rvaStart + 1;

			std::string fName{ funcName };
			PBYTE opcodeBuf = nullptr;
			DWORD sizeofBuf = 0;

			if (GetOpcodeBuf(moduleMemory + fList[i].rvaStart, codeSize, opcodeBuf, sizeofBuf) && opcodeBuf)
			{
				std::wstring hashDig = hashVar.HashData(opcodeBuf, sizeofBuf);
				if (uniqHashFuncName.find(hashDig) != uniqHashFuncName.end())
				{
					std::string currFuncName{ uniqHashFuncName[hashDig].begin(), uniqHashFuncName[hashDig].end() };
					DbgSetAutoLabelAt(codeStart, currFuncName.c_str());
					counter++;
				}

				free(opcodeBuf);
			}

		}
		ZeroMemory(funcName, MAX_LABEL_SIZE);
	}

	char msg[0x100]{};
	sprintf_s(msg, "\n[idenLib] Applied to %d function(s)\n", counter);
	GuiAddLogMessage(msg);

	Script::Misc::Free(moduleMemory);
	BridgeFree(functionList.data);
	GuiUpdateDisassemblyView();


	return true;
}

Md5Hash::Md5Hash()
{
	this->pbHashObject = nullptr;
	this->pbHash = nullptr;
	this->hHash = nullptr;
	this->phAlgorithm = nullptr;
	this->cbHash = 0;

	ULONG cbResult{};


	// The BCryptOpenAlgorithmProvider function loads and initializes a CNG provider.
	if (!NT_SUCCESS(this->Status = BCryptOpenAlgorithmProvider(
		&this->phAlgorithm,
		BCRYPT_MD5_ALGORITHM,
		nullptr,
		BCRYPT_HASH_REUSABLE_FLAG)))
	{
		wprintf(L"[!] Error 0x%lx BCryptOpenAlgorithmProvider\n", this->Status);
		return;
	}

	// HASH LENGTH
	if (!NT_SUCCESS(this->Status = BCryptGetProperty(
		this->phAlgorithm,
		BCRYPT_HASH_LENGTH,
		reinterpret_cast<PBYTE>(&this->cbHash),
		sizeof(DWORD),
		&cbResult,
		0)))
	{
		wprintf(L"[!] Error 0x%lx BCryptGetProperty\n", this->Status);
		return;
	}

	// The BCryptCreateHash function is called to create a md5_hash or Message Authentication Code (MAC) object.
	if (!NT_SUCCESS(this->Status = BCryptCreateHash(
		this->phAlgorithm,
		&this->hHash,
		nullptr,
		0,
		nullptr,
		0,
		BCRYPT_HASH_REUSABLE_FLAG)))
	{
		wprintf(L"[!] Error 0x%lx BCryptCreateHash\n", this->Status);
		return;
	}


	this->Status = STATUS_SUCCESS;
}



std::wstring Md5Hash::HashData(__in PUCHAR data, __in ULONG szData)
{
	this->Status = STATUS_UNSUCCESSFUL;
	PWSTR hashStr = nullptr;
	// The BCryptHashData function performs a one way md5_hash or Message Authentication Code (MAC) on a data buffer.
	if (!NT_SUCCESS(this->Status = BCryptHashData(
		this->hHash,
		data,
		szData,
		0)))
	{
		wprintf(L"[!] Error 0x%lx BCryptHashData\n", this->Status);
		return hashStr;
	}


	this->pbHash = static_cast<PBYTE>(HeapAlloc(GetProcessHeap(), 0, this->cbHash));
	if (nullptr == this->pbHash)
	{
		wprintf(L"[!] HeapAlloc failed\n");
		return hashStr;
	}


	// The BCryptFinishHash function retrieves the md5_hash or Message Authentication Code (MAC) value for the data accumulated from prior calls to BCryptHashData.
	if (!NT_SUCCESS(this->Status = BCryptFinishHash(
		this->hHash,
		this->pbHash,
		this->cbHash,
		0)))
	{
		wprintf(L"[!] Error 0x%lx BCryptFinishHash\n", this->Status);
		return hashStr;
	}

	const DWORD dwFlags = CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF;
	DWORD cchString{};
	// The CryptBinaryToString function converts an array of bytes into a formatted string.
	if (CryptBinaryToStringW(this->pbHash, this->cbHash, dwFlags, nullptr, &cchString))
	{
		hashStr = static_cast<PWSTR>(HeapAlloc(GetProcessHeap(), 0, cchString * sizeof(WCHAR)));
		if (hashStr)
		{
			if (CryptBinaryToStringW(this->pbHash, this->cbHash, dwFlags, hashStr, &cchString))
			{
				return hashStr;
			}
		}
	}

	HeapFree(GetProcessHeap(), 0, this->pbHash);
	return hashStr;
}

Md5Hash::~Md5Hash()
{
	if (this->phAlgorithm)
	{
		BCryptCloseAlgorithmProvider(this->phAlgorithm, 0);
	}
	if (this->pbHashObject)
	{
		HeapFree(GetProcessHeap(), 0, this->pbHashObject);
	}
	if (this->pbHash)
	{
		HeapFree(GetProcessHeap(), 0, this->pbHash);
	}
	if (this->hHash)
	{
		BCryptDestroyHash(this->hHash);
	}
}