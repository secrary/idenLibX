#include "idenLib.h"

_Success_(return)
bool GetOpcodeBuf(__in PBYTE funcVa, __in SIZE_T length, __out PCHAR& opcodesBuf)
{
	ZydisDecoder decoder;

	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_ADDRESS_WIDTH_32);

	ZyanUSize offset = 0;
	ZydisDecodedInstruction instruction;

	auto cSize = length * 2;
	opcodesBuf = static_cast<PCHAR>(malloc(cSize)); // // we need to resize the buffer
	if (!opcodesBuf)
	{
		return false;
	}
	SIZE_T counter = 0;
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, funcVa + offset, length - offset,
		&instruction)))
	{
		CHAR opcode[3];
		sprintf_s(opcode, "%02x", instruction.opcode);

		memcpy_s(opcodesBuf + counter, cSize - counter, opcode, sizeof(opcode));
		counter += 2;

		offset += instruction.length;
	}
	opcodesBuf = static_cast<PCHAR>(realloc(opcodesBuf, counter + 1)); // +1 for 0x00

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

bool getSig(fs::path& sigPath, std::unordered_map<std::string, std::string> &funcSignature)
{
	PBYTE decompressedData = nullptr;
	if (!DecompressFile(sigPath, decompressedData) || !decompressedData)
	{
		return false;
	}
	char seps[] = "\n";
	char* next_token = nullptr;
	char* line = strtok_s(reinterpret_cast<char*>(decompressedData), seps, &next_token);
	while (line != nullptr)
	{
		std::vector<std::string> vec{};
		Split(line, vec);
		if (vec.size() != 2)
		{
			return false;
		}
		// vec[0] opcode
		// vec[1] name
		funcSignature[vec[0]] = vec[1];
		line = strtok_s(nullptr, seps, &next_token);
	}


	delete[] decompressedData;

	return true;
}

bool cbIdenLib(int argc, char * argv[])
{
	if (!DbgIsDebugging())
	{
		_plugin_logprintf("[idenLib] The debugger is not running!\n");
		return false;
	}
	DbgCmdExecDirect("analyze"); // Do function analysis.
	DbgCmdExecDirect("analyse_nukem"); // Do function analysis using nukem’s algorithm.

	size_t counter = 0;
	std::unordered_map<std::string, std::string> funcSignature;
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
		GuiAddLogMessage("[idenLib] Following path does not exist:");
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
		auto currentPath = p.path();
		if (fs::is_regular_file(currentPath, ec))
		{
			if (ec.value() != STATUS_SUCCESS)
			{
				continue;
			}

			getSig(currentPath, funcSignature);

		}
	}

	// apply sig
	CHAR funcName[MAX_LABEL_SIZE]{};
	for (auto i = 0; i < functionList.count; i++)
	{
		const auto codeStart = moduleBase + fList[i].rvaStart;
		if (DbgGetLabelAt(codeStart, SEG_DEFAULT, funcName)) {

			auto codeSize = fList[i].rvaEnd - fList[i].rvaStart + 1;
			if (codeSize < MIN_FUNC_SIZE)
				continue;
			if (codeSize > MAX_FUNC_SIZE)
			{
				codeSize = MAX_FUNC_SIZE;
			}

			std::string fName{ funcName };
			PCHAR opcodesBuf = nullptr;
			DWORD sizeofBuf = 0;

			if (GetOpcodeBuf(moduleMemory + fList[i].rvaStart, codeSize, opcodesBuf) && opcodesBuf)
			{
				std::string cOpcodes{ opcodesBuf };
				if (funcSignature.find(cOpcodes) != funcSignature.end())
				{
					DbgSetAutoLabelAt(codeStart, funcSignature[cOpcodes].c_str());
					counter++;
				}

				free(opcodesBuf);
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