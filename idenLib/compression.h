#pragma once

#include "plugin.h"

bool CompressFile(__in const fs::path& sigPathTmp, const fs::path& sigPath);

bool DecompressFile(__in const fs::path & sigPath, PBYTE &decompressedData);