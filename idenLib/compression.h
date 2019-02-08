#pragma once

#include "plugin.h"

bool CompressFile(fs::path& sigPathTmp, const fs::path& sigPath);

bool DecompressFile(fs::path & sigPath, PBYTE &decompressedData);