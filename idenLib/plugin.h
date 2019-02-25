#pragma once

#include "pluginmain.h"

#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <istream>
#include <sstream>
#include <iterator>
#include <tuple>
#include <fstream>
#include <ctime>
#include <future>

#include "Zydis/Zydis.h"

#define ZSTD_STATIC_LINKING_ONLY
#include "zstd.h"

#include <cereal/types/unordered_map.hpp>
#include <cereal/types/tuple.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/archives/binary.hpp>

namespace fs = std::filesystem;


//plugin data
#define PLUGIN_NAME "idenLib"
#define PLUGIN_VERSION 1
#define PLUGIN_VERSION_STR "0.4"

#define DEFAULT_COMPRESS_LEVEL 3
#define JACCARD_DISTANCE 0.9

#ifdef _WIN64
#define ZYDIS_ADDRESS_WIDTH ZYDIS_ADDRESS_WIDTH_64
#define ZYDIS_MODE ZYDIS_MACHINE_MODE_LONG_64
#define SIG_EXT L".sig64"
#define idenLibCache "idenLibCache64"
#define idenLibCacheMain "idenLibCacheMain64"
#else
#define ZYDIS_ADDRESS_WIDTH ZYDIS_ADDRESS_WIDTH_32
#define ZYDIS_MODE ZYDIS_MACHINE_MODE_LEGACY_32
#define SIG_EXT L".sig"
#define idenLibCache "idenLibCache"
#define idenLibCacheMain "idenLibCacheMain"
#endif

//functions
bool pluginInit(PLUG_INITSTRUCT* initStruct);
void pluginStop();
void pluginSetup();
