#pragma once

#include "pluginmain.h"


#include <filesystem>
#include <Windows.h>

#include "Zydis/Zydis.h"

#define ZSTD_STATIC_LINKING_ONLY
#include "zstd.h"

namespace fs = std::filesystem;


//plugin data
#define PLUGIN_NAME "idenLib"
#define PLUGIN_VERSION 1
#define PLUGIN_VERSION_STR "0.3"

#define DEFAULT_COMPRESS_LEVEL 3

#ifdef _WIN64
#define ZYDIS_ADDRESS_WIDTH ZYDIS_ADDRESS_WIDTH_64
#define ZYDIS_MODE ZYDIS_MACHINE_MODE_LONG_64
#define SIG_EXT L".sig64"
#else
#define ZYDIS_ADDRESS_WIDTH ZYDIS_ADDRESS_WIDTH_32
#define ZYDIS_MODE ZYDIS_MACHINE_MODE_LEGACY_32
#define SIG_EXT L".sig"
#endif

//functions
bool pluginInit(PLUG_INITSTRUCT* initStruct);
void pluginStop();
void pluginSetup();
