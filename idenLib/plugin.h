#pragma once

#include "pluginmain.h"

#include "zstd.h"
#include <filesystem>
#include <Windows.h>

namespace fs = std::filesystem;

#pragma comment(lib, "libzstd_static")

//plugin data
#define PLUGIN_NAME "idenLib"
#define PLUGIN_VERSION 1
#define PLUGIN_VERSION_STR "0.1"

#define DEFAULT_COMPRESS_LEVEL 3

//functions
bool pluginInit(PLUG_INITSTRUCT* initStruct);
void pluginStop();
void pluginSetup();
