#pragma once

#include "pluginmain.h"

//plugin data
#define PLUGIN_NAME "idenLib"
#define PLUGIN_VERSION 1
#define PLUGIN_VERSION_STR "0.1"


//functions
bool pluginInit(PLUG_INITSTRUCT* initStruct);
void pluginStop();
void pluginSetup();
