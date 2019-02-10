#pragma once

#include "plugin.h"
#include <fstream>
#include <istream>
#include <sstream>
#include <iterator>
#include "compression.h"




#define SymExDir "SymEx"
#define NT_SUCCESS(_)				(((NTSTATUS)(_)) >= 0)
#define STATUS_SUCCESS				((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL			((NTSTATUS)0xC0000001L)

#define MIN_FUNC_SIZE 0x20
#define MAX_FUNC_SIZE 0x100

enum {
	IDEN_LIB,
	ABOUT
};

bool cbIdenLib(int argc, char* argv[]);