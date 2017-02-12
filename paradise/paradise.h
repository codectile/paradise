#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <functional>
#include <chrono>
#include <vector>
#include <string>
#include "include\capstone.h"

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "capstone.lib")

#define MAX_BYTES	32
#define SAFE_DELETE(x)	if(x){ delete x; x = NULL; }
