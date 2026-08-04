#pragma once

#include "common.h"

void LogProcessInfo(void);

void DumpLoadedModules(void);

void LogStack(void);

LONG WINAPI MyExceptionHandler(EXCEPTION_POINTERS *e);