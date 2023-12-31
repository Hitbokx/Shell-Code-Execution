#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h> // So we don't need to care about character set

HINSTANCE GetModuleHandleEx( HANDLE hTargetProc, const TCHAR* lpModuleName );

void* GetProcAddressEx( HANDLE hTargetProc, const TCHAR* lpModuleName, const char* lpProcName );