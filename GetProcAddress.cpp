#include "GetProcAddress.h"

HINSTANCE GetModuleHandleEx( HANDLE hTargetProc, const TCHAR* lpModuleName )
{
	MODULEENTRY32 ME32{ 0 };
	ME32.dwSize = sizeof( ME32 );

	HANDLE hSnap{ CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, GetProcessId( hTargetProc ) ) };

	if ( hSnap == INVALID_HANDLE_VALUE )
	{
		while ( GetLastError( ) == ERROR_BAD_LENGTH )
		{
			hSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, GetProcessId( hTargetProc ) );

			if ( hSnap != INVALID_HANDLE_VALUE )
				break;
		}
	}

	if ( hSnap == INVALID_HANDLE_VALUE )
		return nullptr;

	BOOL bRet{ Module32First( hSnap, &ME32 ) };

	do
	{
		if ( !_tcsicmp( lpModuleName, ME32.szModule ) )
			break;

		bRet = Module32Next( hSnap, &ME32 );

	} while ( bRet );

	CloseHandle( hSnap );

	if( !hSnap)
		return nullptr;

	return ME32.hModule;
}

void* GetProcAddressEx( HANDLE hTargetProc, const TCHAR* lpModuleName, const char* lpProcName )
{
	BYTE* pModBase{ reinterpret_cast<BYTE*>(GetModuleHandleEx( hTargetProc, lpModuleName )) };

	if ( !pModBase )
		return nullptr;

	// 0x1000 is the max size of PE header
	BYTE* pPeHeader{ new BYTE[0x1000] };

	if ( !pPeHeader )
		return nullptr;

	if ( !ReadProcessMemory( hTargetProc, pModBase, pPeHeader, 0x1000, nullptr ) )
	{
		delete[] pPeHeader;
		return nullptr;
	}

	auto* pNtHeader{ reinterpret_cast<IMAGE_NT_HEADERS*>(pPeHeader + reinterpret_cast<IMAGE_DOS_HEADER*>(pPeHeader)->e_lfanew) };

	auto* pExportEntry{ &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] };

	if ( !pExportEntry->Size )
	{
		delete[] pPeHeader;

		return nullptr;
	}

	BYTE* pExportData{ new BYTE[pExportEntry->Size] };

	if ( !pExportData )
	{
		delete[] pPeHeader;

		return nullptr;
	}

	if ( !ReadProcessMemory( hTargetProc, pModBase + pExportEntry->VirtualAddress, pExportData, pExportEntry->Size, nullptr ) )
	{
		delete[] pExportData;
		delete[] pPeHeader;

		return nullptr;
	}

	BYTE* localBase{ pExportData - pExportEntry->VirtualAddress };
	PIMAGE_EXPORT_DIRECTORY pExportDirectory{ reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(pExportData) };

	auto forward
	{
		[&]( DWORD funcRVA )->void*
	    {
			// Expoted functions check
			// Ex: kernel32.ReadProcessMemory\0
			// kernel32 = pFullExport
			// ReadProcessMemory = pFuncName

			char pFullExport[MAX_PATH + 1]{0};
			auto length{ strlen( reinterpret_cast<char*>(localBase + funcRVA) ) };
			if ( !length )
				return nullptr;

			memcpy( pFullExport, reinterpret_cast<char*>(localBase + funcRVA), length );

			char* pFuncName{ strchr( pFullExport, '.' ) };
			// pFuncName currently points at '.' (member operator)

			*(pFuncName++) = 0;
			// makes pFuncName point at 1st char in the name the next time pFuncName is used
			// makes '.' a null \0
			// Ex: kernel32.ReadProcessMemory\0 --> kernel32\0ReadProcessMemory\0

			if ( *pFuncName == '#' )
				pFuncName = reinterpret_cast<char*>(LOWORD( atoi( ++pFuncName ) ));

			// if function is exported by ordinal,
			// convert the string number into actual number
			// Ex: kernel32.#"123"\0 --> kernel32\0#123\0

#ifdef UNICODE
			TCHAR modNameW[MAX_PATH + 1]{ 0 };
			size_t sizeOut = 0;
			mbstowcs_s( &sizeOut, modNameW, pFullExport, MAX_PATH );

			return GetProcAddressEx( hTargetProc, modNameW, pFuncName );

#else
			return GetProcAddressEx( hTargetProc, pFullExport, pFuncName );

#endif // !UNICODE
		}
	};

	// Exported by ordinal

	if ( (reinterpret_cast<UINT_PTR>(lpProcName) & 0xffffff) <= MAXWORD )
	{ // if lpProcName is just an ordinal
		WORD base{ LOWORD( pExportDirectory->Base - 1 ) };
		// pExportDirectory->Base - 1 should be pExportDirectory->Base - pExportDirectory->Base
		// as Base is not always 1
		WORD ordinal = LOWORD( lpProcName ) - base;

		DWORD funcRVA{ reinterpret_cast<DWORD*>(localBase + pExportDirectory->AddressOfFunctions)[ordinal] };

		delete[] pExportData;
		delete[] pPeHeader;

		if ( !funcRVA )
			return nullptr;

		// Check for forwarded function
		if ( funcRVA >= pExportEntry->VirtualAddress && funcRVA < pExportEntry->VirtualAddress + pExportEntry->Size )
		{
			return forward( funcRVA );
		}

		return pModBase + funcRVA;
	}

	// Exported by name

	DWORD max{ pExportDirectory->NumberOfNames - 1 };
	DWORD min{ 0 };
	DWORD funcRVA{ 0 };

	while ( min <= max )
	{
		DWORD mid{ (min + max) / 2 };

		DWORD currentNameRVA{ reinterpret_cast<DWORD*>(localBase + pExportDirectory->AddressOfNames)[mid] };
		char* szName{ reinterpret_cast<char*>(localBase + currentNameRVA) };

		int cmp{ strcmp( szName, lpProcName ) };
		if ( cmp < 0 ) // i.e. lpProcName comes after szName in alphabetics
			min = mid + 1;
		else if ( cmp > 0 )// i.e. lpProcName comes before szName in alphabetics
			max = mid - 1;
		else
		{
			WORD ordinal{ reinterpret_cast<WORD*>(localBase + pExportDirectory->AddressOfNameOrdinals)[mid] };
			funcRVA = reinterpret_cast<DWORD*>(localBase + pExportDirectory->AddressOfFunctions)[ordinal];

			break;
		}
	}

	delete[] pExportData;
	delete[] pPeHeader;

	if ( !funcRVA )
		return nullptr;

	// Check for forwarded function
	if ( funcRVA >= pExportEntry->VirtualAddress && funcRVA < pExportEntry->VirtualAddress + pExportEntry->Size )
	{
		return forward( funcRVA );
	}

	return pModBase + funcRVA;
}