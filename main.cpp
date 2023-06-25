#include  "Start Routine.h"

#define DLL_PATH_X86 TEXT("E:\\DEV\\VS Projects\\testdll\\Debug\\testdll.dll")
#define DLL_PATH_X64DLL_PATH_X64 TEXT("E:\\DEV\\VS Projects\\testdll\\Debug\\testdll.dll")

#define PROCESS_NAME_X86 TEXT("notepad++.exe")
#define PROCESS_NAME_X64 TEXT("notepad++.exe")

#define LOAD_LIBRARY_NAME_A "LoadLibraryA"
#define LOAD_LIBRARY_NAME_W "LoadLibraryW"

#ifdef UNICODE
#define LOAD_LIBRARY_NAME LOAD_LIBRARY_NAME_W
#else
#define LOAD_LIBRARY_NAME LOAD_LIBRARY_NAME_A
#endif // UNICODE

#ifdef _WIN64
#define DLL_PATH      DLL_PATH_X64
#define PROCESS_NAME  PROCESS_NAME_X64
#else
#define DLL_PATH      DLL_PATH_X86
#define PROCESS_NAME  PROCESS_NAME_X86
#endif // _WIN64

HANDLE GetProcessByName( const TCHAR* szProcName, DWORD dwDesiredAccess = PROCESS_ALL_ACCESS )
{
	HANDLE hSnap{ CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 ) };
	if ( hSnap == INVALID_HANDLE_VALUE )
		return nullptr;

	PROCESSENTRY32 PE32{ 0 };
	PE32.dwSize = sizeof( PE32 );

	BOOL bRet{ Process32First( hSnap, &PE32 ) };
	while ( bRet )
	{
		if ( !_tcsicmp( PE32.szExeFile, szProcName ) )
			break;

		bRet = Process32Next( hSnap, &PE32 );
	}
	CloseHandle( hSnap );

	if ( !bRet )
		return nullptr;

	return OpenProcess( dwDesiredAccess, FALSE, PE32.th32ProcessID );
}

bool InjectDLL( const TCHAR* szProcess, const TCHAR* szPath, LAUNCH_METHOD method )
{
	HANDLE hProc{ GetProcessByName( szProcess ) };
	if ( !hProc )
	{
		DWORD dwError{ GetLastError( ) };
		printf( "OpenProcess() Failed: 0x%08X\n", dwError );

		return false;
	}

	size_t pathLen{ _tcslen( szPath ) * sizeof( TCHAR ) };
	void* pArg{ VirtualAllocEx( hProc, nullptr, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) };
	// pArg is the dllPath buffer

	if ( !pArg )
	{
		DWORD dwError{ GetLastError( ) };
		printf( "VirtualAlloc() Failed: 0x%08X\n", dwError );

		CloseHandle( hProc );

		return false;
	}

	BOOL wRet{ WriteProcessMemory( hProc, pArg, szPath, pathLen, nullptr ) };
	// Copy the dll path into dllPath buffer inside the target process's virtual memory

	if ( !wRet )
	{
		DWORD dwError{ GetLastError( ) };
		printf( "WriteProcessMemory() Failed: 0x%08X\n", dwError );

		VirtualFreeEx( hProc, pArg, 0, MEM_RELEASE );

		CloseHandle( hProc );

		return false;
	}

	f_Routine* pLoadLibrary{ reinterpret_cast<f_Routine*>(GetProcAddressEx( hProc, TEXT( "kernel32.dll" ), LOAD_LIBRARY_NAME )) };
	// f_Routine is the LoadLibray function pointer
	// Gets LoadLibrary's address from kernel32.dll and stores it into pLoadLibrary

	if ( !pLoadLibrary )
	{
		printf( "Can't find LoadLibrary.\n" );

		VirtualFreeEx( hProc, pArg, 0, MEM_RELEASE );

		CloseHandle( hProc );

		return false;
	}

	UINT_PTR hDLLOut{ 0 };
	DWORD lastError{ 0 };

	DWORD dwError{ StartRoutine( hProc, pLoadLibrary, pArg, method, lastError, hDLLOut ) };
	// pLoadLibrary is the pRoutine ( address of function to be called )
	// pArg is the dllPath buffer used as the argument to LoadLibrary
	// method is the Launch_Method using which to call pRoutine
	// lastError is the return value of GetLastError()
	// hDLLOut is the address of the DLL which has been loaded into the target's virtual memory
	
	if ( method != LM_QueueUserAPC ) // Check for LM_QueueUserAPC as the hook procedure may still be queued to be called by another thread
	{ 
		VirtualFreeEx( hProc, pArg, 0, MEM_RELEASE );
	}

	CloseHandle( hProc );

	if ( dwError )
	{
		printf( "StartRoutine failed: 0x%08X\n", dwError );
		printf( "     LastWin32Error: 0x%08X\n", lastError );

		return false;
	}

	if ( !hDLLOut )
	{
		printf( "LoadLibrary failed. Could not load the DLL.\n" );
		return false;
	}

	printf( "Success! LoadLibrary returned 0x%p\n", reinterpret_cast<void*>(hDLLOut) );
	return true;
}

int main( )
{
	bool bRet{ InjectDLL( PROCESS_NAME, DLL_PATH, LM_NtCreateThreadEx ) };

	if ( !bRet )
	{
		printf( "Press Enter to exit.\n" );
		std::cin.get( );
	}

	return 0;
}