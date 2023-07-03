#include "Start Routine.h"

DWORD SR_NtCreateThreadEx( HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, DWORD& lastWin32Error, UINT_PTR& remoteThread );
DWORD SR_HijackThread( HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, DWORD& lastWin32Error, UINT_PTR& remoteThread );
DWORD SR_SetWindowsHookEx( HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, DWORD& lastWin32Error, UINT_PTR& remoteThread );
DWORD SR_QueueUserAPC( HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, DWORD& lastWin32Error, UINT_PTR& remoteThread );

DWORD StartRoutine( HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, LAUNCH_METHOD method, DWORD& lastWin32Error, UINT_PTR& remoteThread )
{
    DWORD dwRet{ 0 };
    switch ( method )
    {
        case LM_NtCreateThreadEx:
            dwRet = SR_NtCreateThreadEx( hTargetProc, pRoutine, pArg, lastWin32Error, remoteThread );
            break;

        case LM_HijackThread:
            dwRet = SR_HijackThread( hTargetProc, pRoutine, pArg, lastWin32Error, remoteThread );
            break;

        case LM_SetWindowsHookEx:
            dwRet = SR_SetWindowsHookEx( hTargetProc, pRoutine, pArg, lastWin32Error, remoteThread );
            break;

        case LM_QueueUserAPC:
            dwRet = SR_QueueUserAPC( hTargetProc, pRoutine, pArg, lastWin32Error, remoteThread );
            break;

        default:
            dwRet = SR_ERR_INVALID_LAUNCH_METHOD;
            break;
    }

    return dwRet;
}

// Create a new thread inside the process and call LoadLibrary from it.
DWORD SR_NtCreateThreadEx( HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, DWORD& lastWin32Error, UINT_PTR& remoteRet )
{
    // (THREAD_START_ROUTINE)pRoutine named "lpStartAddress" --> points to a (callback) function which is to be executed by the newly created thread (here, LoadLibrary) and represents the starting address of the thread
    // 
    // (lpThreadParameter)pArg named "lpParameter" --> A pointer to a variable (here, dllpath buffer)
    //           to be passed to the newly created thread function
    //
    // In our case pRoutine points to LoadLibrary and pArg is the dllpath buffer
    // LoadLibrary(dllPath) loads the dll of the given path in target's virtual memory

    auto pNtCreateThreadEx{ reinterpret_cast<f_NtCreateThreadEx>(GetProcAddress( GetModuleHandle( TEXT( "ntdll.dll" ) ), "NtCreateThreadEx" )) };

    if ( !pNtCreateThreadEx )
    {
        lastWin32Error = GetLastError( );
        return SR_NTCTE_ERR_NTCTE_MISSING;
    }

    void* pMem{ VirtualAllocEx( hTargetProc, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) };
    if ( !pMem )
    {
        lastWin32Error = GetLastError( );
        return SR_NTCTE_ERR_CANT_ALLOC_MEM;
    }

#ifdef _WIN64

    BYTE ShellCode[] =
    {
        // Buffer to store pArg
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // - 0x10   -> argument / returned value

        // Buffer to store pRoutine
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // - 0x08   -> pRoutine

        // Actual Function starts here:
        // This function has has a __fastcall calling convention and therefore address of pArg (pShellCode_start) is passed into rcx as a parameter to this function
        // rcx contains the 'starting address of ShellCode' which is also the address of pArg
        // address of pArg is shallow copied into rax
        // rax is derefernced to get pArg and pArg is copied into rcx to be passed as parameter to pRoutine
        0x48, 0x8B, 0xC1,                                   // + 0x00   -> mov rax, rcx
        0x48, 0x8B, 0x08,                                   // + 0x03   -> mov rcx, [rax]

        // stack setup for calling function
        // Usually add 0x20 bytes for __stdcalls/__fastcalls but when working with  Start Routines, Entry Points, etc. we additionally have to reserve 0x8 bytes
        0x48, 0x83, 0xEC, 0x28,                             // + 0x06   -> sub rsp, 0x28

        // starting address of ShellCode(currently in rax) + 0x08 bytes gives the address of pRoutine(function to be called)
        // therefore, 'ShellCode + 0x08' is derefernced and called
        0xFF, 0x50, 0x08,                                   // + 0x0A   -> call qword ptr [rax + 0x08]
        0x48, 0x83, 0xC4, 0x28,                             // + 0x0D   -> add rsp, 0x28

        // starting address of ShellCode is stored in rcx
        0x48, 0x8D, 0x0D, 0xD8, 0xFF, 0xFF, 0xFF,           // + 0x11   -> lea rcx, [pShellCode_start]
                                                            // written as 'lea rcx, [rip - 0x28]'

        // return value is stored in *rcx i.e in ShellCode_start
        0x48, 0x89, 0x01,                                   // + 0x18   -> mov [rcx], rax

        // rax is zeroed
        0x48, 0x31, 0xC0,                                   // + 0x1B   -> xor rax, rax

        0xC3                                                // + 0x1E   -> ret
    }; // SIZE = 0x1F (+ 0x10)
 
    *reinterpret_cast<void**>(ShellCode + 0x00) = pArg;
    *reinterpret_cast<f_Routine**>(ShellCode + 0x08) = pRoutine;

    DWORD funcOffset{ 0x10 }; // start offset of func

    // copy ShellCode int0 memory allocated
    BOOL bRet{ WriteProcessMemory( hTargetProc, pMem, ShellCode, sizeof( ShellCode ), nullptr ) };
    if ( !bRet )
    {
        lastWin32Error = GetLastError( );

        VirtualFreeEx( hTargetProc, pMem, 0, MEM_RELEASE );

        return SR_NTCTE_ERR_WPM_FAIL;
    }

    void* pRemoteArg{ pMem };
    void* pRemoteFunc{ reinterpret_cast<BYTE*>(pMem) + funcOffset };

    // Call NtCreateThreadEx

    HANDLE hThread{ nullptr };
    NTSTATUS ntRet{ pNtCreateThreadEx( &hThread, THREAD_ALL_ACCESS, nullptr, hTargetProc, pRemoteFunc, pRemoteArg, 0, 0, 0, 0, nullptr ) };
    // hThread --> handle to newly created thread 
    // hTargetProc --> handle to process inside which to create thread
    // pRemoteFunc --> starting address of the thread (pRoutine)
    // pRemoteArg --> argument to be passed to the pRoutine function(i.e. pRemoteFunc) which has a _fastcall calling convention. Therefore, pArg is passed in rcx

    if ( NT_FAIL(ntRet) || !hThread )
    {
        lastWin32Error = ntRet;
        VirtualFreeEx( hTargetProc, pMem, 0, MEM_RELEASE );

        return SR_NTCTE_ERR_NTCTE_FAIL;
    }

    // WaitForSingleObject pauses the calling thread same as 'while(true)' and makes the handle to the object given as parameter (here, hThread) to execute till the object gets signalled (thread or process terminates) or the timer, given as parameter, expires

    // every object can be waited upon that has DISPATCHER_HEADER as its 1st Entry
    DWORD dwWaitRet{ WaitForSingleObject( hThread, SR_REMOTE_TIMEOUT ) };

    // WaitForSingleObject will return WAIT_OBJECT_0 if the wait wasn't aborted.
    if ( dwWaitRet != WAIT_OBJECT_0 )
    {
        lastWin32Error = GetLastError( );
        TerminateThread( hThread, 0 );

        CloseHandle( hThread );

        VirtualFreeEx( hTargetProc, pMem, 0, MEM_RELEASE );

        return SR_NTCTE_ERR_TIMEOUT;
    }

    CloseHandle( hThread );

    // Copy pMem into remoteRet
    bRet = ReadProcessMemory( hTargetProc, pMem, &remoteRet, sizeof( remoteRet ), nullptr );

    VirtualFreeEx( hTargetProc, pMem, 0, MEM_RELEASE );

    if ( !bRet )
    {
        lastWin32Error = GetLastError( );

        return SR_NTCTE_ERR_RPM_FAIL;
    }

#else

    HANDLE hThread{ nullptr };
    NTSTATUS ntRet{ pNtCreateThreadEx( &hThread, THREAD_ALL_ACCESS, nullptr, hTargetProc, pRoutine, pArg, 0, 0, 0, 0, nullptr ) };

    if ( NT_FAIL( ntRet ) || !hThread )
    {
        lastWin32Error = ntRet;
        VirtualFreeEx( hTargetProc, pMem, 0, MEM_RELEASE );

        return SR_NTCTE_ERR_NTCTE_FAIL;
    }

    DWORD dwWaitRet{ WaitForSingleObject( hThread, SR_REMOTE_TIMEOUT ) };
    if ( dwWaitRet != WAIT_OBJECT_0 )
    {
        lastWin32Error = GetLastError( );
        TerminateThread( hThread, 0 );

        CloseHandle( hThread );

        VirtualFreeEx( hTargetProc, pMem, 0, MEM_RELEASE );

        return SR_NTCTE_ERR_TIMEOUT;
    }

    DWORD dwRemoteThread{ 0 };
    BOOL bRet{ GetExitCodeThread( hThread, &dwRemoteThread ) };
    if ( !bRet )
    {
        lastWin32Error = GetLastError( );
        
        CloseHandle( hThread );

        return SR_NTCTE_ERR_RPM_FAIL;
    }

    // For error checking.
    remoteRet = dwRemoteThread;
    CloseHandle( hThread );

#endif // _WIN64

    return SR_ERR_SUCCESS;
}

// Calls Load Library from an existing thread inside the process.
DWORD SR_HijackThread( HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, DWORD& lastWin32Error, UINT_PTR& remoteRet )
{
    // Describes an entry from a list of the threads executing in the system when a snapshot was taken.
    THREADENTRY32 TE32{ 0 };
    TE32.dwSize = sizeof( TE32 );

    DWORD targetPID{ GetProcessId( hTargetProc ) };

    // TH32CS_SNAPTHREAD -> Includes all threads in the system in the snapshot.
    // th32ProcessID(here, targetPID) --> The process identifier of the process to be included in the snapshot.
    HANDLE hSnap{ CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, targetPID ) };
    if ( hSnap == INVALID_HANDLE_VALUE )
    {
        lastWin32Error = GetLastError( );

        return SR_HT_ERR_TH32_FAIL;
    }

    DWORD threadID{ 0 };

    // Retrieves information about the first thread of any process encountered in a system snapshot.
    BOOL bRet{ Thread32First( hSnap, &TE32 ) };
    if ( !bRet )
    {
        lastWin32Error = GetLastError( );
        CloseHandle( hSnap );

        return SR_HT_ERR_T32FIRST_FAIL;
    }

    // To identify the threads that belong to a specific process, compare its process identifier to the th32OwnerProcessID member of the THREADENTRY32 structure when enumerating the threads.
    do
    {
        if ( TE32.th32OwnerProcessID == targetPID )
        {
            threadID = TE32.th32ThreadID;
            break;
        }

        bRet = Thread32Next( hSnap, &TE32 );
    } while ( bRet );

    if ( !threadID )
        return SR_HT_ERR_NO_THREADS;

    // Opens an existing thread object.
    HANDLE hThread{ OpenThread( THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, threadID ) };
    if ( !hThread )
    {
        lastWin32Error = GetLastError( );

        return SR_HT_ERR_OPEN_THREAD_FAIL;
    }

    if ( SuspendThread( hThread ) == (DWORD)-1 )
    {
        lastWin32Error = GetLastError( );
        CloseHandle( hThread );

        return SR_HT_ERR_SUSPEND_FAIL;
    }

    // The flags values within this flag control the contents of
    // a CONTEXT record.
    //
    // If the context record is used as an input parameter, then
    // for each portion of the context record controlled by a flag
    // whose value is set, it is assumed that that portion of the
    // context record contains valid context. If the context record
    // is being used to modify a threads context, then only that
    // portion of the threads context will be modified.
    //
    // If the context record is used as an IN OUT parameter to capture
    // the context of a thread, then only those portions of the thread's
    // context corresponding to set flags will be returned.
    //
    // The context record is never used as an OUT only parameter.

    CONTEXT oldContext{ 0 };
    oldContext.ContextFlags = CONTEXT_CONTROL;
    if ( !GetThreadContext( hThread, &oldContext ) )
    {
        lastWin32Error = GetLastError( );
        ResumeThread( hThread );
        CloseHandle( hThread );

        return SR_HT_ERR_GET_CONTEXT_FAIL;
    }

    void* pCodeCave{ VirtualAllocEx( hTargetProc, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) };
    if ( !pCodeCave )
    {
        lastWin32Error = GetLastError( );
        ResumeThread( hThread );
        CloseHandle( hThread );

        return SR_HT_ERR_CANT_ALLOC_MEM;
    }

#ifdef _WIN64

    // Currently thread is suspended
    BYTE ShellCode[] =
    {
        // Buffer for return value
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                         // - 0x08           -> returned value

        // Only One time execution therefore a check to execute once
        // 0x08 is the value of the checkByteOffset
        0x48, 0x83, 0xEC, 0x08,                                                 // + 0x00           -> sub rsp, 0x08

        // move old RIP int RSP
        0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,                               // + 0x04 (+ 0x07)  -> mov [rsp], RipLowPart
        0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00,                        // + 0x0B (+ 0x0F)  -> mov [rsp + 0x04], RipHighPart

        // save all volatile registers and 
        0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,       // + 0x13           -> push r(a/c/d)x / r(8 - 11)
        // Push EFLAGS Register Onto the Stack
        0x9C,                                                                   // + 0x1E           -> pushfq

        // move LoadLibrary function pointer into rax
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // + 0x1F (+ 0x21)  -> mov rax, pRoutine
        // move dllPath buffer into rcx
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // + 0x29 (+ 0x2B)  -> mov rcx, pArg

        // __fastcall calling convention stack setup
        0x48, 0x83, 0xEC, 0x20,                                                 // + 0x33           -> sub rsp, 0x20
        0xFF, 0xD0,                                                             // + 0x37           -> call rax
        0x48, 0x83, 0xC4, 0x20,                                                 // + 0x39           -> add rsp, 0x20

        // store pShellCode_start into rcx
        0x48, 0x8D, 0x0D, 0xB4, 0xFF, 0xFF, 0xFF,                               // + 0x3D           -> lea rcx, [pShellCode_start]
                                                                                // lea rcx, [rip - 0x4c]

        // assign the return value to pShellCode_start
        0x48, 0x89, 0x01,                                                       // + 0x44           -> mov [rcx], rax

        // release all the registers
        0x9D,                                                                   // + 0x47           -> popfq
        0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58,       // + 0x48           -> pop r(11-8) / r(d/c/a)x

        // move zero into checkByteOffset
        0xC6, 0x05, 0xA9, 0xFF, 0xFF, 0xFF, 0x00,                              // + 0x53           -> mov byte ptr[rip - 0x57], 0

        0xC3                                                                    // + 0x5A           -> return to OldEip
}; // SIZE = 0x5B (+ 0x08)

    DWORD funcOffset{ 0x08 };
    DWORD checkByteOffset{ 0x03 + funcOffset };

    DWORD dwLoRIP{ (DWORD)(oldContext.Rip & 0xffffffff) };
    DWORD dwHiRIP{ (DWORD)(((oldContext.Rip) >> 0x20) & 0xffffffff) };

    *reinterpret_cast<DWORD*>(ShellCode + 0x07 + funcOffset) = dwLoRIP;
    *reinterpret_cast<DWORD*>(ShellCode + 0x0F + funcOffset) = dwHiRIP;

    *reinterpret_cast<void**>(ShellCode + 0x21 + funcOffset) = pRoutine;
    *reinterpret_cast<void**>(ShellCode + 0x2B + funcOffset) = pArg;

    oldContext.Rip = reinterpret_cast<UINT_PTR>(pCodeCave) + funcOffset;

#else

    BYTE ShellCode[] =
    {
            0x00, 0x00, 0x00, 0x00,                     // - 0x04 (pCodecave)   -> returned value                           ;buffer to store returned value (eax)

            0x83, 0xEC, 0x04,                          // + 0x00               -> sub esp, 0x04                           ;prepare stack for ret
            0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,   // + 0x03 (+ 0x06)      -> mov [esp], OldEip                        ;store old eip as return address

            0x50, 0x51, 0x52,                           // + 0x0A               -> psuh e(a/c/d)                            ;save e(a/c/d)x
            0x9C,                                       // + 0x0D               -> pushfd                                   ;save flags register

            0xB9, 0x00, 0x00, 0x00, 0x00,               // + 0x0E (+ 0x0F)     -> mov ecx, pArg                            ;load pArg into ecx
            0xB8, 0x00, 0x00, 0x00, 0x00,               // + 0x13 (+ 0x14)      -> mov eax, pRoutine

            0x51,                                       // + 0x18               -> push ecx                                 ;push pArg
            0xFF, 0xD0,                                 // + 0x19               -> call eax                                 ;call target function

            // move return value into buffer
            0xA3, 0x00, 0x00, 0x00, 0x00,               // + 0x1B (+ 0x1C)     -> mov dword ptr[pShellCode_start], eax            ;store returned value

            0x9D,                                       // + 0x20               -> popfd                                    ;restore flags register
            0x5A, 0x59, 0x58,                           // + 0x21               -> pop e(d/c/a)                             ;restore e(d/c/a)x

            0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,   // + 0x24 (+ 0x26)      -> mov byte ptr[pShellCode_start + 0x06], 0x00     ;set checkbyte to 0

            0xC3                                       // + 0x2B               -> ret                                     ;return to OldEip

    }; // SIZE = 0x2C (+ 0x04)

    DWORD funcOffset{ 0x04 };
    DWORD checkByteOffset{ 0x02 + funcOffset };

    *reinterpret_cast<DWORD*>(ShellCode + 0x06 + funcOffset) = oldContext.Eip;

    *reinterpret_cast<void**>(ShellCode + 0x0F + funcOffset) = pArg;
    *reinterpret_cast<void**>(ShellCode + 0x14 + funcOffset) = pRoutine;

    *reinterpret_cast<void**>(ShellCode + 0x1C + funcOffset) = pCodeCave;
    *reinterpret_cast<BYTE**>(ShellCode + 0x26 + funcOffset) = reinterpret_cast<BYTE*>(pCodeCave) + checkByteOffset;

    oldContext.Eip = reinterpret_cast<DWORD>(pCodeCave) + funcOffset;


#endif // _WIN64

    if ( !WriteProcessMemory( hTargetProc, pCodeCave, ShellCode, sizeof( ShellCode ), nullptr ) )
    {
        lastWin32Error = GetLastError( );
        ResumeThread( hThread );
        CloseHandle( hThread );
        VirtualFreeEx( hTargetProc, pCodeCave, NULL, MEM_RELEASE );

        return SR_HT_ERR_WPM_FAIL;
    }

    // oldContext has become newContext
    if ( !SetThreadContext(hThread, &oldContext ))
    {
        lastWin32Error = GetLastError( );
        ResumeThread( hThread );
        CloseHandle( hThread );
        VirtualFreeEx( hTargetProc, pCodeCave, NULL, MEM_RELEASE );

        return SR_HT_ERR_SET_CONTEXT_FAIL;
    }

    if ( ResumeThread( hThread ) == (DWORD)-1 )
    {
        lastWin32Error = GetLastError( );
        CloseHandle( hThread );
        VirtualFreeEx( hTargetProc, pCodeCave, NULL, MEM_RELEASE );

        return SR_HT_ERR_RESUME_FAIL;
    }

    CloseHandle( hThread );

    DWORD timer{ GetTickCount( ) };
    BYTE checkByte{ 1 };

    do
    {
        ReadProcessMemory( hTargetProc, reinterpret_cast<BYTE*>(pCodeCave) + checkByteOffset, &checkByte, 1, nullptr );
        if ( GetTickCount( ) - timer > SR_REMOTE_TIMEOUT )
        {
            return SR_HT_ERR_TIMEOUT;
        }

        Sleep( 10 );
    } while ( checkByte != 0 );

    // For error checking.
    bRet = ReadProcessMemory( hTargetProc, pCodeCave, &remoteRet, sizeof( remoteRet ), nullptr );

    VirtualFreeEx( hTargetProc, pCodeCave, 0, MEM_RELEASE );

    if ( !bRet )
    {
        lastWin32Error = GetLastError( );

        return SR_NTCTE_ERR_RPM_FAIL;
    }

    return SR_ERR_SUCCESS;
}

DWORD SR_SetWindowsHookEx( HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, DWORD& lastWin32Error, UINT_PTR& remoteRet )
{
    void* pCodeCave{ VirtualAllocEx( hTargetProc, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) };
    if ( !pCodeCave )
    {
        lastWin32Error = GetLastError( );

        return SR_SWHEX_ERR_CANT_ALLOC_MEM;
    }

    // Passes the hook information to the next hook procedure in the current hook chain
    void* pCallNextHookEx{ GetProcAddressEx( hTargetProc, TEXT( "user32.dll" ), "CallNextHookEx" ) };
    if ( !pCallNextHookEx )
    {
        VirtualFreeEx( hTargetProc, pCodeCave, 0, MEM_RELEASE );
        return SR_SWHEX_ERR_CNHEX_MISSING;
    }

#ifdef _WIN64

    BYTE ShellCode[] =
    {
            // Buffer to store pArg
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // - 0x18   -> pArg / returned value / rax  ;buffer

            // Buffer to store pRoutine
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // - 0x10   -> pRoutine                     ;pointer to target function
                                                            
            // Buffer to store pointer to CallNextHookEx
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // - 0x08   -> CallNextHookEx               ;pointer to CallNextHookEx

            0x55,                                           // + 0x00   -> push rbp                     ;save important registers
            0x54,                                           // + 0x01   -> push rsp
            0x53,                                           // + 0x02   -> push rbx

            0x48, 0x8D, 0x1D, 0xDE, 0xFF, 0xFF, 0xFF,       // + 0x03   -> lea rbx, [pArg]              ;load pointer to pArg(pShellCode_start) into rbx
                                                            // lea rbx, [rip - 0x22]

            0x48, 0x83, 0xEC, 0x20,                         // + 0x0A   -> sub rsp, 0x20                ;reserve stack
            0x4D, 0x8B, 0xC8,                               // + 0x0E   -> mov r9,r8                    ;set up arguments for CallNextHookEx
            0x4C, 0x8B, 0xC2,                               // + 0x11   -> mov r8, rdx
            0x48, 0x8B, 0xD1,                               // + 0x14   -> mov rdx,rcx
            0xFF, 0x53, 0x10,                               // + 0x17   -> call [rbx + 0x10]            ;call CallNextHookEx
            0x48, 0x83, 0xC4, 0x20,                         // + 0x1A   -> add rsp, 0x20                ;update stack

            0x48, 0x8B, 0xC8,                               // + 0x1E   -> mov rcx, rax                 ;copy return val into rcx

            0xEB, 0x00,                                     // + 0x21   -> jmp 0x02                     ;jmp to next instruction
            // After patching below at 'ShellCode + 0x23 + codeOffset' will become:    jmp 0x1a

            0xC6, 0x05, 0xF8, 0xFF, 0xFF, 0xFF, 0x18,       // + 0x23   -> mov byte ptr[rip - 0x08], 0x18 ;hotpatch jmp above to skip shellcode: to ensure only 1 time execution

            // 'rcx' currently contains 'CallNextHookEx's return Value' and 'rbx' contains 'pointer to pArg'
            0x48, 0x87, 0x0B,                               // + 0x2A   -> xchg [rbx], rcx              ;store CallNextHookEx retval, load pArg
            // Now, 'rbx' contains 'CallNextHookEx's return Value' and 'rcx' contains 'pointer to pArg'

            0x48, 0x83, 0xEC, 0x20,                         // + 0x2D   -> sub rsp, 0x20                ;reserve stack
            0xFF, 0x53, 0x08,                               // + 0x31   -> call [rbx + 0x08]            ;call pRoutine(LoadLibrary)
            0x48, 0x83, 0xC4, 0x20,                         // + 0x34   -> add rsp, 0x20                ;update stack

            // 'rbx' currently contains 'CallNextHookEx's ret Value' and 'rax' contains 'pRoutine retval'
            0x48, 0x87, 0x03,                               // + 0x38   -> xchg [rbx], rax              ;store pRoutine retval, restore CallNextHookEx retval
            // Now, 'rax' contains 'CallNextHookEx's ret Value' and 'rbx' contains 'pointer to pRoutine retval'

            0x5B,                                           // + 0x3B   -> pop rbx                      ;restore important registers
            0x5C,                                           // + 0x3C   -> pop rsp
            0x5D,                                           // + 0x3D   -> pop rbp

            0xC3                                            // + 0x3E   -> ret                          ;return CallNextHookEx's ret Value
    }; // SIZE = 0x3F (+ 0x18)

    DWORD codeOffset{ 0x18 };
    DWORD checkByteOffset{ 0x22 + codeOffset };

    *reinterpret_cast<void**>(ShellCode + 0x00) = pArg;
    *reinterpret_cast<void**>(ShellCode + 0x08) = pRoutine;
    *reinterpret_cast<void**>(ShellCode + 0x10) = pCallNextHookEx;

#else

    BYTE ShellCode[] =
    {
            0x00, 0x00, 0x00, 0x00,         // - 0x08               -> pArg                     ;pointer to argument
            0x00, 0x00, 0x00, 0x00,         // - 0x04               -> pRoutine                 ;pointer to target function

            0x55,                           // + 0x00               -> push ebp                 ;x86 stack frame creation
            0x8B, 0xEC,                     // + 0x01               -> mov ebp, esp

            0xFF, 0x75, 0x10,               // + 0x03               -> push [ebp + 0x10]        ;push CallNextHookEx arguments
            0xFF, 0x75, 0x0C,               // + 0x06               -> push [ebp + 0x0C]
            0xFF, 0x75, 0x08,               // + 0x09               -> push [ebp + 0x08]
            0x6A, 0x00,                     // + 0x0C               -> push 0x00

            0xE8, 0x00, 0x00, 0x00, 0x00,   // + 0x0E (+ 0x0F)      -> call CallNextHookEx      ;call CallNextHookEx

            0xEB, 0x00,                     // + 0x13               -> jmp 0x02                 ;jmp to next instruction
            // After patching below at 'ShellCode + 0x1c + codeOffset' will become:    jmp 0x14

            0x50,                           // + 0x15               -> push eax                 ;save eax (CallNextHookEx retval)
            0x53,                           // + 0x16               -> push ebx                 ;save ebx (non volatile)

            0xBB, 0x00, 0x00, 0x00, 0x00,   // + 0x17 (+ 0x18)      -> mov ebx, pArg            ;move pArg (pShellCode_start) into ebx
            0xC6, 0x43, 0x1C, 0x14,         // + 0x1C               -> mov [ebx + 0x1C], 0x14   ;hotpatch jmp above to skip shellcode

            0xFF, 0x33,                     // + 0x20               -> push [ebx]               ;push pArg (__stdcall)

            0xFF, 0x53, 0x04,               // + 0x22               -> call [ebx + 0x04]        ;call target function

            0x89, 0x03,                     // + 0x25               -> mov [ebx], eax           ;store returned value(loaded dll's address) at pShellCode_start

            0x5B,                           // + 0x27               -> pop ebx                  ;restore old ebx
            0x58,                           // + 0x28               -> pop eax                  ;restore eax (CallNextHookEx retval)
            0x5D,                           // + 0x29               -> pop ebp                  ;restore ebp
            0xC2, 0x0C, 0x00                // + 0x2A               -> ret 0x000C               ;return and pop 0xC bytes off of the stack
    }; // SIZE = 0x3D (+ 0x08)

    DWORD codeOffset{ 0x08 };
    DWORD checkByteOffset{ 0x14 + codeOffset };

    *reinterpret_cast<void**>(ShellCode + 0x00) = pArg;
    *reinterpret_cast<void**>(ShellCode + 0x04) = pRoutine;

    // Calculate RVA to pCallNextHookEx from next instruction to execute
    *reinterpret_cast<DWORD*>(ShellCode + 0x0F + codeOffset) = reinterpret_cast<DWORD>(pCallNextHookEx) - ((reinterpret_cast<DWORD>(pCodeCave) + 0x0E + codeOffset) + 5);

    *reinterpret_cast<void**>(ShellCode + 0x18 + codeOffset) = pCodeCave;

#endif

    // Write ShellCode in the target process
    if ( !WriteProcessMemory( hTargetProc, pCodeCave, ShellCode, sizeof( ShellCode ), nullptr ))
    {
        lastWin32Error = GetLastError( );
        VirtualFreeEx( hTargetProc, pCodeCave, 0, MEM_RELEASE );

        return SR_SWHEX_ERR_WPM_FAIL;
    }

    static EnumWindowsCallback_Data data;

    data.m_hookData.clear( );
    data.m_pHook = reinterpret_cast<HOOKPROC>(reinterpret_cast<BYTE*>(pCodeCave) + codeOffset);
    // Makes ShellCode + codeOffset a CALLBACK function
    data.m_PID = GetProcessId( hTargetProc );
    data.m_hModule = GetModuleHandle( TEXT( "user32.dll" ) );

    WNDENUMPROC EnumWindowsCallback
    {
         []( HWND hWnd, LPARAM )->BOOL
         {
             DWORD winPID{ 0 };
             DWORD winTID{ GetWindowThreadProcessId( hWnd, &winPID ) };
             // Retrieves the identifier of the thread that created the specified window and, optionally, the identifier of the process that created the window.
             // If the function succeeds, the return value is the identifier of the thread that created the window
             
             if ( winPID == data.m_PID )
             {
                 TCHAR szWindow[MAX_PATH]{ 0 };
                 if ( IsWindowVisible( hWnd ) && GetWindowText( hWnd, szWindow, MAX_PATH ) )
                     // IsWindowVisible --> Determines the visibility state of the specified window.
                     // GetWindowText --> Copies the text of the specified window's title bar (if it has one) into a buffer.
                 {
                     // SetWindowsHookEx doesen't work on Console windows
                     // Check to not attach to console windows
                     if ( GetClassName( hWnd, szWindow, MAX_PATH ) && _tcscmp( szWindow, TEXT( "ConsoleWindowClass" ) ) )
                         // GetClassName --> Retrieves the name of the class to which the specified window belongs.
                     {
                         HHOOK hHook{ SetWindowsHookEx( WH_CALLWNDPROC, data.m_pHook, data.m_hModule, winTID ) };
                         // 1st parameter(idHook) -> The type of hook procedure to be installed.
                         // 2nd parameter(lpfn) -> A pointer to the hook procedure.
                         // 3rd parameter(hMod) -> A handle to the DLL containing the hook procedure pointed to by the lpfn parameter.
                         // 4th parameter(dwThreadId) -> The identifier of the thread with which the hook procedure is to be associated.
                         if ( hHook )
                         {
                             data.m_hookData.push_back( { hHook, hWnd } );
                         }
                     }
                 }
             }

                return TRUE;
         }
    };

    if ( !EnumWindows( EnumWindowsCallback, reinterpret_cast<LPARAM>(&data) ) )
    {
        lastWin32Error = GetLastError( );
        VirtualFreeEx( hTargetProc, pCodeCave, 0, MEM_RELEASE );

        return SR_SWHEX_ERR_ENUM_WND_FAIL;
    }

    if ( data.m_hookData.empty( ) )
    {
        VirtualFreeEx( hTargetProc, pCodeCave, 0, MEM_RELEASE );

        return SR_SWHEX_ERR_NO_WINDOWS;
    }

    HWND hForegroundWnd{ GetForegroundWindow( ) };
    // Retrieves a handle to the foreground window (the window with which the user is currently working)

    for ( auto i : data.m_hookData )
    {
        SetForegroundWindow( i.m_hWnd );
        // Brings the thread that created the specified window(i.e. i.m_hWnd) into the foreground and activates the window
        SendMessage( i.m_hWnd, WM_KEYDOWN, VK_SPACE, 0 );
        Sleep( 10 );
        SendMessage( i.m_hWnd, WM_IME_KEYUP, VK_SPACE, 0 );
        UnhookWindowsHookEx( i.m_hHook );
        // Removes a hook procedure installed in a hook chain by the SetWindowsHookEx function.
    }

    SetForegroundWindow( hForegroundWnd );

    DWORD timer{ GetTickCount( ) };
    BYTE checkByte{ 0 };

    do
    {
        ReadProcessMemory( hTargetProc, reinterpret_cast<BYTE*>(pCodeCave) + checkByteOffset, &checkByte, 1, nullptr );

        if ( GetTickCount( ) - timer > SR_REMOTE_TIMEOUT )
            return SR_SWHEX_ERR_TIMEOUT;

        Sleep( 10 );

    } while ( !checkByte );

    ReadProcessMemory( hTargetProc, pCodeCave, &remoteRet, sizeof( remoteRet ), nullptr );

    VirtualFreeEx( hTargetProc, pCodeCave, 0, MEM_RELEASE );

    return SR_ERR_SUCCESS;
}

DWORD SR_QueueUserAPC( HANDLE hTargetProc, f_Routine* pRoutine, void* pArg, DWORD& lastWin32Error, UINT_PTR& remoteRet )
{
    void* pMem{ VirtualAllocEx( hTargetProc, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) };
    if ( !pMem )
    {
        lastWin32Error = GetLastError( );
        return SR_QUAPC_ERR_CANT_ALLOC_MEM;
    }

#ifdef _WIN64

    BYTE ShellCode[] =
    {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // - 0x18   -> returned value                           ;buffer to store returned value
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // - 0x10   -> pArg                                     ;buffer to store argument
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // - 0x08   -> pRoutine                                 ;buffer to store pointer to the rouinte to call

            0xEB, 0x00,                                        // + 0x00   -> jmp 0x02                              ;jump to the next instruction
                                                               // After patching will become: jmp 0x28

            0x48, 0x8B, 0x41, 0x10,                             // + 0x02   -> mov rax, [rcx + 0x10]                    ;move pRoutine into rax
            0x48, 0x8B, 0x49, 0x08,                             // + 0x06   -> mov rcx, [rcx + 0x08]                    ;move pArg into rcx

            0x48, 0x83, 0xEC, 0x28,                             // + 0x0A   -> sub rsp, 0x28                            ;reserve stack
            0xFF, 0xD0,                                         // + 0x0E   -> call rax                                 ;call pRoutine
            0x48, 0x83, 0xC4, 0x28,                             // + 0x10   -> add rsp, 0x28                            ;update stack

            0x48, 0x85, 0xC0,                                   // + 0x14   -> test rax, rax                            ;check if rax indicates success/failure
            0x74, 0x11,                                        // + 0x17   -> je pCodecave + 0x2A                       ;jmp to ret if routine failed i.e. if rax == 0

            0x48, 0x8D, 0x0D, 0xC8, 0xFF, 0xFF, 0xFF,           // + 0x19   -> lea rcx, [pShellcode_start]              ;load pShellcode_start into rcx
                                                                //             lea rcx, [rip - 0x38]

            0x48, 0x89, 0x01,                                   // + 0x20   -> mov [rcx], rax                           ;store returned value at Shellcode_start

            0xC6, 0x05, 0xD7, 0xFF, 0xFF, 0xFF, 0x28,           // + 0x23   -> mov byte ptr[pCodecave + 0x18], 0x28     ;hot patch jump to skip shellcode
                                                                // mov byte ptr [rip - 0x29], 0x28

            0xC3                                                // + 0x2A   -> ret                                      ;return
    }; // SIZE = 0x2B (+ 0x10)

    DWORD codeOffset{ 0x18 };

    *reinterpret_cast<void**>(ShellCode + 0x08) = pArg;
    *reinterpret_cast<void**>(ShellCode + 0x10) = pRoutine;

#else

    BYTE ShellCode[] =
    {
            0x00, 0x00, 0x00, 0x00, // - 0x0C   -> returned value                   ;buffer to store returned value
            0x00, 0x00, 0x00, 0x00, // - 0x08   -> pArg                             ;buffer to store argument
            0x00, 0x00, 0x00, 0x00, // - 0x04   -> pRoutine                         ;pointer to the routine to call

            0x55,                   // + 0x00   -> push ebp                         ;x86 stack frame creation
            0x8B, 0xEC,             // + 0x01   -> mov ebp, esp

            0xEB, 0x00,             // + 0x03   -> jmp 2                            ;jump to next instruction
                                                // After patching will become: jmp 0x28

            0x53,                   // + 0x05   -> push ebx                         ;save ebx
            0x8B, 0x5D, 0x08,       // + 0x06   -> mov ebx, [ebp + 0x08]            ;move pShellcode_start into ebx (non volatile)

            0xFF, 0x73, 0x04,       // + 0x09   -> push [ebx + 0x04]                ;push pArg on stack
            0xFF, 0x53, 0x08,       // + 0x0C   -> call dword ptr[ebx + 0x08]       ;call pRoutine

            0x85, 0xC0,             // + 0x0F   -> test eax, eax                    ;check if eax indicates success/failure
            0x74, 0x06,             // + 0x11   -> je pCodecave + 0x19 (+ 0x0C)     ;jmp to cleanup if routine failed
                                    //             je 8

            0x89, 0x03,             // + 0x13   -> mov [ebx], eax                   ;store returned value
            0xC6, 0x43, 0x10, 0x15, // + 0x15   -> mov byte ptr [ebx + 0x10], 0x15  ;hot patch jump to skip shellcode

            0x5B,                   // + 0x19   -> pop ebx                          ;restore old ebx
            0x5D,                   // + 0x1A   -> pop ebp                          ;restore ebp

            0xC2, 0x04, 0x00        // + 0x1B   -> ret 0x0004                       ;return
    }; // SIZE = 0x1E (+ 0x0C)

    DWORD codeOffset{ 0x0C };

    *reinterpret_cast<void**>(ShellCode + 0x04) = pArg;
    *reinterpret_cast<void**>(ShellCode + 0x08) = pRoutine;

#endif // _WIN64

    BOOL bRet{ WriteProcessMemory( hTargetProc, pMem, ShellCode, sizeof( ShellCode ), nullptr ) };
    if ( !bRet )
    {
        lastWin32Error = GetLastError( );
        VirtualFreeEx( hTargetProc, pMem, 0, MEM_RELEASE );

        return SR_QUAPC_ERR_WPM_FAIL;
    }

    HANDLE hSnap{ CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, GetProcessId( hTargetProc ) ) };
    if ( hSnap == INVALID_HANDLE_VALUE )
    {
        lastWin32Error = GetLastError( );
        VirtualFreeEx( hTargetProc, pMem, 0, MEM_RELEASE );

        return SR_QUAPC_ERR_TH32_FAIL;
    }

    DWORD targetPID{ GetProcessId( hTargetProc ) };
    bool APCQueued{ false };
    PAPCFUNC pShellCode{ reinterpret_cast<PAPCFUNC>(reinterpret_cast<BYTE*>(pMem) + codeOffset) };

    THREADENTRY32 TE32{};
    TE32.dwSize = sizeof( TE32 );

    bRet = Thread32First( hSnap, &TE32 );
    if ( !bRet )
    {
        lastWin32Error = GetLastError( );
        CloseHandle( hSnap );
        VirtualFreeEx( hTargetProc, pMem, 0, MEM_RELEASE );

        return SR_QUAPC_ERR_T32FIRST_FAIL;
    }

    do
    {
        if ( TE32.th32OwnerProcessID == targetPID )
        {
            // Open any thread of the target process
            HANDLE hThread{ OpenThread( THREAD_SET_CONTEXT | THREAD_ALL_ACCESS | SYNCHRONIZE, FALSE, TE32.th32ThreadID ) };
            SuspendThread( hThread );
            if ( hThread )
            {
                // Queue Shellcode as a APC funtion object (CALLBACK function) to to the APC queue of the specified thread.
                // APC function(pRoutine) will be called when the specified thread(hThread performs an alertable wait operation.
                if ( QueueUserAPC( pShellCode, hThread, reinterpret_cast<ULONG_PTR>(pMem) ) )
                {
                    APCQueued = true;
                }
               
                else
                    lastWin32Error = GetLastError( );

                ResumeThread( hThread );
                CloseHandle( hThread );
            }
        }

        bRet = Thread32Next( hSnap, &TE32 );

    } while ( bRet );

    CloseHandle( hSnap );

    if ( !APCQueued )
    {
        VirtualFreeEx( hTargetProc, pMem, 0, MEM_RELEASE );

        return SR_QUAPC_ERR_NO_APC_THREAD;
    }
    else
    {
        lastWin32Error = 0;
    }

    DWORD timer{ GetTickCount( ) };
    remoteRet = 0;

    do
    {
        ReadProcessMemory( hTargetProc, pMem, &remoteRet, sizeof( remoteRet ), nullptr );

       if ( GetTickCount( ) - timer > SR_REMOTE_TIMEOUT )
            return SR_SWHEX_ERR_TIMEOUT;

        Sleep( 10 );

    } while ( !remoteRet );

    return SR_ERR_SUCCESS;
}