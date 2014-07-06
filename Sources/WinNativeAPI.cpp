// zwtesdt.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <assert.h>
#include <string>
#include <iostream>

using std::string;
using std::wstring;
using std::cout;

#include <windows.h>
#include <Winternl.h>
#include <crtdbg.h>

#include "NTStatusErrors.hpp"


#define UNDEFINED_STATUS_CODE_ERROR_MESSAGE "[Undefined NT Status Code]"

// Public API functions
const char *DecodeWinNTStatusCodeDescription(NTSTATUS codeValue)
{
    WinNativeAPI::NtStatusInfo *info = WinNativeAPI::DecodeNtStatusInfo(static_cast<WinNativeAPI::NTSTATUS_CODES>(codeValue));
    const char *result = info  != NULL ?
            info->m_description : UNDEFINED_STATUS_CODE_ERROR_MESSAGE;
    return result;
}

const char *DecodeWinNTStatusCodeName(NTSTATUS codeValue)
{
    WinNativeAPI::NtStatusInfo *info = WinNativeAPI::DecodeNtStatusInfo(static_cast<WinNativeAPI::NTSTATUS_CODES>(codeValue));
    const char *result = info  != NULL ?
        info->m_name : UNDEFINED_STATUS_CODE_ERROR_MESSAGE;
    return result;
}


//////////////////////////////////////////////////////////////////////////
// Links to read:
//  Using Nt and Zw Versions of the Native System Services Routines [http://msdn.microsoft.com/en-us/library/windows/hardware/ff565438(v=vs.85).aspx]
// 
//////////////////////////////////////////////////////////////////////////

#define NTDLL_LIBRARYNAME _TEXT("NTDLL.dll")
#define NT_WRITEFILE_FUNCTION_NAME "NtWriteFile"
#define NT_CREATEFILE_FUNCTION_NAME "NtCreateFile"
#define RTL_INITUNICODESTRING_FUNCTION_NAME "RtlInitUnicodeString"
#define NT_CLOSE_FUNCTION_NAME "NtClose"
#define NT_READFILE_FUNCTION_NAME "NtReadFile"



//////////////////////////////////////////////////////////////////////////

#define NTAPI __stdcall

typedef NTSTATUS(NTAPI *NtWriteFile_Function)
    (
    _In_      HANDLE FileHandle,
    _In_opt_  HANDLE Event,
    _In_opt_  PIO_APC_ROUTINE ApcRoutine,
    _In_opt_  PVOID ApcContext,
    _Out_     PIO_STATUS_BLOCK IoStatusBlock,
    _In_      PVOID Buffer,
    _In_      ULONG Length,
    _In_opt_  PLARGE_INTEGER ByteOffset,
    _In_opt_  PULONG Key
    );

typedef NTSTATUS(NTAPI *NtCreateFile_Function)
    (
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER AllocationSize OPTIONAL,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG CreateDisposition,
    IN ULONG CreateOptions,
    IN PVOID EaBuffer OPTIONAL,
    IN ULONG EaLength
    );

typedef VOID(NTAPI *RtlInitUnicodeString_Function)
    (
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
    );

typedef NTSTATUS(NTAPI *NtClose_Function)
    (
    IN HANDLE Handle
    );

typedef NTSTATUS (NTAPI *NtReadFile_Function)
    (
      _In_      HANDLE FileHandle,
      _In_opt_  HANDLE Event,
      _In_opt_  PIO_APC_ROUTINE ApcRoutine,
      _In_opt_  PVOID ApcContext,
      _Out_     PIO_STATUS_BLOCK IoStatusBlock,
      _Out_     PVOID Buffer,
      _In_      ULONG Length,
      _In_opt_  PLARGE_INTEGER ByteOffset,
      _In_opt_  PULONG Key
    );


//////////////////////////////////////////////////////////////////////////

class NativeAPI
{
public:
    static NativeAPI *GetInstance()
    {
        if (m_intance == NULL)
        {
            m_intance = new NativeAPI();
        }

        return m_intance;
    }

private:
    NativeAPI():
        m_isInitialized(false),
        m_lastError(WinNativeAPI::NTSTATUS_CODES::SC_STATUS_SUCCESS)
    {
    }

public:

    bool Initialize()
    {
        _ASSERT(!GetIsInitializedFlag());

        bool result;

        if (InitializeLibrary())
        {
            SetIsInitializedFlag();

            result = true;
        }
        else
        {
            result = false;
        }

        return result;
    }

    void Finalize()
    {
        if (GetIsInitializedFlag())
        {
            // ...
            ResetIsInitializedFlag();
        }
    }

public:
    bool WriteFileData(HANDLE fileToWriteHandle, const void *data, size_t dataSize)
    {
        _ASSERT(GetIsInitializedFlag());

        bool result;

        auto NtWriteFileFunction = GetNtWriteFilePtr();

        IO_STATUS_BLOCK inOutStatusBlock;
        ::ZeroMemory(&inOutStatusBlock, sizeof(inOutStatusBlock));
        
        LARGE_INTEGER writeOffset;
        writeOffset.QuadPart = 0;

        NTSTATUS writeResult = NtWriteFileFunction(fileToWriteHandle, 
            NULL, 
            NULL, 
            NULL, 
            &inOutStatusBlock, 
            const_cast<void *>(data), 
            dataSize,
            &writeOffset,
            NULL);

        if (NT_SUCCESS(writeResult))
        {            
            result = true;
        }
        else
        {
            StoreLastError(writeResult);
            result = false;
        }

        return result;
    }

    bool ReadFileData(HANDLE fileToWriteHandle, void *buffer, size_t bufferSize)
    {
        _ASSERT(GetIsInitializedFlag());

        auto NtWriteFileFunction = GetNtReadFilePtr();

    }

    bool WriteFileDatAsync(HANDLE fileToWriteHandle, const void *data, size_t dataSize, HANDLE completionEvent)
    {
        return false;
    }

    bool OpenFileForRead(HANDLE &hOutOpenedFileHandle, const wstring &fileName)
    {
        _ASSERT(GetIsInitializedFlag());

        bool result;

        HANDLE fileHandle = NULL;
        OBJECT_ATTRIBUTES objectAttributes;
        UNICODE_STRING unicodeFileName;
        IO_STATUS_BLOCK inOutStatusBlock;

        GetRtlInitUnicodeStringPtr()(&unicodeFileName, fileName.c_str());

        ZeroMemory(&objectAttributes, sizeof(OBJECT_ATTRIBUTES));
        ZeroMemory(&inOutStatusBlock, sizeof(IO_STATUS_BLOCK));
        InitializeObjectAttributes(&objectAttributes, &unicodeFileName, 0, NULL, NULL);

        NTSTATUS createResult = GetNtCreateFilePtr()(&fileHandle,
            GENERIC_READ,
            &objectAttributes,
            &inOutStatusBlock,
            0,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            NULL,
            0);
        
        if (NT_SUCCESS(createResult))
        {
            hOutOpenedFileHandle = fileHandle;
            result = true;
        }
        else
        {
            StoreLastError(createResult);
            result = false;
        }
        
        return result;
    }

    bool OpenFileForWrite(HANDLE &hOutOpenedFileHandle, const wstring &fileName)
    {
        _ASSERT(GetIsInitializedFlag());

        bool result;

        HANDLE fileHandle = NULL;
        OBJECT_ATTRIBUTES objectAttributes;
        UNICODE_STRING unicodeFileName;
        IO_STATUS_BLOCK inOutStatusBlock;

        GetRtlInitUnicodeStringPtr()(&unicodeFileName, fileName.c_str());

        ZeroMemory(&objectAttributes, sizeof(OBJECT_ATTRIBUTES));
        ZeroMemory(&inOutStatusBlock, sizeof(IO_STATUS_BLOCK));
        InitializeObjectAttributes(&objectAttributes, &unicodeFileName, 0, NULL, NULL);

        NTSTATUS createResult = GetNtCreateFilePtr()(&fileHandle,
            GENERIC_WRITE,
            &objectAttributes,
            &inOutStatusBlock,
            0,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_WRITE,
            FILE_OVERWRITE_IF,
            FILE_NON_DIRECTORY_FILE,
            NULL,
            0);

        if (NT_SUCCESS(createResult))
        {
            hOutOpenedFileHandle = fileHandle;
            result = true;
        }
        else
        {
            StoreLastError(createResult);
            result = false;
        }

        return result;
    }

    void CloseFile(HANDLE hHandleToClose)
    {
        _ASSERT(GetIsInitializedFlag());

        NTSTATUS result = GetNtCloseFilePtr()(hHandleToClose);
        _ASSERT(NT_SUCCESS(result));
    }

public:
    NTSTATUS GetLastError() { return RetrieveLastError(); }


private:
    // TODO: Make it thread safe and reenterant
    void StoreLastError(NTSTATUS status)
    {        
        m_lastError = status;
    }
    NTSTATUS RetrieveLastError()
    {
        return m_lastError;
    }

private:
    bool InitializeLibrary()
    {
        bool result = false;

        HINSTANCE hLib = NULL;
        void *p_writeFileAddress = NULL, *p_createFileAddress = NULL, *p_initUnicodeString = NULL, *p_close = NULL, *p_readFileAddress = NULL;

        do
        {
            hLib = ::LoadLibrary(NTDLL_LIBRARYNAME);
            if (hLib == NULL)
            {
                break;
            }

            SetNtDllInstance(hLib);

            p_writeFileAddress = ::GetProcAddress(hLib, NT_WRITEFILE_FUNCTION_NAME);
            if (p_writeFileAddress == NULL)
            {
                break;
            }

            SetNtWriteFilePtr(p_writeFileAddress);

            p_readFileAddress = ::GetProcAddress(hLib, NT_READFILE_FUNCTION_NAME);
            if (p_readFileAddress == NULL)
            {
                break;
            }
            
            SetNtReadFilePtr(p_readFileAddress);

            p_createFileAddress = ::GetProcAddress(hLib, NT_CREATEFILE_FUNCTION_NAME);
            if (p_createFileAddress == NULL)
            {
                break;
            }

            SetNtCreateFilePtr(p_createFileAddress);

            p_initUnicodeString = ::GetProcAddress(hLib, RTL_INITUNICODESTRING_FUNCTION_NAME);
            if (p_initUnicodeString == NULL)
            {
                break;
            }

            SetRtlInitUnicodeStringPtr(p_initUnicodeString);

            p_close = ::GetProcAddress(hLib, NT_CLOSE_FUNCTION_NAME);
            if (p_close == NULL)
            {
                break;
            }

            SetNtCloseFilePtr(p_close);

            result = true;
        }
        while (false);

        if (!result)
        {
            if (hLib != NULL)
            {
                if (p_writeFileAddress != NULL )
                {
                    if (p_readFileAddress != NULL)
                    {
                        if (p_createFileAddress != NULL)
                        {
                            if (p_initUnicodeString != NULL)
                            {
                                if (p_close != NULL)
                                {
                                    SetNtCloseFilePtr(NULL);
                                }

                                SetRtlInitUnicodeStringPtr(NULL);
                            }

                            SetNtCreateFilePtr(NULL);
                        }

                        SetNtReadFilePtr(NULL);
                    }

                    SetNtWriteFilePtr(NULL);
                }

                ::FreeLibrary(hLib);
                SetNtDllInstance(NULL);
            }
        }

        return result;
    }

private:
    void SetNtDllInstance(HINSTANCE instance) { m_ntdllLibraryInstnace = instance; }
    HINSTANCE GetNtDllInstance() const { return m_ntdllLibraryInstnace; }

    void SetNtWriteFilePtr(void *address) { m_writeFileFunction = (NtWriteFile_Function)address; }
    NtWriteFile_Function GetNtWriteFilePtr() const { return m_writeFileFunction; }

    void SetNtReadFilePtr(void *address) { m_readFileFunction = (NtReadFile_Function) address; }
    NtReadFile_Function GetNtReadFilePtr() const { return m_readFileFunction; }

    void SetNtCreateFilePtr(void *address) { m_createFileFunction = (NtCreateFile_Function)address; }
    NtCreateFile_Function GetNtCreateFilePtr() const { return m_createFileFunction; }

    void SetRtlInitUnicodeStringPtr(void *address) { m_rtlInitUnicodeString = (RtlInitUnicodeString_Function)address; }
    RtlInitUnicodeString_Function GetRtlInitUnicodeStringPtr() const { return m_rtlInitUnicodeString; }

    void SetNtCloseFilePtr(void *address) { m_closeFunction = (NtClose_Function)address; }
    NtClose_Function GetNtCloseFilePtr() const { return m_closeFunction; }

    

    void SetIsInitializedFlag() { m_isInitialized = true; }
    bool GetIsInitializedFlag() const { return m_isInitialized; }
    void ResetIsInitializedFlag() { m_isInitialized = false; }

private:
    bool                            m_isInitialized;
    static NativeAPI                *m_intance;
    NTSTATUS                        m_lastError;

    HINSTANCE                       m_ntdllLibraryInstnace;
    NtWriteFile_Function            m_writeFileFunction;
    NtReadFile_Function             m_readFileFunction;
    NtCreateFile_Function           m_createFileFunction;
    RtlInitUnicodeString_Function   m_rtlInitUnicodeString;
    NtClose_Function                m_closeFunction;
};

/*static */
NativeAPI   *NativeAPI::m_intance;



#define DD_FILE_NAME_U L"\\??\\ll:\\TESTTESTTEST.txt"

int _tmain(int argc, _TCHAR* argv[])
{
    std::cout << "> Program Started.." << std::endl;

    NativeAPI *nativeAPI = NativeAPI::GetInstance();

    bool result = false;
    bool initialized = false;

    do
    {
        if (!nativeAPI->Initialize())
        {
            std::cerr << "> Failed initializing native API library\n";
            break;
        }

        initialized = true;

        std::cout << "> NativeAPI unit initialized.\n";

        HANDLE writeHandle;
        if (!nativeAPI->OpenFileForWrite(writeHandle, DD_FILE_NAME_U))
        {
            std::cerr << "> Failed opening file for writing\n";
            break;
        }

        std::cout << "> File for writing opened.\n";

        const char *sampleText = "Red little fox jumps over the lazy dog";

        if (!nativeAPI->WriteFileData(writeHandle, sampleText, strlen(sampleText)))
        {
            std::cerr << "> Failed writing test to the file data\n";
            break;
        }
        
        std::cout << "> Written successfully.\n";


        std::cout << "> Closing file.\n";
        nativeAPI->CloseFile(writeHandle);

        result = true;
    }
    while (false);

    if (!result)
    {        
        NTSTATUS failedOperationStatus = nativeAPI->GetLastError();                
        std::cerr << ">\tERROR: " << DecodeWinNTStatusCodeName(failedOperationStatus) << std::endl;
        std::cerr << ">\tERROR DESCRIPTION: \"" << DecodeWinNTStatusCodeDescription(failedOperationStatus) << "\"" << std::endl;

        if (initialized)
        {
            std::cout << "> Finalizing.\n";
            nativeAPI->Finalize();
        }
    }

    std::cout << "> Exit.." << std::endl;
}

