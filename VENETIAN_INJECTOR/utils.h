#pragma once
#include <Windows.h>
#include <string>
#include <TlHelp32.h>
#include <stdexcept>

namespace inject_utils {
    DWORD GetProcessIdByName(const std::wstring& processName) {
        DWORD pid = 0;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return 0;

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        std::wstring exeName = pe.szExeFile;

        if (Process32FirstW(snapshot, &pe)) {
            do {
                if (processName == exeName) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &pe));
        }

        CloseHandle(snapshot);
        return pid;
    }
}