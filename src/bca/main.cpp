#include <Windows.h>

#include "bca/install.h"

BOOL WINAPI DllMain(const HINSTANCE module, const DWORD reason, LPVOID )
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        HMODULE pinned = nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                           reinterpret_cast<LPCWSTR>(&DllMain), &pinned);
        CloseHandle(CreateThread(
            nullptr, 0,
            [](LPVOID) -> DWORD {
                try {
                    bca::install();
                }
                catch (...) {
                }
                return 0;
            },
            nullptr, 0, nullptr));
    }
    return TRUE;
}
