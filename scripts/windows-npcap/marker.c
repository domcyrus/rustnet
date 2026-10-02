#include <windows.h>

/* Record only that this test DLL ran. No capture or network operations. */
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        WCHAR path[32768];
        DWORD length = GetEnvironmentVariableW(L"RUSTNET_DLL_MARKER", path, 32768);
        if (length > 0 && length < 32768) {
            HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                                      CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (file != INVALID_HANDLE_VALUE) {
                const char message[] = "marker DLL executed\n";
                DWORD written;
                WriteFile(file, message, sizeof(message) - 1, &written, NULL);
                CloseHandle(file);
            }
        }
    }
    return TRUE;
}
