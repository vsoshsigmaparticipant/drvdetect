#include "framework.h"
#include "shared.h"

#include <cstdio>

static const wchar_t* AlertTypeToText(unsigned long type)
{
    switch (type)
    {
    case AlertTypeProcessBlocked:
        return L"PROCESS_BLOCKED";
    case AlertTypeKernelImageSuspicious:
        return L"KERNEL_IMAGE_SUSPICIOUS";
    default:
        return L"UNKNOWN";
    }
}

int wmain()
{
    HANDLE hDevice;

    wprintf(L"[drvdetect-um] connecting to %ls\n", DRVDETECT_USER_SYMLINK);

    hDevice = CreateFileW(
        DRVDETECT_USER_SYMLINK,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        wprintf(L"[drvdetect-um] failed to open device, gle=%lu\n", GetLastError());
        return 1;
    }

    wprintf(L"[drvdetect-um] connected, polling alerts...\n");

    for (;;)
    {
        DRVDETECT_ALERT alert = {};
        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_DRVDETECT_GET_ALERT,
            nullptr,
            0,
            &alert,
            static_cast<DWORD>(sizeof(alert)),
            &bytesReturned,
            nullptr);

        if (!ok)
        {
            DWORD gle = GetLastError();
            if (gle == ERROR_NO_MORE_ITEMS || gle == ERROR_NOT_FOUND)
            {
                Sleep(500);
                continue;
            }

            wprintf(L"[drvdetect-um] ioctl failed, gle=%lu\n", gle);
            Sleep(1000);
            continue;
        }

        wprintf(
            L"[drvdetect-um] type=%ls pid=%lu tid=%lu msg=%ls\n",
            AlertTypeToText(alert.Type),
            alert.ProcessId,
            alert.ThreadId,
            alert.Message);
    }

    CloseHandle(hDevice);
    return 0;
}
