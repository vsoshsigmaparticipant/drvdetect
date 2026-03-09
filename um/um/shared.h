#pragma once

#include <winioctl.h>

#define DRVDETECT_USER_SYMLINK L"\\\\.\\DrvDetect"

#define IOCTL_DRVDETECT_GET_ALERT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)

typedef enum _DRVDETECT_ALERT_TYPE
{
    AlertTypeProcessBlocked = 1,
    AlertTypeKernelImageSuspicious = 2,
} DRVDETECT_ALERT_TYPE;

typedef struct _DRVDETECT_ALERT
{
    unsigned long Version;
    unsigned long Type;
    unsigned long ProcessId;
    unsigned long ThreadId;
    LARGE_INTEGER Timestamp;
    wchar_t Message[220];
} DRVDETECT_ALERT, *PDRVDETECT_ALERT;

#define DRVDETECT_ALERT_VERSION 1

