#pragma once

#include <ntdef.h>

#define DRVDETECT_DEVICE_NAME      L"\\Device\\DrvDetect"
#define DRVDETECT_DOS_DEVICE_NAME  L"\\DosDevices\\DrvDetect"
#define DRVDETECT_USER_SYMLINK     L"\\\\.\\DrvDetect"

#define DRVDETECT_TAG 'DdTK'

#define IOCTL_DRVDETECT_GET_ALERT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)

typedef enum _DRVDETECT_ALERT_TYPE
{
    AlertTypeProcessBlocked = 1,
    AlertTypeKernelImageSuspicious = 2,
} DRVDETECT_ALERT_TYPE;

typedef struct _DRVDETECT_ALERT
{
    ULONG Version;
    ULONG Type;
    ULONG ProcessId;
    ULONG ThreadId;
    LARGE_INTEGER Timestamp;
    WCHAR Message[220];
} DRVDETECT_ALERT, *PDRVDETECT_ALERT;

#define DRVDETECT_ALERT_VERSION 1

