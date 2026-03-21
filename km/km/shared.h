#pragma once

#include <ntdef.h>

#define DRVDETECT_DEVICE_NAME      L"\\Device\\DrvDetect"
#define DRVDETECT_DOS_DEVICE_NAME  L"\\DosDevices\\DrvDetect"
#define DRVDETECT_USER_SYMLINK     L"\\\\.\\DrvDetect"

#define DRVDETECT_TAG 'DdTK'

#define IOCTL_DRVDETECT_GET_ALERT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_DRVDETECT_SET_STATE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_DRVDETECT_GET_STATE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA)

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

typedef enum _DRVDETECT_BLOCKING_STATE
{
    DrvDetectBlockingOff = 0,
    DrvDetectBlockingOn = 1,
} DRVDETECT_BLOCKING_STATE;

typedef struct _DRVDETECT_STATE
{
    ULONG Version;
    ULONG BlockingState;
    ULONG PendingAlerts;
    ULONG Reserved;
} DRVDETECT_STATE, *PDRVDETECT_STATE;

#define DRVDETECT_ALERT_VERSION 1
#define DRVDETECT_STATE_VERSION 1

