#include <ntifs.h>
#include <ntstrsafe.h>
#include <wdf.h>

#include "shared.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL DrvDetectEvtIoDeviceControl;
EVT_WDF_DEVICE_FILE_CREATE DrvDetectEvtFileCreate;
EVT_WDF_FILE_CLOSE DrvDetectEvtFileClose;
EVT_WDF_DRIVER_UNLOAD DrvDetectEvtDriverUnload;

#define DRVDETECT_MAX_ALERTS 128
#define DRVDETECT_MAX_TRACKED_SERVICES 64

typedef struct _DRVDETECT_GLOBALS
{
    WDFDEVICE ControlDevice;
    BOOLEAN ProcessNotifyRegistered;
    BOOLEAN ProcessNotifyLegacyRegistered;
    BOOLEAN ImageNotifyRegistered;
    BOOLEAN RegistryCallbackRegistered;
    LARGE_INTEGER RegistryCookie;
    KSPIN_LOCK AlertLock;
    KSPIN_LOCK ServiceTrackLock;
    ULONG AlertHead;
    ULONG AlertTail;
    ULONG AlertCount;
    DRVDETECT_ALERT Alerts[DRVDETECT_MAX_ALERTS];
} DRVDETECT_GLOBALS;

static DRVDETECT_GLOBALS g_DrvDetect;

typedef struct _DRVDETECT_SERVICE_TRACK
{
    BOOLEAN InUse;
    BOOLEAN HasKernelType;
    BOOLEAN HasSuspiciousImagePath;
    WCHAR KeyName[160];
    WCHAR ImagePath[160];
} DRVDETECT_SERVICE_TRACK;

static DRVDETECT_SERVICE_TRACK g_ServiceTracks[DRVDETECT_MAX_TRACKED_SERVICES];

static const WCHAR* g_BlockedMapperNames[] =
{
    L"kdmapper.exe",
    L"kdmapper_debug.exe",
    L"drvmap.exe",
    L"kdu.exe",
    L"drvloader.exe",
};

static const WCHAR* g_BlockedMapperPatterns[] =
{
    L"*\\kdmapper*.exe",
    L"*\\drvmap*.exe",
    L"*\\kdu*.exe",
    L"*\\drvloader*.exe",
};

static const WCHAR* g_VulnerableDriverIndicators[] =
{
    L"\\iqvw64e.sys",
    L"\\gdrv.sys",
    L"\\dbutil_2_3.sys",
    L"\\asupio.sys",
    L"\\eneio64.sys",
    L"\\device\\nal",
};

static
VOID
DrvDetectPushAlert(
    _In_ ULONG Type,
    _In_ ULONG ProcessId,
    _In_ PCWSTR Message
);

static
NTSTATUS
DrvDetectRegistryCallback(
    _In_opt_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
);

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE (0x0001)
#endif

static
BOOLEAN
DrvDetectEndsWithInsensitive(
    _In_opt_ PCUNICODE_STRING Haystack,
    _In_ PCWSTR Suffix
)
{
    UNICODE_STRING suffixUs;

    if (Haystack == NULL || Haystack->Buffer == NULL || Haystack->Length == 0 || Suffix == NULL)
    {
        return FALSE;
    }

    RtlInitUnicodeString(&suffixUs, Suffix);
    return RtlSuffixUnicodeString(&suffixUs, Haystack, TRUE);
}

static
BOOLEAN
DrvDetectContainsSubstrInsensitive(
    _In_opt_ PCUNICODE_STRING Haystack,
    _In_ PCWSTR Substring
)
{
    UNICODE_STRING needle;
    USHORT hayChars;
    USHORT needleChars;
    USHORT i;
    USHORT j;
    WCHAR hayChar;
    WCHAR needleChar;

    if (Haystack == NULL || Haystack->Buffer == NULL || Haystack->Length == 0 || Substring == NULL)
    {
        return FALSE;
    }

    RtlInitUnicodeString(&needle, Substring);
    if (needle.Buffer == NULL || needle.Length == 0)
    {
        return FALSE;
    }

    hayChars = Haystack->Length / sizeof(WCHAR);
    needleChars = needle.Length / sizeof(WCHAR);

    if (needleChars > hayChars)
    {
        return FALSE;
    }

    for (i = 0; i <= (USHORT)(hayChars - needleChars); i++)
    {
        for (j = 0; j < needleChars; j++)
        {
            hayChar = RtlUpcaseUnicodeChar(Haystack->Buffer[i + j]);
            needleChar = RtlUpcaseUnicodeChar(needle.Buffer[j]);
            if (hayChar != needleChar)
            {
                break;
            }
        }

        if (j == needleChars)
        {
            return TRUE;
        }
    }

    return FALSE;
}

static
BOOLEAN
DrvDetectMatchesPatternInsensitive(
    _In_opt_ PCUNICODE_STRING Haystack,
    _In_ PCWSTR Pattern
)
{
    UNICODE_STRING patternUs;

    if (Haystack == NULL || Haystack->Buffer == NULL || Haystack->Length == 0 || Pattern == NULL)
    {
        return FALSE;
    }

    RtlInitUnicodeString(&patternUs, Pattern);
    return FsRtlIsNameInExpression(&patternUs, (PUNICODE_STRING)Haystack, TRUE, NULL);
}

static
BOOLEAN
DrvDetectIsBlockedMapperPath(
    _In_opt_ PCUNICODE_STRING ImagePath
)
{
    SIZE_T i;

    if (ImagePath == NULL || ImagePath->Buffer == NULL || ImagePath->Length == 0)
    {
        return FALSE;
    }

    for (i = 0; i < RTL_NUMBER_OF(g_BlockedMapperPatterns); i++)
    {
        if (DrvDetectMatchesPatternInsensitive(ImagePath, g_BlockedMapperPatterns[i]))
        {
            return TRUE;
        }
    }

    for (i = 0; i < RTL_NUMBER_OF(g_BlockedMapperNames); i++)
    {
        if (DrvDetectEndsWithInsensitive(ImagePath, g_BlockedMapperNames[i]))
        {
            return TRUE;
        }
    }

    return FALSE;
}

static
VOID
DrvDetectTryTerminateProcess(
    _In_ HANDLE ProcessId,
    _In_ NTSTATUS Reason
)
{
    CLIENT_ID cid = { 0 };
    OBJECT_ATTRIBUTES oa;
    HANDLE processHandle = NULL;
    NTSTATUS status;
    WCHAR msg[220];

    cid.UniqueProcess = ProcessId;
    cid.UniqueThread = NULL;

    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenProcess(&processHandle, PROCESS_TERMINATE, &oa, &cid);
    if (!NT_SUCCESS(status))
    {
        RtlStringCchPrintfW(
            msg,
            RTL_NUMBER_OF(msg),
            L"Blocked mapper pid=%lu but ZwOpenProcess failed 0x%08X (reason=0x%08X).",
            HandleToULong(ProcessId),
            status,
            Reason);
        DrvDetectPushAlert(AlertTypeProcessBlocked, HandleToULong(ProcessId), msg);
        return;
    }

    status = ZwTerminateProcess(processHandle, STATUS_ACCESS_DENIED);
    ZwClose(processHandle);

    RtlStringCchPrintfW(
        msg,
        RTL_NUMBER_OF(msg),
        L"Terminated blocked mapper pid=%lu status=0x%08X (reason=0x%08X).",
        HandleToULong(ProcessId),
        status,
        Reason);
    DrvDetectPushAlert(AlertTypeProcessBlocked, HandleToULong(ProcessId), msg);
}

static
BOOLEAN
DrvDetectIsLikelyKdmapperImagePath(
    _In_ PCUNICODE_STRING ValueData
)
{
    USHORT i;
    USHORT end;
    USHORT baseStart;
    USHORT baseLen;
    BOOLEAN hasDot = FALSE;
    BOOLEAN hasSysExtension = FALSE;
    BOOLEAN tempLikePath = FALSE;
    BOOLEAN hasUserTemp = FALSE;
    BOOLEAN hasWindowsTemp = FALSE;
    BOOLEAN allAsciiName = TRUE;

    if (ValueData == NULL || ValueData->Buffer == NULL || ValueData->Length == 0)
    {
        return FALSE;
    }

    if (!DrvDetectContainsSubstrInsensitive(ValueData, L"\\??\\"))
    {
        return FALSE;
    }

    hasUserTemp =
        DrvDetectContainsSubstrInsensitive(ValueData, L"\\users\\") &&
        DrvDetectContainsSubstrInsensitive(ValueData, L"\\appdata\\local\\temp\\");
    hasWindowsTemp = DrvDetectContainsSubstrInsensitive(ValueData, L"\\windows\\temp\\");
    tempLikePath = hasUserTemp || hasWindowsTemp;

    if (DrvDetectContainsSubstrInsensitive(ValueData, L"\\windows\\system32\\drivers\\"))
    {
        return FALSE;
    }

    if (DrvDetectContainsSubstrInsensitive(ValueData, L"iqvw64e"))
    {
        return TRUE;
    }

    if (!tempLikePath)
    {
        return FALSE;
    }

    end = ValueData->Length / sizeof(WCHAR);
    baseStart = 0;
    for (i = 0; i < end; i++)
    {
        if (ValueData->Buffer[i] == L'\\' || ValueData->Buffer[i] == L'/')
        {
            baseStart = i + 1;
        }
    }

    if (baseStart >= end)
    {
        return FALSE;
    }

    baseLen = end - baseStart;
    if (baseLen < 8 || baseLen > 44)
    {
        return FALSE;
    }

    for (i = baseStart; i < end; i++)
    {
        WCHAR c = ValueData->Buffer[i];
        if (c == L'.')
        {
            hasDot = TRUE;
            if ((i + 4) == end &&
                (ValueData->Buffer[i + 1] == L's' || ValueData->Buffer[i + 1] == L'S') &&
                (ValueData->Buffer[i + 2] == L'y' || ValueData->Buffer[i + 2] == L'Y') &&
                (ValueData->Buffer[i + 3] == L's' || ValueData->Buffer[i + 3] == L'S'))
            {
                hasSysExtension = TRUE;
                break;
            }

            allAsciiName = FALSE;
            break;
        }

        if (!((c >= L'0' && c <= L'9') ||
              (c >= L'a' && c <= L'z') ||
              (c >= L'A' && c <= L'Z') ||
              c == L'_'))
        {
            allAsciiName = FALSE;
            break;
        }
    }

    if (!allAsciiName)
    {
        return FALSE;
    }

    if (!hasDot)
    {
        return TRUE;
    }

    return hasSysExtension;
}

static
BOOLEAN
DrvDetectShouldBlockDriverServiceImagePath(
    _In_ PCUNICODE_STRING ValueData
)
{
    SIZE_T i;

    if (ValueData == NULL || ValueData->Buffer == NULL || ValueData->Length == 0)
    {
        return FALSE;
    }

    if (DrvDetectContainsSubstrInsensitive(ValueData, L"\\??\\") &&
        ((DrvDetectContainsSubstrInsensitive(ValueData, L"\\users\\") &&
          DrvDetectContainsSubstrInsensitive(ValueData, L"\\appdata\\local\\temp\\")) ||
         DrvDetectContainsSubstrInsensitive(ValueData, L"\\windows\\temp\\")))
    {
        return TRUE;
    }

    for (i = 0; i < RTL_NUMBER_OF(g_VulnerableDriverIndicators); i++)
    {
        if (DrvDetectContainsSubstrInsensitive(ValueData, g_VulnerableDriverIndicators[i]))
        {
            return TRUE;
        }
    }

    return DrvDetectIsLikelyKdmapperImagePath(ValueData);
}

static
VOID
DrvDetectDescribeRegistryWrite(
    _In_ PCUNICODE_STRING KeyName,
    _In_ PCUNICODE_STRING ValueName,
    _In_ ULONG ValueType,
    _In_opt_ PCUNICODE_STRING ValueData
)
{
    WCHAR msg[220];

    if (KeyName == NULL || ValueName == NULL)
    {
        return;
    }

    if (ValueData != NULL &&
        ValueData->Buffer != NULL &&
        ValueData->Length > 0 &&
        (ValueType == REG_SZ || ValueType == REG_EXPAND_SZ))
    {
        RtlStringCchPrintfW(
            msg,
            RTL_NUMBER_OF(msg),
            L"Registry write key=%wZ value=%wZ data=%wZ",
            KeyName,
            ValueName,
            ValueData);
    }
    else if (ValueType == REG_DWORD && ValueData != NULL && ValueData->Buffer != NULL && ValueData->Length >= sizeof(ULONG))
    {
        RtlStringCchPrintfW(
            msg,
            RTL_NUMBER_OF(msg),
            L"Registry write key=%wZ value=%wZ dword=%lu",
            KeyName,
            ValueName,
            *(ULONG*)ValueData->Buffer);
    }
    else
    {
        RtlStringCchPrintfW(
            msg,
            RTL_NUMBER_OF(msg),
            L"Registry write key=%wZ value=%wZ type=%lu size=%u",
            KeyName,
            ValueName,
            ValueType,
            ValueData != NULL ? ValueData->Length : 0);
    }

    DrvDetectPushAlert(AlertTypeKernelImageSuspicious, HandleToULong(PsGetCurrentProcessId()), msg);
}

static
VOID
DrvDetectInitRegistryStringValue(
    _Out_ PUNICODE_STRING ValueData,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize
)
{
    USHORT lengthBytes;

    ValueData->Buffer = (PWCH)Data;
    lengthBytes = (USHORT)min(DataSize, (ULONG)0xFFFE);

    while (lengthBytes >= sizeof(WCHAR))
    {
        WCHAR tail = *((PWCHAR)((PUCHAR)Data + lengthBytes - sizeof(WCHAR)));
        if (tail != UNICODE_NULL)
        {
            break;
        }

        lengthBytes -= sizeof(WCHAR);
    }

    ValueData->Length = lengthBytes;
    ValueData->MaximumLength = lengthBytes;
}

static
BOOLEAN
DrvDetectIsServicesRegistryPath(
    _In_opt_ PCUNICODE_STRING KeyName
)
{
    if (KeyName == NULL || KeyName->Buffer == NULL || KeyName->Length == 0)
    {
        return FALSE;
    }

    if (!DrvDetectContainsSubstrInsensitive(KeyName, L"\\registry\\machine\\system\\"))
    {
        return FALSE;
    }

    if (!(DrvDetectContainsSubstrInsensitive(KeyName, L"\\currentcontrolset\\services\\") ||
          DrvDetectContainsSubstrInsensitive(KeyName, L"\\controlset")))
    {
        return FALSE;
    }

    return DrvDetectContainsSubstrInsensitive(KeyName, L"\\services\\");
}

static
BOOLEAN
DrvDetectIsCiConfigRegistryPath(
    _In_opt_ PCUNICODE_STRING KeyName
)
{
    if (KeyName == NULL || KeyName->Buffer == NULL || KeyName->Length == 0)
    {
        return FALSE;
    }

    if (!DrvDetectContainsSubstrInsensitive(KeyName, L"\\registry\\machine\\system\\"))
    {
        return FALSE;
    }

    if (!(DrvDetectContainsSubstrInsensitive(KeyName, L"\\currentcontrolset\\control\\ci\\config") ||
          DrvDetectContainsSubstrInsensitive(KeyName, L"\\controlset001\\control\\ci\\config") ||
          DrvDetectContainsSubstrInsensitive(KeyName, L"\\controlset002\\control\\ci\\config") ||
          DrvDetectContainsSubstrInsensitive(KeyName, L"\\controlset003\\control\\ci\\config")))
    {
        return FALSE;
    }

    return TRUE;
}

static
NTSTATUS
DrvDetectRegistryCallback(
    _In_opt_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
)
{
    REG_NOTIFY_CLASS notifyClass;
    PREG_SET_VALUE_KEY_INFORMATION setInfo;
    PCUNICODE_STRING keyName = NULL;
    UNICODE_STRING valueData;
    ULONG valueType;
    ULONG dwordValue;
    BOOLEAN isServicesKey = FALSE;
    BOOLEAN isTypeWrite = FALSE;
    BOOLEAN isImagePathWrite = FALSE;
    BOOLEAN shouldBlock = FALSE;
    BOOLEAN immediateImagePathBlock = FALSE;
    KLOCK_QUEUE_HANDLE lockHandle;
    ULONG i;
    LONG freeIndex = -1;
    LONG matchIndex = -1;
    WCHAR msg[220];
    ULONG_PTR objectId = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(CallbackContext);

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    if (notifyClass != RegNtPreSetValueKey || Argument2 == NULL)
    {
        return STATUS_SUCCESS;
    }

    setInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
    if (setInfo->ValueName == NULL || setInfo->Data == NULL)
    {
        return STATUS_SUCCESS;
    }

    valueType = setInfo->Type;
    isTypeWrite = DrvDetectEndsWithInsensitive(setInfo->ValueName, L"Type");
    isImagePathWrite = DrvDetectEndsWithInsensitive(setInfo->ValueName, L"ImagePath");

    if (!isTypeWrite && !isImagePathWrite)
    {
        return STATUS_SUCCESS;
    }

    if (isImagePathWrite && (valueType == REG_SZ || valueType == REG_EXPAND_SZ))
    {
        WCHAR observedMsg[220];

        DrvDetectInitRegistryStringValue(&valueData, setInfo->Data, setInfo->DataSize);

        RtlStringCchPrintfW(
            observedMsg,
            RTL_NUMBER_OF(observedMsg),
            L"Observed ImagePath: %wZ",
            &valueData);
        DrvDetectPushAlert(
            AlertTypeKernelImageSuspicious,
            HandleToULong(PsGetCurrentProcessId()),
            observedMsg);

        if (DrvDetectShouldBlockDriverServiceImagePath(&valueData))
        {
            WCHAR earlyMsg[220];

            RtlStringCchPrintfW(
                earlyMsg,
                RTL_NUMBER_OF(earlyMsg),
                L"Blocked suspicious ImagePath write before service resolution: %wZ",
                &valueData);
            DrvDetectPushAlert(AlertTypeProcessBlocked, HandleToULong(PsGetCurrentProcessId()), earlyMsg);
            return STATUS_ACCESS_DENIED;
        }
    }

    status = CmCallbackGetKeyObjectIDEx(
        &g_DrvDetect.RegistryCookie,
        setInfo->Object,
        &objectId,
        &keyName,
        0);
    if (!NT_SUCCESS(status) || keyName == NULL)
    {
        return STATUS_SUCCESS;
    }

    isServicesKey = DrvDetectIsServicesRegistryPath(keyName);
    if (!isServicesKey)
    {
        if (DrvDetectIsCiConfigRegistryPath(keyName) &&
            DrvDetectEndsWithInsensitive(setInfo->ValueName, L"VulnerableDriverBlocklistEnable") &&
            valueType == REG_DWORD &&
            setInfo->DataSize >= sizeof(ULONG))
        {
            dwordValue = *(ULONG*)setInfo->Data;
            if (dwordValue == 0)
            {
                DrvDetectPushAlert(
                    AlertTypeProcessBlocked,
                    HandleToULong(PsGetCurrentProcessId()),
                    L"Blocked attempt to disable VulnerableDriverBlocklistEnable.");
                CmCallbackReleaseKeyObjectIDEx(keyName);
                return STATUS_ACCESS_DENIED;
            }
        }

        CmCallbackReleaseKeyObjectIDEx(keyName);
        return STATUS_SUCCESS;
    }

    KeAcquireInStackQueuedSpinLock(&g_DrvDetect.ServiceTrackLock, &lockHandle);

    for (i = 0; i < DRVDETECT_MAX_TRACKED_SERVICES; i++)
    {
        if (g_ServiceTracks[i].InUse)
        {
            UNICODE_STRING lhs;
            UNICODE_STRING rhs;
            RtlInitUnicodeString(&lhs, g_ServiceTracks[i].KeyName);
            rhs = *keyName;
            if (RtlEqualUnicodeString(&lhs, &rhs, TRUE))
            {
                matchIndex = (LONG)i;
                break;
            }
        }
        else if (freeIndex < 0)
        {
            freeIndex = (LONG)i;
        }
    }

    if (matchIndex < 0)
    {
        if (freeIndex < 0)
        {
            freeIndex = 0;
        }
        matchIndex = freeIndex;
        RtlZeroMemory(&g_ServiceTracks[matchIndex], sizeof(g_ServiceTracks[matchIndex]));
        g_ServiceTracks[matchIndex].InUse = TRUE;
        RtlStringCchCopyNW(
            g_ServiceTracks[matchIndex].KeyName,
            RTL_NUMBER_OF(g_ServiceTracks[matchIndex].KeyName),
            keyName->Buffer,
            keyName->Length / sizeof(WCHAR));
    }

    if (isTypeWrite && valueType == REG_DWORD && setInfo->DataSize >= sizeof(ULONG))
    {
        valueData.Buffer = (PWCH)setInfo->Data;
        valueData.Length = sizeof(ULONG);
        valueData.MaximumLength = sizeof(ULONG);
        DrvDetectDescribeRegistryWrite(keyName, setInfo->ValueName, valueType, &valueData);

        dwordValue = *(ULONG*)setInfo->Data;
        if (dwordValue == 1)
        {
            g_ServiceTracks[matchIndex].HasKernelType = TRUE;
        }
    }

    if (isImagePathWrite && (valueType == REG_SZ || valueType == REG_EXPAND_SZ))
    {
        DrvDetectInitRegistryStringValue(&valueData, setInfo->Data, setInfo->DataSize);
        DrvDetectDescribeRegistryWrite(keyName, setInfo->ValueName, valueType, &valueData);

        if (DrvDetectShouldBlockDriverServiceImagePath(&valueData))
        {
            g_ServiceTracks[matchIndex].HasSuspiciousImagePath = TRUE;
            immediateImagePathBlock = TRUE;
            RtlStringCchCopyNW(
                g_ServiceTracks[matchIndex].ImagePath,
                RTL_NUMBER_OF(g_ServiceTracks[matchIndex].ImagePath),
                valueData.Buffer,
                valueData.Length / sizeof(WCHAR));
        }
    }

    if (immediateImagePathBlock || (g_ServiceTracks[matchIndex].HasKernelType && g_ServiceTracks[matchIndex].HasSuspiciousImagePath))
    {
        shouldBlock = TRUE;
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);

    if (shouldBlock)
    {
        RtlStringCchPrintfW(
            msg,
            RTL_NUMBER_OF(msg),
            L"Blocked kdmapper-like vulnerable-driver staging: key=%wZ img=%ws",
            keyName,
            g_ServiceTracks[matchIndex].ImagePath);
        DrvDetectPushAlert(AlertTypeProcessBlocked, HandleToULong(PsGetCurrentProcessId()), msg);
        CmCallbackReleaseKeyObjectIDEx(keyName);
        return STATUS_ACCESS_DENIED;
    }

    CmCallbackReleaseKeyObjectIDEx(keyName);
    return STATUS_SUCCESS;
}

static
VOID
DrvDetectPushAlert(
    _In_ ULONG Type,
    _In_ ULONG ProcessId,
    _In_ PCWSTR Message
)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    DRVDETECT_ALERT* alert;

    KeAcquireInStackQueuedSpinLock(&g_DrvDetect.AlertLock, &lockHandle);

    if (g_DrvDetect.AlertCount == DRVDETECT_MAX_ALERTS)
    {
        g_DrvDetect.AlertHead = (g_DrvDetect.AlertHead + 1) % DRVDETECT_MAX_ALERTS;
        g_DrvDetect.AlertCount--;
    }

    alert = &g_DrvDetect.Alerts[g_DrvDetect.AlertTail];
    RtlZeroMemory(alert, sizeof(*alert));
    alert->Version = DRVDETECT_ALERT_VERSION;
    alert->Type = Type;
    alert->ProcessId = ProcessId;
    alert->ThreadId = HandleToULong(PsGetCurrentThreadId());
    KeQuerySystemTimePrecise(&alert->Timestamp);

    if (Message != NULL)
    {
        RtlStringCchCopyW(alert->Message, RTL_NUMBER_OF(alert->Message), Message);
    }

    g_DrvDetect.AlertTail = (g_DrvDetect.AlertTail + 1) % DRVDETECT_MAX_ALERTS;
    g_DrvDetect.AlertCount++;

    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

static
BOOLEAN
DrvDetectPopAlert(
    _Out_ DRVDETECT_ALERT* Alert
)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    BOOLEAN hasAlert = FALSE;

    KeAcquireInStackQueuedSpinLock(&g_DrvDetect.AlertLock, &lockHandle);

    if (g_DrvDetect.AlertCount > 0)
    {
        *Alert = g_DrvDetect.Alerts[g_DrvDetect.AlertHead];
        g_DrvDetect.AlertHead = (g_DrvDetect.AlertHead + 1) % DRVDETECT_MAX_ALERTS;
        g_DrvDetect.AlertCount--;
        hasAlert = TRUE;
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return hasAlert;
}

static
VOID
DrvDetectProcessNotifyEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    WCHAR message[220];
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo == NULL || CreateInfo->ImageFileName == NULL)
    {
        return;
    }

    if (DrvDetectIsBlockedMapperPath(CreateInfo->ImageFileName))
    {
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;

        RtlStringCchPrintfW(
            message,
            RTL_NUMBER_OF(message),
            L"Blocked known mapper process: %wZ (pid=%lu)",
            CreateInfo->ImageFileName,
            HandleToULong(ProcessId));

        DrvDetectPushAlert(AlertTypeProcessBlocked, HandleToULong(ProcessId), message);
        return;
    }
}

static
VOID
DrvDetectProcessNotifyLegacy(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
)
{
    PEPROCESS process = NULL;
    PUNICODE_STRING processPath = NULL;
    NTSTATUS status;
    WCHAR msg[220];

    UNREFERENCED_PARAMETER(ParentId);

    if (!Create)
    {
        return;
    }

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status))
    {
        return;
    }

    status = SeLocateProcessImageName(process, &processPath);
    ObDereferenceObject(process);

    if (!NT_SUCCESS(status) || processPath == NULL)
    {
        return;
    }

    if (DrvDetectIsBlockedMapperPath(processPath))
    {
        RtlStringCchPrintfW(
            msg,
            RTL_NUMBER_OF(msg),
            L"Legacy callback matched mapper path: %wZ",
            processPath);
        DrvDetectPushAlert(AlertTypeProcessBlocked, HandleToULong(ProcessId), msg);
        DrvDetectTryTerminateProcess(ProcessId, STATUS_NOT_SUPPORTED);
    }

    ExFreePool(processPath);
}

static
VOID
DrvDetectImageLoadNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
)
{
    SIZE_T i;
    WCHAR message[220];
    ULONG signatureLevel;
    ULONG signatureType;
    UNICODE_STRING emptyName;
    PUNICODE_STRING safeName;

    if (ImageInfo == NULL || ImageInfo->SystemModeImage == 0)
    {
        return;
    }

    if (ProcessId != NULL)
    {
        return;
    }

    signatureLevel = ImageInfo->ImageSignatureLevel;
    signatureType = ImageInfo->ImageSignatureType;

    RtlInitUnicodeString(&emptyName, L"<unknown>");
    safeName = (FullImageName != NULL && FullImageName->Buffer != NULL && FullImageName->Length > 0) ? FullImageName : &emptyName;

    if (FullImageName == NULL || FullImageName->Buffer == NULL || FullImageName->Length == 0 || signatureLevel == 0 || signatureType == 0)
    {
        RtlStringCchPrintfW(
            message,
            RTL_NUMBER_OF(message),
            L"Suspicious kernel image load: path=%wZ sigLevel=%lu sigType=%lu base=%p size=0x%Ix",
            safeName,
            signatureLevel,
            signatureType,
            ImageInfo->ImageBase,
            ImageInfo->ImageSize);

        DrvDetectPushAlert(AlertTypeKernelImageSuspicious, 0, message);
        return;
    }

    for (i = 0; i < RTL_NUMBER_OF(g_VulnerableDriverIndicators); i++)
    {
        if (DrvDetectEndsWithInsensitive(FullImageName, g_VulnerableDriverIndicators[i]))
        {
            RtlStringCchPrintfW(
                message,
                RTL_NUMBER_OF(message),
                L"Known vulnerable helper driver loaded: %wZ",
                FullImageName);

            DrvDetectPushAlert(AlertTypeKernelImageSuspicious, 0, message);
            return;
        }
    }
}

static
NTSTATUS
DrvDetectCreateControlDevice(
    _In_ WDFDRIVER Driver
)
{
    NTSTATUS status;
    PWDFDEVICE_INIT deviceInit = NULL;
    WDFDEVICE device;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_FILEOBJECT_CONFIG fileConfig;
    UNICODE_STRING securityDescriptor;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLink;
    WDF_OBJECT_ATTRIBUTES attributes;

    RtlInitUnicodeString(&securityDescriptor, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    deviceInit = WdfControlDeviceInitAllocate(Driver, &securityDescriptor);
    if (deviceInit == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlInitUnicodeString(&deviceName, DRVDETECT_DEVICE_NAME);
    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status))
    {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    WDF_FILEOBJECT_CONFIG_INIT(
        &fileConfig,
        DrvDetectEvtFileCreate,
        DrvDetectEvtFileClose,
        WDF_NO_EVENT_CALLBACK);
    WdfDeviceInitSetFileObjectConfig(deviceInit, &fileConfig, WDF_NO_OBJECT_ATTRIBUTES);

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    status = WdfDeviceCreate(&deviceInit, &attributes, &device);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = DrvDetectEvtIoDeviceControl;

    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status))
    {
        WdfObjectDelete(device);
        return status;
    }

    RtlInitUnicodeString(&symbolicLink, DRVDETECT_DOS_DEVICE_NAME);
    status = WdfDeviceCreateSymbolicLink(device, &symbolicLink);
    if (!NT_SUCCESS(status))
    {
        WdfObjectDelete(device);
        return status;
    }

    g_DrvDetect.ControlDevice = device;
    WdfControlFinishInitializing(device);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
DrvDetectEvtFileCreate(
    WDFDEVICE Device,
    WDFREQUEST Request,
    WDFFILEOBJECT FileObject
)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(FileObject);
    WdfRequestComplete(Request, STATUS_SUCCESS);
}

_Use_decl_annotations_
VOID
DrvDetectEvtFileClose(
    WDFFILEOBJECT FileObject
)
{
    UNREFERENCED_PARAMETER(FileObject);
}

_Use_decl_annotations_
VOID
DrvDetectEvtIoDeviceControl(
    WDFQUEUE Queue,
    WDFREQUEST Request,
    size_t OutputBufferLength,
    size_t InputBufferLength,
    ULONG IoControlCode
)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    size_t bytesReturned = 0;
    DRVDETECT_ALERT* outAlert = NULL;

    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (IoControlCode == IOCTL_DRVDETECT_GET_ALERT)
    {
        if (OutputBufferLength < sizeof(DRVDETECT_ALERT))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            goto Exit;
        }

        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(DRVDETECT_ALERT), (PVOID*)&outAlert, NULL);
        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }

        if (!DrvDetectPopAlert(outAlert))
        {
            status = STATUS_NO_MORE_ENTRIES;
            goto Exit;
        }

        bytesReturned = sizeof(DRVDETECT_ALERT);
        status = STATUS_SUCCESS;
    }

Exit:
    WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}

_Use_decl_annotations_
VOID
DrvDetectEvtDriverUnload(
    WDFDRIVER Driver
)
{
    UNREFERENCED_PARAMETER(Driver);

    if (g_DrvDetect.ProcessNotifyRegistered)
    {
        PsSetCreateProcessNotifyRoutineEx(DrvDetectProcessNotifyEx, TRUE);
        g_DrvDetect.ProcessNotifyRegistered = FALSE;
    }

    if (g_DrvDetect.ProcessNotifyLegacyRegistered)
    {
        PsSetCreateProcessNotifyRoutine(DrvDetectProcessNotifyLegacy, TRUE);
        g_DrvDetect.ProcessNotifyLegacyRegistered = FALSE;
    }

    if (g_DrvDetect.ImageNotifyRegistered)
    {
        PsRemoveLoadImageNotifyRoutine(DrvDetectImageLoadNotify);
        g_DrvDetect.ImageNotifyRegistered = FALSE;
    }

    if (g_DrvDetect.RegistryCallbackRegistered)
    {
        CmUnRegisterCallback(g_DrvDetect.RegistryCookie);
        g_DrvDetect.RegistryCallbackRegistered = FALSE;
    }

    if (g_DrvDetect.ControlDevice != NULL)
    {
        WdfObjectDelete(g_DrvDetect.ControlDevice);
        g_DrvDetect.ControlDevice = NULL;
    }
}

_Use_decl_annotations_
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDFDRIVER driver;

    RtlZeroMemory(&g_DrvDetect, sizeof(g_DrvDetect));
    KeInitializeSpinLock(&g_DrvDetect.AlertLock);
    KeInitializeSpinLock(&g_DrvDetect.ServiceTrackLock);
    DrvDetectPushAlert(
        AlertTypeKernelImageSuspicious,
        0,
        L"DrvDetect build=trace2-controlset loaded.");

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags = WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = DrvDetectEvtDriverUnload;

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);

    status = WdfDriverCreate(DriverObject, RegistryPath, &attributes, &config, &driver);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = DrvDetectCreateControlDevice(driver);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = PsSetCreateProcessNotifyRoutineEx(DrvDetectProcessNotifyEx, FALSE);
    if (NT_SUCCESS(status))
    {
        g_DrvDetect.ProcessNotifyRegistered = TRUE;
    }
    else
    {
        WCHAR msg[220];
        RtlStringCchPrintfW(
            msg,
            RTL_NUMBER_OF(msg),
            L"Process callback Ex failed NTSTATUS=0x%08X. Trying legacy fallback.",
            status);
        DrvDetectPushAlert(AlertTypeKernelImageSuspicious, 0, msg);

        status = PsSetCreateProcessNotifyRoutine(DrvDetectProcessNotifyLegacy, FALSE);
        if (NT_SUCCESS(status))
        {
            g_DrvDetect.ProcessNotifyLegacyRegistered = TRUE;
            DrvDetectPushAlert(
                AlertTypeKernelImageSuspicious,
                0,
                L"Legacy process callback registered (post-create terminate mode).");
        }
        else
        {
            RtlStringCchPrintfW(
                msg,
                RTL_NUMBER_OF(msg),
                L"Legacy process callback failed NTSTATUS=0x%08X.",
                status);
            DrvDetectPushAlert(AlertTypeKernelImageSuspicious, 0, msg);
        }
    }

    status = PsSetLoadImageNotifyRoutine(DrvDetectImageLoadNotify);
    if (NT_SUCCESS(status))
    {
        g_DrvDetect.ImageNotifyRegistered = TRUE;
    }
    else
    {
        DrvDetectPushAlert(AlertTypeKernelImageSuspicious, 0, L"Failed to register image callback.");
    }

    {
        UNICODE_STRING altitude;
        RtlInitUnicodeString(&altitude, L"370030");
        status = CmRegisterCallbackEx(
            DrvDetectRegistryCallback,
            &altitude,
            DriverObject,
            NULL,
            &g_DrvDetect.RegistryCookie,
            NULL);
        if (NT_SUCCESS(status))
        {
            g_DrvDetect.RegistryCallbackRegistered = TRUE;
        }
        else
        {
            WCHAR msg[220];
            RtlStringCchPrintfW(
                msg,
                RTL_NUMBER_OF(msg),
                L"Failed to register registry callback NTSTATUS=0x%08X.",
                status);
            DrvDetectPushAlert(AlertTypeKernelImageSuspicious, 0, msg);
        }
    }

    return STATUS_SUCCESS;
}
