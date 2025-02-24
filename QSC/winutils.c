#include "winutils.h"

#if defined(QSC_SYSTEM_OS_WINDOWS)
#   include "stringutils.h"
#   include <stdbool.h>
#   include <stdlib.h>
#   include <stdio.h>
#   include <string.h>
#   include <tchar.h>
#   include <winsock2.h>
#   include <lm.h>
#   include <ws2tcpip.h>
#   include <psapi.h>
#   include <ShellApi.h>
#   include <tlhelp32.h>
#   define WIN32_LEAN_AND_MEAN
#   include <windows.h>
#   include <iphlpapi.h>
#   pragma comment(lib, "advapi32.lib")
#   pragma comment(lib, "IPHLPAPI.lib")
#   pragma comment(lib, "netapi32.lib")
#   pragma comment(lib, "psapi.lib")
#   if defined(QSC_DEBUG_MODE)
#       include "consoleutils.h"
#       include "fileutils.h"
#   endif

typedef struct AttributeDescription
{
    DWORD attribute;
    const char* description;
} AttributeDescription;

#define WINUTILS_ATTRIBUTE_SIZE 22

static AttributeDescription winutils_attribute_descriptions[WINUTILS_ATTRIBUTE_SIZE] = 
{
    { FILE_ATTRIBUTE_READONLY, "readonly" },
    { FILE_ATTRIBUTE_HIDDEN, "hidden" },
    { FILE_ATTRIBUTE_SYSTEM, "system" },
    { FILE_ATTRIBUTE_DIRECTORY, "directory" },
    { FILE_ATTRIBUTE_ARCHIVE, "archive" },
    { FILE_ATTRIBUTE_DEVICE, "device" },
    { FILE_ATTRIBUTE_NORMAL, "normal" },
    { FILE_ATTRIBUTE_TEMPORARY, "temporary" },
    { FILE_ATTRIBUTE_SPARSE_FILE, "sparse_file" },
    { FILE_ATTRIBUTE_REPARSE_POINT, "reparse_point" },
    { FILE_ATTRIBUTE_COMPRESSED, "compressed" },
    { FILE_ATTRIBUTE_OFFLINE, "offline" },
    { FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, "not_content_indexed" },
    { FILE_ATTRIBUTE_ENCRYPTED, "encrypted" },
    { FILE_ATTRIBUTE_INTEGRITY_STREAM, "integrity_stream" },
    { FILE_ATTRIBUTE_VIRTUAL, "virtual" },
    { FILE_ATTRIBUTE_NO_SCRUB_DATA, "no_scrub_data" },
    { FILE_ATTRIBUTE_EA, "ea" },
    { FILE_ATTRIBUTE_PINNED, "pinned" },
    { FILE_ATTRIBUTE_UNPINNED, "unpinned" },
    { FILE_ATTRIBUTE_RECALL_ON_OPEN, "recall_on_open" },
    { FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, "recall_on_data_access" }
};

typedef struct ErrorDescription
{
    DWORD error;
    const char* description;
} ErrorDescription;

static ErrorDescription winutils_error_descriptions[] = 
{
    { ERROR_BAD_NETPATH, "Error: A network folder is not mapped." },
    { ERROR_TRANSACTIONAL_CONFLICT, "Error: The request is a transactional conflict." },
    { ERROR_MORE_DATA, "Error: The buffer is too small." },
    { ERROR_BUFFER_OVERFLOW, "Error: The buffer is too small." },
    { ERROR_ADDRESS_NOT_ASSOCIATED, "Error: An address has not yet been associated with the network endpoint." },
    { ERROR_INVALID_PARAMETER, "Error: One of the parameters is invalid." },
    { ERROR_NOT_ENOUGH_MEMORY, "Error: Insufficient memory resources are available to complete the operation." },
    { ERROR_NO_DATA, "Error: No addresses were found for the requested parameters." },
    { WSAEAFNOSUPPORT, "Error: The address family specified in the Family parameter is not supported." },
    { ERROR_BAD_LENGTH, "Error: The module was not loaded correctly." },
    { ERROR_ACCESS_DENIED, "Error: Access was denied to the system resource." },
    { ERROR_PARTIAL_COPY, "Error: The module was not loaded correctly." },
    { ERROR_NO_MORE_FILES, "Error: No more files to enumerate." },
    { ERROR_INVALID_HANDLE, "Error: The file handle is invalid." },
    { E_INVALIDARG, "Error: The argument value is invalid." },
    { E_OUTOFMEMORY, "Error: The process is out of memory." },
    { E_UNEXPECTED, "Error: The system encountered an unexpected error." },
    { ERROR_FILE_NOT_FOUND, "Error: The specified file was not found." },
    { ERROR_PATH_NOT_FOUND, "Error: The specified path was not found." },
    { ERROR_BAD_FORMAT, "Error: The .exe file is invalid (non-Win32 .exe or error in .exe image)." },
    { ERROR_DATABASE_DOES_NOT_EXIST, "Error: The specified database does not exist." },
    { ERROR_INVALID_NAME, "Error: The specified service name is invalid." },
    { ERROR_SERVICE_DOES_NOT_EXIST, "Error: The specified service does not exist." },
    { ERROR_DEPENDENT_SERVICES_RUNNING, "Error: The service cannot be stopped because other running services are dependent on it." },
    { ERROR_INVALID_SERVICE_CONTROL, "Error: The requested control code is not valid, or it is unacceptable to the service." },
    { ERROR_SERVICE_CANNOT_ACCEPT_CTRL, "Error: The requested control code cannot be sent to the service." },
    { ERROR_SERVICE_NOT_ACTIVE, "Error: The service has not been started." },
    { ERROR_SERVICE_REQUEST_TIMEOUT, "Error: The process for the service was started, but it did not call the dispatcher." },
    { ERROR_SHUTDOWN_IN_PROGRESS, "Error: The system is shutting down." },
    { ERROR_INVALID_LEVEL, "Error: The InfoLevel parameter contains an unsupported value." },
    { NERR_BufTooSmall, "Error: The buffer is too small to contain an entry." },
    { NERR_InvalidComputer, "Error: The computer name is invalid." },
    { NERR_UserNotFound, "Error: The user name could not be found." }
};

static const char WINUTILS_SERVICE_STATE_STRINGS[9][12] =
{
    "Stopped",
    "Starting",
    "Stopping",
    "Running",
    "Continuing",
    "Pausing",
    "Paused",
    "Unknown"
};

static DWORD winutils_attribute_from_string(const char* attr) 
{
    DWORD res;

    if (strcmp(attr, "readonly") == 0)
    {
        res = FILE_ATTRIBUTE_READONLY;
    }
    else if (strcmp(attr, "hidden") == 0)
    {
        res = FILE_ATTRIBUTE_HIDDEN;
    }
    else if (strcmp(attr, "system") == 0)
    {
        res = FILE_ATTRIBUTE_SYSTEM;
    }
    else if (strcmp(attr, "archive") == 0)
    {
        res = FILE_ATTRIBUTE_ARCHIVE;
    }
    else if (strcmp(attr, "normal") == 0)
    {
        res = FILE_ATTRIBUTE_NORMAL;
    }
    else if (strcmp(attr, "temporary") == 0)
    {
        res = FILE_ATTRIBUTE_TEMPORARY;
    }
    else if (strcmp(attr, "offline") == 0)
    {
        res = FILE_ATTRIBUTE_OFFLINE;
    }
    else if (strcmp(attr, "not_content_indexed") == 0)
    {
        res = FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
    }
    else if (strcmp(attr, "encrypted") == 0)
    {
        res = FILE_ATTRIBUTE_ENCRYPTED;
    }
    else
    {
        res = INVALID_FILE_ATTRIBUTES;
    }

    return res;
}

static uint32_t winutils_process_pid_from_name(const char* name) 
{
    PROCESSENTRY32 pe32 = { 0 };
    HANDLE snap;
    uint32_t pid;

    pid = 0;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snap != INVALID_HANDLE_VALUE)
    {
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snap, &pe32) == true)
        {
            while (true)
            {
                if (strcmp(pe32.szExeFile, name) == 0)
                {
                    pid = pe32.th32ProcessID;
                    break;
                }

                if (Process32Next(snap, &pe32) == false)
                {
                    break;
                }
            };

            if (snap != 0)
            {
                CloseHandle(snap);
            }
        }
    }

    return pid;
}

static HKEY winutils_rkey_from_string(const char* root) 
{
    HKEY res;

    if (strcmp(root, "HKEY_CLASSES_ROOT") == 0)
    {
        res = HKEY_CLASSES_ROOT;
    }
    else if (strcmp(root, "HKEY_CURRENT_USER") == 0)
    {
        res = HKEY_CURRENT_USER;
    }
    else if (strcmp(root, "HKEY_LOCAL_MACHINE") == 0)
    {
        res = HKEY_LOCAL_MACHINE;
    }
    else if (strcmp(root, "HKEY_USERS") == 0)
    {
        res = HKEY_USERS;
    }
    else if (strcmp(root, "HKEY_CURRENT_CONFIG") == 0)
    {
        res = HKEY_CURRENT_CONFIG;
    }
    else
    {
        res = NULL;
    }

    return res;
}

static void winutils_get_error_description(char* result, size_t reslen)
{
    const char* desc;
    DWORD err;

    desc = NULL;
    err = GetLastError();

    if (err != 0)
    {
        for (size_t i = 0; i < sizeof(winutils_error_descriptions); ++i)
        {
            if (err == winutils_error_descriptions[i].error)
            {
                desc = winutils_error_descriptions[i].description;
                break;
            }
        }
    }

    if (desc != NULL)
    {
        qsc_stringutils_concat_strings(result, reslen, desc);
    }
    else
    {
        qsc_stringutils_concat_strings(result, reslen, "Error: The operation encountered an error.");
    }
}

static const char* winutils_service_state_to_string(DWORD state)
{
    const char* ret;

    ret = NULL;

    if (state > 0 && state <= SERVICE_PAUSED)
    {
        ret = WINUTILS_SERVICE_STATE_STRINGS[(size_t)state - 1];
    }

    return ret;
}

size_t qsc_winutils_file_get_attributes(char* result, size_t reslen, const char* path) 
{
    assert(result != NULL);
    assert(reslen != 0);
    assert(path != NULL);

    size_t tlen;
    DWORD attr;

    tlen = 0;
    attr = GetFileAttributesA(path);

    if (attr != INVALID_FILE_ATTRIBUTES)
    {
        bool first;

        first = true;

        for (size_t i = 0; i < WINUTILS_ATTRIBUTE_SIZE; ++i)
        {
            if (attr & winutils_attribute_descriptions[i].attribute)
            {
                size_t dlen;

                dlen = strlen(winutils_attribute_descriptions[i].description);

                if (tlen + dlen + (first ? 0 : 1) < reslen)
                {
                    if (!first)
                    {
                        strcat_s(result, reslen, ", ");
                        tlen += 2;
                    }

                    strcat_s(result, reslen, winutils_attribute_descriptions[i].description);
                    tlen += dlen;
                    first = false;
                }
                else
                {
                    break;
                }
            }
        }
    }

    return tlen;
}

bool qsc_winutils_file_set_attribute(const char* path, const char* attr)
{
    assert(path != NULL);
    assert(attr != NULL);

    DWORD datt;
    bool res;

    res = false;
    datt = winutils_attribute_from_string(attr);

    if (datt != INVALID_FILE_ATTRIBUTES)
    {
        res = SetFileAttributesA(path, datt);
    }

    return res;
}

size_t qsc_winutils_network_statistics(char* result, size_t reslen)
{
    assert(result != NULL);
    assert(reslen != 0);
    
    char cbuf[QSC_WINTOOLS_NETSTAT_NAME_SIZE] = { 0 };
    size_t tlen;
    ULONG ufam;
    ULONG ulen;
    PIP_ADAPTER_ADDRESSES padd;
    DWORD nlen;
    DWORD rval;

    tlen = 0;
    nlen = QSC_WINTOOLS_NETSTAT_NAME_SIZE;

    if (GetComputerNameExA(ComputerNameDnsDomain, cbuf, &nlen) == true)
    {
        if (nlen > 0)
        {
            tlen += snprintf(result + tlen, reslen - tlen, "Domain Name -%s\n", cbuf);
        }
        else
        {
            tlen += snprintf(result + tlen, reslen - tlen, "Domain Name -Unknown\n");
        }
    } 
    else
    {
        tlen += snprintf(result + tlen, reslen - tlen, "Domain Name -Unknown\n");
    }

    memset(cbuf, 0, sizeof(cbuf));
    nlen = QSC_WINTOOLS_NETSTAT_NAME_SIZE;

    if (GetComputerNameA(cbuf, &nlen) == true) 
    {
        if (nlen > 0)
        {
            tlen += snprintf(result + tlen, reslen - tlen, "Host Name -%s\n", cbuf);
        }
        else
        {
            tlen += snprintf(result + tlen, reslen - tlen, "Host Name -Unknown\n");
        }
    }
    else 
    {
        tlen += snprintf(result + tlen, reslen - tlen, "Host Name -Unknown\n");
    }

    ufam = AF_UNSPEC;
    ulen = 15000;
    padd = (IP_ADAPTER_ADDRESSES*)malloc(ulen);

    if (padd != NULL)
    {
        rval = GetAdaptersAddresses(ufam, 0, NULL, padd, &ulen);

        if (rval == ERROR_BUFFER_OVERFLOW)
        {
            padd = (IP_ADAPTER_ADDRESSES*)realloc(padd, ulen);

            if (padd == NULL)
            {
                tlen += snprintf(result + tlen, reslen - tlen, "Failed to allocate memory for adapter addresses\n");
                return tlen;
            }

            rval = GetAdaptersAddresses(ufam, 0, NULL, padd, &ulen);
        }

        if (rval == NO_ERROR)
        {
            PIP_ADAPTER_ADDRESSES cadd = padd;

            while (cadd)
            {
                tlen += snprintf(result + tlen, reslen - tlen, "\n");
                PIP_ADAPTER_UNICAST_ADDRESS puni = cadd->FirstUnicastAddress;

                tlen += snprintf(result + tlen, reslen - tlen, "Adaptor Name: \t\t%wS\n", padd->FriendlyName);
                tlen += snprintf(result + tlen, reslen - tlen, "Description: \t\t-%wS\n", padd->Description);
                tlen += snprintf(result + tlen, reslen - tlen, "Identifier: \t\t-%s\n", padd->AdapterName);
                tlen += snprintf(result + tlen, reslen - tlen, "Interface Addresses\n");

                while (puni)
                {
                    if (puni->Address.lpSockaddr->sa_family == AF_INET)
                    {
                        struct sockaddr_in* sa_in = (struct sockaddr_in*)puni->Address.lpSockaddr;

                        inet_ntop(AF_INET, &(sa_in->sin_addr), cbuf, sizeof(cbuf));
                        tlen += snprintf(result + tlen, reslen - tlen, "Ipv4 Address \t\t-%s\n", cbuf);
                    }
                    else if (puni->Address.lpSockaddr->sa_family == AF_INET6)
                    {
                        struct sockaddr_in6* sa_in6 = (struct sockaddr_in6*)puni->Address.lpSockaddr;

                        inet_ntop(AF_INET6, &(sa_in6->sin6_addr), cbuf, sizeof(cbuf));
                        tlen += snprintf(result + tlen, reslen - tlen, "Ipv6 Address \t\t-%s\n", cbuf);
                    }

                    puni = puni->Next;
                }

                PIP_ADAPTER_GATEWAY_ADDRESS_LH pgate = cadd->FirstGatewayAddress;

                if (pgate != NULL)
                {
                    tlen += snprintf(result + tlen, reslen - tlen, "Gateway Addresses\n");

                    while (pgate)
                    {
                        if (pgate->Address.lpSockaddr->sa_family == AF_INET)
                        {
                            struct sockaddr_in* sa_in = (struct sockaddr_in*)pgate->Address.lpSockaddr;

                            inet_ntop(AF_INET, &(sa_in->sin_addr), cbuf, sizeof(cbuf));
                            tlen += snprintf(result + tlen, reslen - tlen, "Gateway \t\t-%s\n", cbuf);
                        }
                        else if (pgate->Address.lpSockaddr->sa_family == AF_INET6)
                        {
                            struct sockaddr_in6* sa_in6 = (struct sockaddr_in6*)pgate->Address.lpSockaddr;

                            inet_ntop(AF_INET6, &(sa_in6->sin6_addr), cbuf, sizeof(cbuf));
                            tlen += snprintf(result + tlen, reslen - tlen, "Gateway \t\t-%s\n", cbuf);
                        }

                        pgate = pgate->Next;
                    }
                }

                PIP_ADAPTER_DNS_SERVER_ADDRESS pdns = cadd->FirstDnsServerAddress;

                if (pdns != NULL)
                {
                    tlen += snprintf(result + tlen, reslen - tlen, "DNS Server Addresses\n");

                    while (pdns)
                    {
                        if (pdns->Address.lpSockaddr->sa_family == AF_INET)
                        {
                            struct sockaddr_in* sa_in = (struct sockaddr_in*)pdns->Address.lpSockaddr;

                            inet_ntop(AF_INET, &(sa_in->sin_addr), cbuf, sizeof(cbuf));
                            tlen += snprintf(result + tlen, reslen - tlen, "DNS Server \t\t-%s\n", cbuf);
                        }
                        else if (pdns->Address.lpSockaddr->sa_family == AF_INET6)
                        {
                            struct sockaddr_in6* sa_in6 = (struct sockaddr_in6*)pdns->Address.lpSockaddr;

                            inet_ntop(AF_INET6, &(sa_in6->sin6_addr), cbuf, sizeof(cbuf));
                            tlen += snprintf(result + tlen, reslen - tlen, "DNS Server \t\t-%s\n", cbuf);
                        }

                        pdns = pdns->Next;
                    }
                }

                cadd = cadd->Next;
            }
        }
        else
        {
            tlen += snprintf(result + tlen, reslen - tlen, "Failed to get network addresses\n");
        }

        free(padd);
    }
    else
    {
        tlen += snprintf(result + tlen, reslen - tlen, "Failed to allocate memory for adapter addresses\n");
    }

    if (tlen == 0)
    {
        winutils_get_error_description(result, reslen);
    }

    return tlen;
}

size_t qsc_winutils_process_list(char* result, size_t reslen) 
{
    assert(result != NULL);
    assert(reslen != 0);
    
    PROCESSENTRY32 pe32 = { 0 };
    char pname[MAX_PATH] = { 0 };
    char pdesc[MAX_PATH] = { 0 };
    HANDLE hsnap;
    HANDLE hproc;
    size_t slen;

    slen = 0;

    if (result != NULL || reslen != 0)
    {
        hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (hsnap != INVALID_HANDLE_VALUE)
        {
            pe32.dwSize = sizeof(PROCESSENTRY32);

            if (Process32First(hsnap, &pe32) == true)
            {
                while (true)
                {
                    int32_t btw;

                    strncpy_s(pname, sizeof(pname), pe32.szExeFile, _TRUNCATE);
                    hproc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);

                    if (hproc != NULL)
                    {
                        HMODULE hmod;
                        DWORD cbn;

                        if (EnumProcessModules(hproc, &hmod, sizeof(hmod), &cbn) > 0) 
                        {
                            GetModuleBaseNameA(hproc, hmod, pdesc, sizeof(pdesc));
                        }

                        CloseHandle(hproc);
                    }

                    if (strlen(pdesc) < 2)
                    {
                        strncpy_s(pdesc, sizeof(pdesc), "[System Process]", _TRUNCATE);
                    }

                    btw = snprintf(result + slen, reslen - slen, "%s\t%s\n", pname, pdesc);

                    if (btw < 0 || btw >= (int32_t)(reslen - slen))
                    {
                        break;
                    }

                    slen += btw;

                    if (Process32Next(hsnap, &pe32) == false)
                    {
                        break;
                    }
                };
            }

            if (hsnap != 0)
            {
                CloseHandle(hsnap);
            }
        }
    }

    if (slen == 0)
    {
        winutils_get_error_description(result, reslen);
    }

    return slen;
}

bool qsc_winutils_process_token_elevate()
{
    HANDLE htok;
    LUID luid = { 0 };
    TOKEN_PRIVILEGES tpriv = { 0 };
    BOOL status;
    bool res;

    htok = 0;
    res = false;

    status = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &htok);
    
    if (status == TRUE)
    {
        if (LookupPrivilegeValue(NULL, SE_CHANGE_NOTIFY_NAME, &luid) == true) //SeChangeNotifyPrivilegeSE_DEBUG_NAME
        {
            tpriv.PrivilegeCount = 1;
            tpriv.Privileges[0].Luid = luid;

            if (AdjustTokenPrivileges(htok, FALSE, &tpriv, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL) == true)
            {
                res = true;
            }
            else
            {
                printf("AdjustTokenPrivileges error: %u\n", GetLastError());
            }
        }
    }
    
    return res;
}

bool qsc_winutils_process_terminate(const char* name) 
{
    assert(name != NULL);
    
    HANDLE hproc;
    DWORD dwexit;
    uint32_t pid;
    bool res;

    res = false;
    pid = winutils_process_pid_from_name(name);

    if (pid != 0)
    {
        hproc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, false, pid);

        if (hproc != NULL)
        {
            if (GetExitCodeProcess(hproc, &dwexit) == true)
            {
                res = TerminateProcess(hproc, dwexit);
            }

            CloseHandle(hproc);
        }
    }

    return res;
}

bool qsc_winutils_registry_key_add(const char* keypath, const char* value, qsc_winutils_registry_value_types vtype)
{
    assert(keypath != NULL);
    assert(value != 0);
    
    HKEY hkey = { 0 };
    HKEY rkey = { 0 };
    char lpath[QSC_WINTOOLS_REGISTRY_BUFFER_SIZE] = { 0 };
    char* root;
    char* ct;
    LONG lres;
    DWORD disp;
    char* subkey;

    ct = NULL;
    lres = 0;
    strncpy_s(lpath, sizeof(lpath), keypath, strlen(keypath));
    root = strtok_s(lpath, "\\", &ct);
    subkey = strtok_s(NULL, "", &ct);
    rkey = winutils_rkey_from_string(root);

    if (rkey != NULL)
    {
        lres = RegCreateKeyExA(rkey, subkey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkey, &disp);

        if (lres == ERROR_SUCCESS)
        {
            switch (vtype)
            {
                case REG_SZ_TYPE:
                {
                    lres = RegSetValueExA(hkey, NULL, 0, REG_SZ, (const BYTE*)value, (DWORD)strlen(value) + 1);
                    break;
                }
                case REG_DWORD_TYPE:
                {
                    DWORD dval;

                    dval = (DWORD)strtoul(value, NULL, 0);
                    lres = RegSetValueExA(hkey, NULL, 0, REG_DWORD, (const BYTE*)&dval, sizeof(dval));
                    break;
                }
                case REG_QWORD_TYPE:
                {
                    ULONGLONG qval;

                    qval = (ULONGLONG)_strtoui64(value, NULL, 0);
                    lres = RegSetValueExA(hkey, NULL, 0, REG_QWORD, (const BYTE*)&qval, sizeof(qval));
                    break;
                }
                case REG_BINARY_TYPE:
                {
                    size_t slen;
                    BYTE* bval;

                    slen = strlen(value);
                    bval = (BYTE*)malloc(slen / 2);

                    if (bval != NULL)
                    {
                        for (size_t i = 0; i < slen / 2; ++i)
                        {
                            sscanf_s(value + 2 * i, "%2hhx", &bval[i]);
                        }

                        lres = RegSetValueExA(hkey, NULL, 0, REG_BINARY, bval, (DWORD)(slen / 2));
                        free(bval);
                    }

                    break;
                }
                default:
                {
                }
            }

            RegCloseKey(hkey);
        }
    }

    return (lres == ERROR_SUCCESS);
}

bool qsc_winutils_registry_key_delete(const char* keypath) 
{
    assert(keypath != NULL);
    
    HKEY rkey = { 0 };
    char lpath[QSC_WINTOOLS_REGISTRY_BUFFER_SIZE] = { 0 };
    char* ct;
    char* root;
    char* subkey;
    LSTATUS lret;

    ct = NULL;
    lret = ERROR_INVALID_DATA;

    strncpy_s(lpath, sizeof(lpath), keypath, strlen(keypath));
    root = strtok_s(lpath, "\\", &ct);
    subkey = strtok_s(NULL, "", &ct);
    rkey = winutils_rkey_from_string(root);

    if (rkey != NULL)
    {
        lret = RegDeleteKey(rkey, subkey);
    }

    return (lret == ERROR_SUCCESS);
}

size_t qsc_winutils_registry_key_list(char* result, size_t reslen, const char* keypath) 
{
    assert(result != NULL);
    assert(reslen != 0);
    assert(keypath != NULL);

    HKEY hkey = { 0 };
    HKEY rkey = { 0 };
    FILETIME lft = { 0 };
    char kname[QSC_WINTOOLS_REGISTRY_BUFFER_SIZE] = { 0 };
    char lpath[QSC_WINTOOLS_REGISTRY_BUFFER_SIZE] = { 0 };
    char* ct;
    char* root;
    char* subkey;
    DWORD ctr;
    DWORD klen;
    DWORD lres;
    size_t tlen;

    ct = NULL;
    ctr = 0;
    tlen = 0;

    strncpy_s(lpath, sizeof(lpath), keypath, strlen(keypath));
    root = strtok_s(lpath, "\\", &ct);
    subkey = strtok_s(NULL, "", &ct);

    rkey = winutils_rkey_from_string(root);

    if (rkey != NULL)
    {
        lres = RegOpenKeyExA(rkey, subkey, 0, KEY_READ, &hkey);

        if (lres == ERROR_SUCCESS)
        {
            while (true)
            {
                klen = sizeof(kname);
                lres = RegEnumKeyExA(hkey, ctr, kname, &klen, NULL, NULL, NULL, &lft);
                ++ctr;

                if (lres == ERROR_SUCCESS)
                {
                    SYSTEMTIME tm = { 0 };
                    char kbuf[QSC_WINTOOLS_REGISTRY_BUFFER_SIZE] = { 0 };
                    size_t lpos;

                    lpos = sprintf_s(kbuf, sizeof(kbuf), "%s\t", kname);

                    FileTimeToSystemTime(&lft, &tm);
                    sprintf_s(kbuf + lpos, sizeof(kbuf) - lpos, "%02d-%02d-%d %02d:%02d:%02d\n",
								tm.wMonth, tm.wDay, tm.wYear, tm.wHour, tm.wMinute, tm.wSecond);

                    if (tlen + strlen(kbuf) > reslen)
                    {
                        break;
                    }

                    strcat_s(result, reslen, kbuf);
                    tlen += strlen(kbuf);
                }
                else
                {
                    break;
                }
            }

            RegCloseKey(hkey);
        }
    }
    
    if (tlen == 0)
    {
        winutils_get_error_description(result, reslen);
    }

    return tlen;
}

bool qsc_winutils_run_executable(const char* expath) 
{
    assert(expath != NULL);
    
    HRESULT hres;
    HINSTANCE pret;
    bool res;

    res = false;
    hres = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    if (hres == S_OK)
    {
        pret = ShellExecuteA(GetDesktopWindow(), "open", expath, NULL, NULL, SW_SHOW);
        res = ((INT_PTR)pret > 32);
    }

    return res;
}

bool qsc_winutils_run_as_user(const char* user, const char* password, const char* expath)
{
    assert(user != NULL);
    assert(password != 0);
    assert(expath != NULL);

    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    wchar_t wuser[QSC_WINTOOLS_RUNAS_BUFFER_SIZE] = { 0 };
    wchar_t wpass[QSC_WINTOOLS_RUNAS_BUFFER_SIZE] = { 0 };
    wchar_t wpath[QSC_WINTOOLS_RUNAS_BUFFER_SIZE] = { 0 };
    wchar_t wdomain[sizeof(wchar_t)] = L".";
    bool res;

    MultiByteToWideChar(CP_ACP, 0, user, -1, wuser, QSC_WINTOOLS_RUNAS_BUFFER_SIZE);
    MultiByteToWideChar(CP_ACP, 0, password, -1, wpass, QSC_WINTOOLS_RUNAS_BUFFER_SIZE);
    MultiByteToWideChar(CP_ACP, 0, expath, -1, wpath, QSC_WINTOOLS_RUNAS_BUFFER_SIZE);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    res = CreateProcessWithLogonW(
        wuser,
        wdomain,
        wpass,
        LOGON_WITH_PROFILE,
        NULL,
        wpath,
        CREATE_UNICODE_ENVIRONMENT,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (res == true)
    {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } 

    return res;
}

bool qsc_winutils_service_state(const char* name, qsc_winutils_service_states estate) 
{
    assert(name != NULL);
    
    SERVICE_STATUS_PROCESS ssp = { 0 };
    SC_HANDLE scm;
    SC_HANDLE sch;
    bool res;
    
    res = false;
    scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (scm != NULL)
    {
        sch = OpenServiceA(scm, name, SERVICE_ALL_ACCESS);
        
        if (sch != NULL)
        {
            switch (estate) 
            {
                case QSC_WINUTILS_SERVICE_START:
                {
                    res = StartServiceA(sch, 0, NULL);
                    break;
                }
                case QSC_WINUTILS_SERVICE_STOP:
                {
                    res = ControlService(sch, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp);
                    break;
                }
                case QSC_WINUTILS_SERVICE_PAUSE:
                {
                    res = ControlService(sch, SERVICE_CONTROL_PAUSE, (LPSERVICE_STATUS)&ssp);
                    break;
                }
                case QSC_WINUTILS_SERVICE_RESUME:
                {
                    res = ControlService(sch, SERVICE_CONTROL_CONTINUE, (LPSERVICE_STATUS)&ssp);
                    break;
                }
                default:
                {
                    break;
                }
            }

            CloseServiceHandle(sch);
        }

        CloseServiceHandle(scm);
    }

    return res;
}

size_t qsc_winutils_service_list(char* result, size_t reslen) 
{
    assert(result != NULL);
    assert(reslen != 0);
    
    SC_HANDLE sch = { 0 };
    ENUM_SERVICE_STATUS_PROCESS* pinfo;
    DWORD dexp;
    DWORD dret;
    DWORD hres;
    DWORD llen;
    size_t tlen;
    bool res;

    dexp = 0;
    dret = 0;
    hres = 0;
    llen = 0;
    tlen = 0;

    sch = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);

    if (sch != NULL)
    {
        llen = (DWORD)qsc_winutils_service_list_size();

        if (llen > 0)
        {
            pinfo = (ENUM_SERVICE_STATUS_PROCESS*)malloc(llen);

            if (pinfo != NULL)
            {
                res = EnumServicesStatusEx(
                    sch,
                    SC_ENUM_PROCESS_INFO,
                    SERVICE_WIN32,
#if defined(QSC_WINTOOLS_SERVICE_LIST_ACTIVE_ONLY)
                    SERVICE_ACTIVE,
#else
                    SERVICE_STATE_ALL,
#endif
                    (LPBYTE)pinfo,
                    llen,
                    &dexp,
                    &dret,
                    &hres,
                    NULL);

                if (pinfo != NULL && res == true)
                {
                    for (DWORD i = 0; i < dret; i++)
                    {
                        char sbuf[QSC_WINTOOLS_SERVICE_BUFFER_SIZE] = { 0 };
                        size_t elen;

#if !defined(QSC_WINTOOLS_SERVICE_LIST_ACTIVE_ONLY)
                        const char* pstr;
                        DWORD dwp;

                        dwp = pinfo[i].ServiceStatusProcess.dwCurrentState;
                        pstr = winutils_service_state_to_string(dwp);

                        if (pstr == NULL)
                        {
                            pstr = WINUTILS_SERVICE_STATE_STRINGS[8];
                        }                        
#endif

#if defined(QSC_WINTOOLS_SERVICE_LIST_DESCRIPTION)
#   if defined(QSC_WINTOOLS_SERVICE_LIST_ACTIVE_ONLY)
                        snprintf(sbuf, QSC_WINTOOLS_SERVICE_LIST_SIZE, "%s%s\n", pinfo[i].lpServiceName, pinfo[i].lpDisplayName);
#   else
                        snprintf(sbuf, QSC_WINTOOLS_SERVICE_LIST_SIZE, "%s\t%s\t%s\n", pinfo[i].lpServiceName, pinfo[i].lpDisplayName, pstr);
#   endif
#else
#   if defined(QSC_WINTOOLS_SERVICE_LIST_ACTIVE_ONLY)
                        snprintf(sbuf, QSC_WINTOOLS_SERVICE_LIST_SIZE, "%s\n", pinfo[i].lpServiceName);
#   else
                        snprintf(sbuf, QSC_WINTOOLS_SERVICE_LIST_SIZE, "%s\t%s\n", pinfo[i].lpServiceName, pstr);
#   endif
#endif

                        elen = strlen(sbuf);

                        if (tlen + elen > reslen)
                        {
                            break;
                        }

                        strcat_s(result, reslen, sbuf);
                        tlen += elen;
                    }
                }

                free(pinfo);
            }
        }

        CloseServiceHandle(sch);
    }
    
    if (tlen == 0)
    {
        winutils_get_error_description(result, reslen);
    }

    return tlen;
}

size_t qsc_winutils_service_list_size()
{
    SC_HANDLE sch = { 0 };
    DWORD dexp;
    DWORD dret;
    DWORD hres;
    size_t tlen;
    bool res;

    dexp = 0;
    dret = 0;
    hres = 0;
    tlen = 0;
    res = false;

    sch = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);

    if (sch != NULL)
    {
        res = EnumServicesStatusExA(
            sch,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
#if defined(QSC_WINTOOLS_SERVICE_LIST_ACTIVE_ONLY)
            SERVICE_ACTIVE,
#else
            SERVICE_STATE_ALL,
#endif
            NULL,
            0,
            &dexp,
            &dret,
            &hres,
            NULL);

        tlen = (size_t)dexp + (dret * 12) + 1;

        CloseServiceHandle(sch);
    }

    return tlen;
}

size_t qsc_winutils_user_list(char* result, size_t reslen) 
{
    assert(result != NULL);
    assert(reslen != 0);
    
    USER_INFO_1* pbuf;
    DWORD derd;
    DWORD dlvl;
    DWORD prem;
    DWORD resh;
    DWORD tote;
    NET_API_STATUS stat;
    size_t tlen;

    pbuf = NULL;
    derd = 0;
    dlvl = 1;
    prem = MAX_PREFERRED_LENGTH;
    resh = 0;
    tlen = 0;
    tote = 0;

    do {
        stat = NetUserEnum(
            NULL,
            dlvl,
            FILTER_NORMAL_ACCOUNT,
            (LPBYTE*)&pbuf,
            prem,
            &derd,
            &tote,
            &resh);

        if ((pbuf != NULL) && (stat == NERR_Success) || (stat == ERROR_MORE_DATA))
        {
            USER_INFO_1 *ptmp;
            DWORD pctr;

            ptmp = pbuf;

            for (pctr = 0; (pctr < derd) && (tlen < reslen); ++pctr) 
            {
                char uname[UNLEN + 1] = { 0 };
                size_t nlen;
                size_t olen;

                if (tlen >= reslen)
                {
                    break;
                }

                nlen = wcslen(ptmp->usri1_name);
                olen = 0;
                wcstombs_s(&olen, uname, sizeof(uname), ptmp->usri1_name, nlen);

                if (ptmp->usri1_priv == USER_PRIV_ADMIN)
                {
                    tlen += snprintf(result + tlen, reslen - tlen, "%s %s -%s\n", "User Name:", uname, "Administrator");
                }
                else if (ptmp->usri1_priv == USER_PRIV_GUEST)
                {
                    tlen += snprintf(result + tlen, reslen - tlen, "%s %s -%s\n", "User Name:", uname, "Guest");
                }
                else
                {
                    tlen += snprintf(result + tlen, reslen - tlen, "%s %s -%s\n", "User Name:", uname, "User");
                }

                ++ptmp;
            }
        }

        if (pbuf != NULL) 
        {
            NetApiBufferFree(pbuf);
            pbuf = NULL;
        }
    } 
    while (stat == ERROR_MORE_DATA);
    
    if (tlen == 0)
    {
        winutils_get_error_description(result, reslen);
    }

    return tlen;
}

size_t qsc_winutils_current_user(char* result, size_t reslen)
{
    assert(result != NULL);
    assert(reslen != 0);
    
    char uname[UNLEN + 1] = { 0 };
    size_t tlen;
    DWORD ulen;

    tlen = 0;
    ulen = UNLEN + 1;
    
    if (GetUserNameA(uname, &ulen) == true)
    {
        USER_INFO_1* uinfo = { 0 };
        wchar_t wuser[UNLEN + 1] = { 0 };
        NET_API_STATUS stat;
        size_t olen;

        olen = 0;
        mbstowcs_s(&olen, wuser, ulen, uname, sizeof(uname));
        stat = NetUserGetInfo(NULL, wuser, 1, (LPBYTE*)&uinfo);

        if (stat == NERR_Success)
        {
            if (uinfo->usri1_priv == USER_PRIV_ADMIN)
            {
                tlen = snprintf(result, reslen, "%s %s -%s", "User Name:", uname, "Administrator");
            }
            else if (uinfo->usri1_priv == USER_PRIV_GUEST)
            {
                tlen = snprintf(result, reslen, "%s %s -%s", "User Name:", uname, "Guest");
            }
            else
            {
                tlen = snprintf(result, reslen, "%s %s -%s", "User Name:", uname, "User");
            }

            NetApiBufferFree(uinfo);
        }
    }
    
    if (tlen == 0)
    {
        winutils_get_error_description(result, reslen);
    }

    return (tlen > 0);
}

#if defined(QSC_DEBUG_MODE)
void qsc_winutils_test()
{
    FILE* fp;
    char msg[] = "This is a test file.";
    char path[] = "C:\\Users\\Public\\test.txt";
    char sbuf[QSC_WINTOOLS_SERVICE_LIST_SIZE] = { 0 };
    size_t rlen;

    /* file attributes */

    qsc_consoleutils_print_line("Testing the file attribute functions.");

    qsc_fileutils_create(path);
    fp = qsc_fileutils_open(path, qsc_fileutils_mode_write, false);

    if (fp != NULL)
    {
        qsc_fileutils_write(msg, sizeof(msg), 0, fp);
        qsc_fileutils_close(fp);
        qsc_consoleutils_print_line("Created a test file.");

        if (qsc_winutils_file_set_attribute(path, "readonly"))
        {
            qsc_consoleutils_print_line("The readonly attribute was applied.");
        }
        else
        {
            qsc_consoleutils_print_line("The readonly attribute could not be applied.");
        }

        rlen = qsc_winutils_file_get_attributes(sbuf, sizeof(sbuf), path);

        if (rlen > 0)
        {
            qsc_consoleutils_print_safe("file attributes: ");
            qsc_consoleutils_print_line(sbuf);
        }
        else
        {
            qsc_consoleutils_print_line("The get attribute function has failed.");

        }

        qsc_stringutils_clear_string(sbuf);
    }
    else
    {
        qsc_consoleutils_print_line("The file could not be created.");
    }

    /* network attributes */

    qsc_consoleutils_print_line("Testing network statistics.");

    rlen = qsc_winutils_network_statistics(sbuf, sizeof(sbuf));

    if (rlen > 0)
    {
        qsc_consoleutils_print_line(sbuf);
    }
    else
    {
        qsc_consoleutils_print_line("The network statistics function has failed.");
    }

    qsc_stringutils_clear_string(sbuf);

    /* system process */

    qsc_consoleutils_print_line("Testing process list function.");

    rlen = qsc_winutils_process_list(sbuf, sizeof(sbuf));

    if (rlen > 0)
    {
        qsc_consoleutils_print_line(sbuf);
    }
    else
    {
        qsc_consoleutils_print_line("The process list function has failed.");
    }

    qsc_stringutils_clear_string(sbuf);

    qsc_consoleutils_print_line("Testing the run function.");

    if (qsc_winutils_run_executable(path) == true)
    {
        if (qsc_winutils_process_terminate("Notepad.exe") == true)
        {
            qsc_consoleutils_print_line("The process was terminated.");
        }
        else
        {
            qsc_consoleutils_print_line("Could not terminate the process.");
        }

        if (qsc_fileutils_delete(path) == true)
        {
            qsc_consoleutils_print_line("Deleted the test file.");
        }
        else
        {
            qsc_consoleutils_print_line("Could not delete the test file.");
        }
    }
    else
    {
        qsc_consoleutils_print_line("The executable could not be run.");
    }
    
    /* system registry */

    qsc_consoleutils_print_line("Testing the system registry functions.");

    rlen = qsc_winutils_registry_key_list(sbuf, sizeof(sbuf), "HKEY_CURRENT_USER\\Software");

    if (rlen > 0)
    {
        qsc_consoleutils_print_line(sbuf);
    }
    else
    {
        qsc_consoleutils_print_line("The registry could not be read.");
    }

    qsc_stringutils_clear_string(sbuf);

    if (qsc_winutils_registry_key_add("HKEY_CURRENT_USER\\Software\\PQS", "test", REG_SZ_TYPE) == true)
    {
        qsc_consoleutils_print_line("The key was added to the registry.");

        if (qsc_winutils_registry_key_delete("HKEY_CURRENT_USER\\Software\\PQS") == true)
        {
            qsc_consoleutils_print_line("The key was deleted from the registry.");
        }
        else
        {
            qsc_consoleutils_print_line("The key could not be deleted from the registry.");
        }
    }
    else
    {
        qsc_consoleutils_print_line("The key could not be added to the registry.");
    }

    /* system services */
    
    qsc_consoleutils_print_line("Testing the system service functions.");

    rlen = qsc_winutils_service_list(sbuf, sizeof(sbuf));

    if (rlen > 0)
    {
        qsc_consoleutils_print_line(sbuf);
    }
    else
    {
        qsc_consoleutils_print_line("The service list function failed.");
    }

    /* User specific function. */ 
    qsc_stringutils_clear_string(sbuf);

    if (qsc_winutils_service_state("WpcMonSvc", QSC_WINUTILS_SERVICE_START) == true)
    {
        qsc_consoleutils_print_line("The Parental Controls service was started.");

        if (qsc_winutils_service_state("WpcMonSvc", QSC_WINUTILS_SERVICE_STOP) == true)
        {
            qsc_consoleutils_print_line("The Parental Controls service was stopped.");
        }
        else
        {
            qsc_consoleutils_print_line("The Parental Controls service could not be stopped or is shutting down.");
        }
    }
    else
    {
        qsc_consoleutils_print_line("The Parental Controls service could not be started.");
    }

    /* user accounts */

    qsc_consoleutils_print_line("Testing the user functions.");

    rlen = qsc_winutils_user_list(sbuf, sizeof(sbuf));

    if (rlen > 0)
    {
        qsc_consoleutils_print_line(sbuf);
    }
    else
    {
        qsc_consoleutils_print_line("The user accounts list function failed.");
    }

    qsc_stringutils_clear_string(sbuf);

    rlen = qsc_winutils_current_user(sbuf, sizeof(sbuf));

    if (rlen > 0)
    {
        qsc_consoleutils_print_line(sbuf);
    }
    else
    {
        qsc_consoleutils_print_line("The logged-in user function failed.");
    }
}
#endif

#endif





