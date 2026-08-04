//
// RR Redirector DLL
//
// Build:
// cl /O2 /LD redirector.c /link ws2_32.lib dbghelp.lib /OUT:redirector.dll
//

#define WIN32_LEAN_AND_MEAN
#define RR_DEBUG 1
#define DEBUG_LOG(x,...) \
    if(RR_DEBUG) Log(x,__VA_ARGS__)

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <psapi.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"dbghelp.lib")
#pragma comment(lib,"psapi.lib")


// ============================================================
// Forward declarations
// ============================================================

void Log(const char *fmt,...);
void LogProcessInfo();
void DumpLoadedModules();
void LogStack();


// ============================================================
// Function typedefs
// ============================================================


typedef int (WSAAPI *getaddrinfo_t)
(
    PCSTR,
    PCSTR,
    const ADDRINFOA *,
    PADDRINFOA *
);


typedef struct hostent *(WSAAPI *gethostbyname_t)
(
    const char *
);


typedef int (WSAAPI *connect_t)
(
    SOCKET,
    const struct sockaddr *,
    int
);



// ============================================================
// Original functions
// ============================================================

static getaddrinfo_t real_getaddrinfo = NULL;

static getaddrinfo_t original_getaddrinfo = NULL;

static gethostbyname_t real_gethostbyname = NULL;

static connect_t real_connect = NULL;



// ============================================================
// Hook memory
// ============================================================


static BYTE original_bytes[14];

static LPVOID target_function = NULL;

static LPVOID trampoline = NULL;



// ============================================================
// Deep Logger
// ============================================================

static FILE *logFile = NULL;


void InitLogger()
{

    char path[MAX_PATH];


    GetModuleFileNameA(
        NULL,
        path,
        sizeof(path)
    );


    char *slash =
        strrchr(path,'\\');


    if(slash)
        *(slash+1)=0;


    strcat(
        path,
        "redirector.log"
    );


    logFile =
        fopen(
            path,
            "w"
        );


    if(logFile)
    {

        fprintf(
            logFile,
            "==============================\n"
        );


        fprintf(
            logFile,
            " RR Redirector Loaded\n"
        );


        fprintf(
            logFile,
            "==============================\n\n"
        );


        fflush(logFile);

    }

}



void Log(
    const char *fmt,
    ...
)
{

    SYSTEMTIME st;


    GetLocalTime(
        &st
    );


    DWORD tid =
        GetCurrentThreadId();



    char buffer[4096];


    va_list args;


    va_start(
        args,
        fmt
    );


    vsprintf_s(
        buffer,
        sizeof(buffer),
        fmt,
        args
    );


    va_end(args);



    printf(
        "[%02d:%02d:%02d.%03d][TID %lu] %s\n",
        st.wHour,
        st.wMinute,
        st.wSecond,
        st.wMilliseconds,
        tid,
        buffer
    );



    if(logFile)
    {

        fprintf(
            logFile,
            "[%02d:%02d:%02d.%03d][TID %lu] %s\n",
            st.wHour,
            st.wMinute,
            st.wSecond,
            st.wMilliseconds,
            tid,
            buffer
        );


        fflush(
            logFile
        );

    }

}


// ============================================================
// Console
// ============================================================


void InitConsole()
{

    AllocConsole();


    FILE *fp;


    freopen_s(
        &fp,
        "CONOUT$",
        "w",
        stdout
    );


    printf(
        "\n==============================\n"
    );


    printf(
        " RR Redirector Loaded\n"
    );


    printf(
        "==============================\n\n"
    );

}



// ============================================================
// Process information
// ============================================================


void LogProcessInfo()
{

    char path[MAX_PATH];


    GetModuleFileNameA(
        NULL,
        path,
        sizeof(path)
    );


    Log(
        "[PROCESS] %s",
        path
    );


    Log(
        "[PID] %lu",
        GetCurrentProcessId()
    );

}



// ============================================================
// Module dump
// ============================================================


void DumpLoadedModules()
{

    Log(
        "========== MODULE LIST =========="
    );


    HANDLE snap =
        CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE,
            GetCurrentProcessId()
        );


    if(
        snap == INVALID_HANDLE_VALUE
    )
    {
        Log(
            "[MODULE] Failed"
        );

        return;
    }



    MODULEENTRY32 me;

    me.dwSize =
        sizeof(me);



    if(Module32First(
        snap,
        &me))
    {

        do
        {

            MODULEINFO info;


            HANDLE process =
                GetCurrentProcess();



            if(
                GetModuleInformation(
                    process,
                    me.hModule,
                    &info,
                    sizeof(info)
                )
            )
            {

                Log(
                    "[MODULE] %s Base=%p Size=%lu",
                    me.szModule,
                    info.lpBaseOfDll,
                    info.SizeOfImage
                );

            }
            else
            {

                Log(
                    "[MODULE] %s",
                    me.szModule
                );

            }


        }
        while(
            Module32Next(
                snap,
                &me
            )
        );

    }


    CloseHandle(
        snap
    );


    Log(
        "================================"
    );

}



// ============================================================
// Stack trace
// ============================================================


void LogStack()
{

    void *frames[32];


    USHORT count =
        CaptureStackBackTrace(
            1,
            32,
            frames,
            NULL
        );


    Log(
        "[STACK] Frames=%d",
        count
    );


    for(
        int i=0;
        i<count;
        i++
    )
    {

        Log(
            "[STACK] %p",
            frames[i]
        );

    }

}



// ============================================================
// Redirect config
// ============================================================


#define CONFIG_FILE "redirector.json"

#define MAX_REDIRECTS 64

#define DEFAULT_IP "127.0.0.1"

#define DEFAULT_PORT 443



static char redirect_ip[16] =
    DEFAULT_IP;


static int redirect_port =
    DEFAULT_PORT;


static char *redirect_domains[MAX_REDIRECTS];


static int redirect_count_config = 0;



static int redirect_count = 0;
// ============================================================
// Config loader
// ============================================================


void LoadConfig()
{

    HANDLE hFile =
        CreateFileA(
            CONFIG_FILE,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );


    if(hFile == INVALID_HANDLE_VALUE)
    {

        Log(
            "[CONFIG] No config found, using defaults %s:%d",
            redirect_ip,
            redirect_port
        );

        return;

    }



    DWORD size =
        GetFileSize(
            hFile,
            NULL
        );


    char *buffer =
        calloc(
            1,
            size + 1
        );


    DWORD read;


    ReadFile(
        hFile,
        buffer,
        size,
        &read,
        NULL
    );


    CloseHandle(
        hFile
    );



    //
    // IP
    //

    char *ip =
        strstr(
            buffer,
            "\"ip\""
        );


    if(ip)
    {

        char *colon =
            strchr(
                ip,
                ':'
            );


        if(colon)
        {

            char *start =
                strchr(
                    colon,
                    '"'
                );


            if(start)
            {

                start++;


                char *end =
                    strchr(
                        start,
                        '"'
                    );


                if(end)
                {

                    size_t len =
                        end-start;


                    if(len < sizeof(redirect_ip))
                    {

                        memcpy(
                            redirect_ip,
                            start,
                            len
                        );


                        redirect_ip[len]=0;

                    }

                }

            }

        }

    }



    //
    // Port
    //

    char *port =
        strstr(
            buffer,
            "\"port\""
        );


    if(port)
    {

        char *colon =
            strchr(
                port,
                ':'
            );


        if(colon)
        {

            int p =
                atoi(
                    colon+1
                );


            if(p>0 && p<65536)
                redirect_port=p;

        }

    }



    //
    // Redirect domains
    //

    char *redirect =
        strstr(
            buffer,
            "\"redirect\""
        );


    if(redirect)
    {

        char *array =
            strchr(
                redirect,
                '['
            );


        if(array)
        {

            char *current =
                array;


            while(
                redirect_count_config < MAX_REDIRECTS)
            {

                char *q1 =
                    strchr(
                        current,
                        '"'
                    );


                if(!q1)
                    break;


                q1++;


                char *q2 =
                    strchr(
                        q1,
                        '"'
                    );


                if(!q2)
                    break;



                size_t len =
                    q2-q1;



                redirect_domains[redirect_count_config] =
                    calloc(
                        1,
                        len+1
                    );


                memcpy(
                    redirect_domains[redirect_count_config],
                    q1,
                    len
                );


                redirect_count_config++;


                current =
                    q2+1;

            }

        }

    }


    free(buffer);



    Log(
        "[CONFIG] Loaded %d redirects",
        redirect_count_config
    );


    Log(
        "[CONFIG] Redirect IP %s:%d",
        redirect_ip,
        redirect_port
    );



    for(
        int i=0;
        i<redirect_count_config;
        i++)
    {

        Log(
            "[CONFIG] %s",
            redirect_domains[i]
        );

    }

}



// ============================================================
// Domain matcher
// ============================================================


int ShouldRedirect(
    const char *host
)
{

    if(!host)
        return 0;



    Log(
        "[CHECK] %s",
        host
    );



    for(
        int i=0;
        i<redirect_count_config;
        i++)
    {


        if(
            _stricmp(
                host,
                redirect_domains[i]
            ) == 0)
        {

            Log(
                "[MATCH] %s",
                host
            );

            return 1;

        }



        size_t len =
            strlen(
                redirect_domains[i]
            );



        size_t hostLen =
            strlen(
                host
            );



        if(
            hostLen > len &&
            host[hostLen-len-1]=='.' &&
            _stricmp(
                host+(hostLen-len),
                redirect_domains[i]
            )==0)
        {

            Log(
                "[SUBDOMAIN MATCH] %s",
                host
            );

            return 1;

        }


    }


    return 0;

}



// ============================================================
// gethostbyname hook
// ============================================================


struct hostent *WSAAPI hook_gethostbyname(
    const char *name
)
{

    Log(
        "[HOSTBYNAME] %s",
        name ? name : "NULL"
    );



    if(
        name &&
        ShouldRedirect(name))
    {

        Log(
            "[HOST REDIRECT BLOCK] %s",
            name
        );


        return NULL;

    }



    if(real_gethostbyname)
        return real_gethostbyname(name);



    return NULL;

}




// ============================================================
// getaddrinfo hook
// ============================================================


int WSAAPI hook_getaddrinfo
(
    PCSTR node,
    PCSTR service,
    const ADDRINFOA *hints,
    PADDRINFOA *result
)
{

    Log(
        "=============================="
    );


    Log(
        "[DNS REQUEST]"
    );


    Log(
        "[THREAD] %lu",
        GetCurrentThreadId()
    );


    Log(
    "[DNS HOST] %s",
    node ? node : "NULL"
    );


    Log(
    "[DNS SERVICE] %s",
    service ? service : "NULL"
    );



    LogStack();



    if(
        ShouldRedirect(node))
    {

        redirect_count++;


        Log(
            "[REDIRECT #%d] %s -> %s:%d",
            redirect_count,
            node,
            redirect_ip,
            redirect_port
        );



        PADDRINFOA ai =
            calloc(
                1,
                sizeof(ADDRINFOA)
            );



        PSOCKADDR_IN addr =
            calloc(
                1,
                sizeof(SOCKADDR_IN)
            );



        if(!ai || !addr)
        {

            free(ai);
            free(addr);

            return EAI_MEMORY;

        }



        addr->sin_family =
            AF_INET;


        addr->sin_port =
            htons(
                redirect_port
            );


        addr->sin_addr.s_addr =
            inet_addr(
                redirect_ip
            );



        ai->ai_family =
            AF_INET;


        ai->ai_socktype =
            SOCK_STREAM;


        ai->ai_protocol =
            IPPROTO_TCP;


        ai->ai_addr =
            (SOCKADDR*)addr;


        ai->ai_addrlen =
            sizeof(SOCKADDR_IN);



        *result =
            ai;



        return 0;

    }




    if(original_getaddrinfo)
    {

        int ret =
            original_getaddrinfo(
                node,
                service,
                hints,
                result
            );



        if(
            ret==0 &&
            result &&
            *result)
        {

            SOCKADDR_IN *addr =
                (SOCKADDR_IN*)
                (*result)->ai_addr;



            char ip[INET_ADDRSTRLEN];


            inet_ntop(
                AF_INET,
                &addr->sin_addr,
                ip,
                sizeof(ip)
            );



            Log(
                "[DNS RESULT] %s -> %s",
                node,
                ip
            );

        }
        else
        {

            Log(
                "[DNS FAIL] %s (%d)",
                node,
                ret
            );

        }



        return ret;

    }



    return EAI_FAIL;

}
// ============================================================
// CONNECT LOGGER
// ============================================================


int WSAAPI hook_connect(
    SOCKET s,
    const struct sockaddr *name,
    int namelen
)
{

    if(name &&
       name->sa_family == AF_INET)
    {

        SOCKADDR_IN *addr =
            (SOCKADDR_IN*)name;


        char ip[INET_ADDRSTRLEN];


        inet_ntop(
            AF_INET,
            &addr->sin_addr,
            ip,
            sizeof(ip)
        );


        Log(
            "[CONNECT] %s:%d",
            ip,
            ntohs(addr->sin_port)
        );

    }



    if(real_connect)
    {

        return real_connect(
            s,
            name,
            namelen
        );

    }


    return SOCKET_ERROR;

}



// ============================================================
// INLINE DETOUR
// ============================================================


int InstallDetour(
    LPVOID target,
    LPVOID hook,
    BYTE *backup,
    LPVOID *outTrampoline
)
{

    if(!target)
        return 0;



    SIZE_T size = 14;



    memcpy(
        backup,
        target,
        size
    );



    LPVOID tramp =
        VirtualAlloc(
            NULL,
            64,
            MEM_COMMIT |
            MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );



    if(!tramp)
    {

        Log(
            "[DETOUR] trampoline failed"
        );

        return 0;

    }



    memcpy(
        tramp,
        backup,
        size
    );



    BYTE *jumpBack =
        (BYTE*)tramp + size;



    jumpBack[0]=0xFF;
    jumpBack[1]=0x25;
    jumpBack[2]=0;
    jumpBack[3]=0;
    jumpBack[4]=0;
    jumpBack[5]=0;



    *(void**)&jumpBack[6] =
        (BYTE*)target + size;




    BYTE patch[14] =
    {
        0xFF,0x25,
        0x00,0x00,
        0x00,0x00,
        0,0,0,0,0,0,0,0
    };



    *(void**)&patch[6] =
        hook;



    DWORD old;



    VirtualProtect(
        target,
        size,
        PAGE_EXECUTE_READWRITE,
        &old
    );



    memcpy(
        target,
        patch,
        size
    );



    VirtualProtect(
        target,
        size,
        old,
        &old
    );



    FlushInstructionCache(
        GetCurrentProcess(),
        target,
        size
    );



    *outTrampoline =
        tramp;



    Log(
        "[DETOUR] %p -> %p",
        target,
        hook
    );


    return 1;

}




// ============================================================
// HOOK THREAD
// ============================================================


DWORD WINAPI HookThread(
    LPVOID param
)
{

    Log(
        "[THREAD] Hook thread started"
    );



    LoadConfig();



    while(
        !GetModuleHandleA(
            "UnityPlayer.dll"
        ))
    {

        Sleep(100);

    }



    Log(
        "[HOOK] UnityPlayer detected"
    );



    Sleep(2000);



    HMODULE ws2 =
        GetModuleHandleA(
            "ws2_32.dll"
        );



    if(!ws2)
    {

        Log(
            "[ERROR] ws2_32 missing"
        );

        return 1;

    }



    Log(
        "[HOOK] ws2_32.dll loaded"
    );



    real_getaddrinfo =
        (getaddrinfo_t)
        GetProcAddress(
            ws2,
            "getaddrinfo"
        );



    real_gethostbyname =
        (gethostbyname_t)
        GetProcAddress(
            ws2,
            "gethostbyname"
        );



    real_connect =
        (connect_t)
        GetProcAddress(
            ws2,
            "connect"
        );



    Log(
        "[ADDR] getaddrinfo=%p",
        real_getaddrinfo
    );


    Log(
        "[ADDR] gethostbyname=%p",
        real_gethostbyname
    );


    Log(
        "[ADDR] connect=%p",
        real_connect
    );





    if(
        real_getaddrinfo)
    {

        InstallDetour(
            real_getaddrinfo,
            hook_getaddrinfo,
            original_bytes,
            (LPVOID*)&original_getaddrinfo
        );

    }
    else
    {

        Log(
            "[ERROR] getaddrinfo missing"
        );

    }



    //
    // NOTE:
    // connect hook needs its own trampoline storage
    // if you want full socket interception.
    //
    // Currently DNS interception is active.
    //



    Log(
        "===================================="
    );


    Log(
        "[STATUS] DNS REDIRECT ACTIVE"
    );


    Log(
        "===================================="
    );



    return 0;

}



// ============================================================
// DLL ENTRY
// ============================================================


BOOL WINAPI DllMain(
    HINSTANCE hinst,
    DWORD reason,
    LPVOID reserved
)
{

    if(
        reason ==
        DLL_PROCESS_ATTACH)
    {

        DisableThreadLibraryCalls(
            hinst
        );



        InitConsole();


        InitLogger();



        Log(
            "[DLL] Process attach"
        );



        LogProcessInfo();


        DumpLoadedModules();



        HANDLE thread =
            CreateThread(
                NULL,
                0,
                HookThread,
                NULL,
                0,
                NULL
            );



        if(thread)
            CloseHandle(thread);

    }



    return TRUE;

}