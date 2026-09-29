```
    _._     _,-'""`-._
   (,-.`._,'(       |\`-/|
       `-.-' \ )-`( , o o)
             `-    \`_`"'-
             SiCk // afflicted.sh
```

# delayed-reaction

ReactOS 0.4.x i386 kernel exploits. 3 LPE + 1 remote DoS.

## afd-lpe.c

AFD driver uses METHOD_NEITHER on all 34 IOCTLs, zero ProbeForWrite/ProbeForRead calls.
SetContext stores payload, GetContext writes it to raw user pointer. Arbitrary kernel write.
Token priv injection + NtCreateToken -> SYSTEM.

`drivers/network/afd/afd/context.c:27`

```
i686-w64-mingw32-gcc -o afd-lpe.exe afd-lpe.c -lws2_32 -ladvapi32 -lkernel32 -lntdll -O2
```

## win32ss-lpe.c

NtUserCallOneParam(GETPROCDEFLAYOUT) returns a DWORD through raw user pointer.
Write any DWORD to any kernel address from userland.

`win32ss/user/ntuser/simplecall.c:404`

```
i686-w64-mingw32-gcc -o win32ss-lpe.exe win32ss-lpe.c -luser32 -ladvapi32 -lkernel32 -lntdll -O2
```

## rle-poolov.c

SURFACE_AllocSurface does cjWidth * cy as unchecked ULONG multiply.
BI_RLE8 with 65536x65536 overflows to zero, kernel allocates sizeof(SURFACE) + 0.
RLE decoder writes past allocation into adjacent SURFACE, corrupts pvScan0.
Get/SetBitmapBits for arbitrary kernel R/W. Pool spray via GDI handle table.

RtlULongMult safe check at surface.c:164 only fires when pvBits!=NULL && cjBufSize!=0.
RLE path sets pvBits=NULL, bypasses it.

`win32ss/gdi/eng/surface.c:184`

```
i686-w64-mingw32-gcc -o rle-poolov.exe rle-poolov.c -lgdi32 -ladvapi32 -lkernel32 -lntdll -O2
```

## tcpip-dos.c

Remote DoS. ProcessFragment miscalculates FragLast when IHL > 5.
Reassembly buffer sized from first fragment, second fragment computed as TotalLen - IHL*4.
IHL=15 + TotalLen=513 = 39 byte pool overflow. Corrupts next pool header,
ExFreePoolWithTag hits BAD_POOL_HEADER (0x19). Two packets, no open ports needed.

```
gcc -o tcpip-dos tcpip-dos.c -O2
sudo ./tcpip-dos <iface> <target-ip> <target-mac>
```

## author

_SiCk // afflicted.sh
