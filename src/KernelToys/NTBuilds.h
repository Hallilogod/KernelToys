// Protection offset definitions from the KDU project
#pragma once


// Windows 7 RTM
#define NT_WIN7_RTM             7600

// Windows 7 SP1
#define NT_WIN7_SP1             7601

// Windows 8 RTM
#define NT_WIN8_RTM             9200

// Windows 8.1
#define NT_WIN8_BLUE            9600

// Windows 10 TH1
#define NT_WIN10_THRESHOLD1     10240

// Windows 10 TH2
#define NT_WIN10_THRESHOLD2     10586

// Windows 10 RS1
#define NT_WIN10_REDSTONE1      14393

// Windows 10 RS2
#define NT_WIN10_REDSTONE2      15063

// Windows 10 RS3
#define NT_WIN10_REDSTONE3      16299

// Windows 10 RS4
#define NT_WIN10_REDSTONE4      17134

// Windows 10 RS5
#define NT_WIN10_REDSTONE5      17763

// Windows 10 19H1
#define NT_WIN10_19H1           18362

// Windows 10 19H2
#define NT_WIN10_19H2           18363

// Windows 10 20H1
#define NT_WIN10_20H1           19041

// Windows 10 20H2
#define NT_WIN10_20H2           19042

// Windows 10 21H1
#define NT_WIN10_21H1           19043

// Windows 10 21H2
#define NT_WIN10_21H2           19044

// Windows 10 22H2
#define NT_WIN10_22H2           19045

// Windows Server 2022
#define NT_WINSRV_21H1          20348

// Windows 11 21H2
#define NT_WIN11_21H2           22000

// Windows 11 22H2
#define NT_WIN11_22H2           22621

// Windows 11 23H2
#define NT_WIN11_23H2           22631

// Windows 11 24H2
#define NT_WIN11_24H2           26100

// Windows 11 Active Development Branch
#define NT_WIN11_25H2           27842 //canary (25H2)



#define PsProtectionOffset_9600  (ULONG)0x67A
#define PsProtectionOffset_10240 (ULONG)0x6AA
#define PsProtectionOffset_10586 (ULONG)0x6B2
#define PsProtectionOffset_14393 (ULONG)0x6C2
#define PsProtectionOffset_15063 (ULONG)0x6CA //same for 16299, 17134, 17763
#define PsProtectionOffset_18362 (ULONG)0x6FA
#define PsProtectionOffset_18363 (ULONG)0x6FA
#define PsProtectionOffset_19041 (ULONG)0x87A
