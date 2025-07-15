#pragma once


#define DSE_PROVIDER_MIN 1U
#define DSE_PROVIDER_MAX 53U
/*
We skip some providers:

0 	Intel 					IQVM64/Nal     Skipped: Usually blocked, skipped to save waiting time for user 
1 	MSI 					RTCore64       	
2 	Gigabyte 				Gdrv
3 	ASUSTeK 				ATSZIO64
4 	Patriot 				MsIo64
5 	ASRock 					GLCKIO2
6 	G.SKILL 				EneIo64
7 	EVGA 					WinRing0x64 	Skipped: crashes the system
8 	Thermaltake 			EneTechIo64
9 	Huawei 					PhyMemx64
10 	Realtek 				RtkIo64
11 	MSI  					EneTechIo64
12 	LG 						LHA 			Skipped: crashes the system
13 	ASUSTeK 				AsIO2
14 	PassMark 				DirectIo64
15 	GMER 					GmerDrv
16 	Dell 					DBUtil_2_3 		Skipped: crashes the system
17 	Benjamin Delpy		 	Mimidrv 		Skipped: detected by defender
18 	Wen Jia Liu 			KProcessHacker2
19 	Microsoft 				ProcExp152
20 	Dell 					DBUtilDrv2
21 	DarkByte 				Dbk64
22 	ASUSTeK 				AsIO3
23 	Marvin 					Hw
24 	CODESYS 				SysDrv3S
25 	Zemana 					amsdk
26 	HiRes Ent. 				inpoutx64
27 	PassMark 				DirectIo64
28 	ASRock 					AsrDrv106
29 	Arthur 					Liberman
30 	AMD 					AMDRyzenMasterDriver
31 	Hilscher 				physmem
32 	Lenovo				 	LDD
33 	Dell 					pcdsrvc_x64
34 	MSI 					winio
35 	HP 						EtdSupport
36 	Pavel Yosifovich 		KExplore
37 	Pavel Yosifovich 		KObjExp
38 	Pavel Yosifovich 		KRegExp
39 	Inspect Element LTD 	EchoDrv
40 	NVidia 					nvoclock
41 	Binalyze 				IREC
42 	DavidXXW 				PhyDMACC
43 	Razer 					rzpnk
44 	AMD 					PdFwKrnl
45 	AMD 					AODDriver
46 	Wincor Nixdorf 			wnBios64
47 	EVGA 					EleetX1
48 	ASRock 					AxtuDrv
49 	ASRock 					AppShopDrv103
50 	ASRock 					AsrDrv107n
51 	ASRock 					AsrDrv107   
52 	Intel 	                PmxDrv 	
53 	Jun Liu 	            HwRwDrv
*/


BOOL PatchDse(DWORD newDseFlags, PDWORD pOldDseFlags);
