# Welcome to KernelToys!

**KERNELTOYS 2.0 IS OUT 🔥🥳🎉🎉**

To get a quick overview, run kerneltoys.exe without arguments in a Command Prompt.

KernelToys is a CLI toolbox that is split into two parts: the usermode executable (KernelToys.exe) and a kernel driver (KernelToysDriver.sys).

Kerneltoys contains various tools like terminating processes or deleting symbolic links that probably dont sound special, but they're designed to bypass as many restrictions as possible;
which is why the heart of it is a kernel driver; you bypass many restrictions out of the box and have access to ALMOST all parts of the OS.

Because the kernel is SUPER MEGA SENSISTIVE LIKE A LITTLE DISCORD KITTEN you have to be CAREFUL, first because you can easily destroy your OS with kerneltoys, second because if you use it incorrectly, your operating system might crash. For example: if you pass an invalid protection offset to protectedprocess, it will still write the memory, but not to the correct location and it will corrupt other stuff, so make sure that you know what you're doing. (although most of the tools will just give you an error if you use them incorrectly).

kdu.exe (kernel driver utility) is used for bypassing the driver signature enforcement (DSE) that would block the kerneltoys driver to start because its not signed, but there are many signed kernel drivers that contain vulnerabilities that kdu uses to write to kernel memory (by writing 0 to the DSE flags you disable the dse, 
but you quickly have to revert the changes after writing 0 because otherwise the system will crash). 
drv64.dll contains the vulnerable drivers.

**I DID NOT MAKE KDU.EXE OR DRV64.DLL! CREDITS GO TO https://github.com/hfiref0x/KDU**

Luckily, Microsoft prefers to add more fancy useless stuff to Windows 11 like **AI enhanced notepad** or **Full-time screen spying** instead of fixing vulnerable drivers, and this is why this mostly works.

Kerneltoys has two switches you can use to start and stop the driver: startdriver and stopdriver (aliases: sa and so), startdriver will run "kdu -prv %d -dse 0" where -prv %d will select the provider, %d is a number and it will try multiple numbers in case one doesnt work
(for each number it tries a different driver, in case one doesnt work, a different one might work) and -dse 0 tells kdu to write 0 to the dse flags in kernel memory. Then it creates a service for the driver, starts it and then writes back the old dse flags (important! If writing back the old flags fails for some reason while the first time it worked then your system will probably bluescreen in the next few minutes
if you don't quickly write back the old flags). The stopdriver option simply stops the driver and deletes the service.

There is a VERY SMALL chance that your system will crash when starting the driver (CRITICAL_STRUCTURE_CORRUPTION Ci.dll, the driver signature enforcement is implemented in Ci.dll). The system WILL crash if the dse flags are 0 for too long (PatchGuard ^-^ a not so nice guy that periodically checks the system for corrupted/patched things like the SSDT/IDT or certain drivers like NTFS). This is VERY RARE and only happened to me like ONCE, but it is possible.

So if you get a bluescreen from Ci.dll CRITICAL_STRUCTURE_CORRUPTION when starting the driver don't worry, just try again, if it keeps happening then something is going terribly wrong and you probably have to jump to manual driver setup.

Not every tool in kerneltoys really uses the kernel driver, tools listed under the "User Options" section (when running kerneltoys.exe without arguments) are implemented in kerneltoys.exe only and dont require the driver to be started.


# FAQ:

**Q:** Can i use kerneltoys for a video or something?

**A:** Sure, feel free to use it, it'd be nice if you could link the repo link though :>


**Q:** Why is the source code so ugly?

**A:** I worked very hard to make kerneltoys 2.0 have a much better, cleaner and organized source code but you might still see something that makes your eyes feel offended because you are a 80 year old grandpa with a 5 meter long beard that has been coding in C since 1975 at bell labs in K&R and has a 50 kilometer long bug-free punchtape program that can simulate the universe and have found a line of code not 100% ANSI X3.159-1989 or ISO/IEC 9899:1999 compliant. In that case you are free to open a pull request with the fixes.


**Q:** HELPP!!! WHAT IS A NT NATIVE PATH???? HOW DO I USE THE DELETEKEY OPTION???

**A:** its a REAL full path, C:\Windows actually isnt a full path, under the hood its \GLOBAL??\C:\Windows, C: is just a symbolic link to \Device\HarddiskVolumeX where X is the partition.
so you could use the deletesymblink option with \??\C: which basically makes C: disappear for the usermode until you reboot (even tho its somewhat safe i wouldnt recommend doing it on your real system)
for the registry native paths you dont do HKLM\Software etc or HKCU\, instead you do \Registry\ so HKEY_LOCAL_MACHINE\Software\test becomes \Registry\Machine\Software\test, the equivalents are:

HKEY_LOCAL_MACHINE: \Registry\Machine

HKEY_USERS: \Registry\User

HKEY_CLASSES_ROOT and HKEY_CURRENT_USER have no kernel equivalent
	

**Q:** which version of windows should i use?

**A:** the kerneltoys driver is compiled for Windows 10 x64, i also tested it on windows 11 and it worked, it MIGHT work on 8 / 8.1 but i recommend using windows 10 x64 or maybe 11, remember that every build or other version 
COULD break some parts of kerneltoys, you knever know what crap microsoft is doing O-O


**Q:** what is the protectionoffset in the ppl option? 

**A:** This is a bit more complex, the ppl option relies on protected process light, a mechanism in windows to protect processes from injection or termination, this is for example used for digital restriction management [(DRM)](https://www.defectivebydesign.org/what_is_drm) bullshit.

Essentially what makes a process a PPL is a member in an internal OS struct for processes (if you're a C/C++ dev you know what a struct is) called EPROCESS that stores a LOT of info about the process, including the information about if its a protected process, or a protected process light (ppl) and how its protected. Kerneltoys has hardcoded knowledge of the member in this struct for the protection, but the memory offset of the members in the EPROCESS struct are different for some windows builds, kerneltoys also has hardcoded knowledge of these, but for new or weird builds you might get a message saying "Couldn't find the protection offset, please pass in the protection offset manually". In this case the build number is unknown and you need to pass in the offset manually. To find it you need to use a kernel debugger like WinDbg (lkd) and connect to the local kernel, i wont explain this in depth, you can search this up on the internet, something like "kernel debugging with WinDbg"
but once in lkd type "dt nt!_EPROCESS" and hit enter, then search for a line saying something like this:

+0x87a Protection       : _PS_PROTECTION

In my case the offset is **0x87a** (Windows 10 22H2 19045), so i would use the command like this:

kerneltoys ppl <PID> <none|light|full|max> 87a

If the offset is wrong then your system might crash ^-^ be careful with kernel memory, the kernel doesn't like it when you play too much with it although its one of the most fun playgrounds.


**Q:** Why does kdu.exe get detected as malware?

**A:** Short answer: AV's suck lmao.
Long answer: kdu.exe uses vulnerabilities in drivers to write custom data to the system DSE flags, which is considered malicious. I kinda recommend turning off your antimalware engine when messing around with kerneltoys, because if your antimalware engine blocks kdu before it can write back the old dse flags then your dse flags will stay at 0, and this will result in the critical structure corruption crash i explained previously.
if you are too scared and don't trust me then you can jump to the Manual driver setup section, or if you don't trust me at all delete kerneltoys or use it in a VM.... i recommend using it in a VM anyways, kerneltoys is dangerous if used incorrectly. If you just want to experiment with kerneltoys then DON'T do that on your real system, USE A VIRTUAL MACHINE!!

**--FAQ end----------**


# Manual driver setup:

In case the startdriver option crashes your system or somehow doesnt work you can manually deal with the driver (this option also prevents the possible crash from Ci.dll), here's how:
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
1. disable the driver signature enforcement on your system manually:
        - hold down shift while selecting Restart from the start menu, let it reboot until you see a blue screen
        - choose Troubleshoot > Advanced options > Startup Settings > Restart, let it reboot again
        - press F7 or 7 on your keyboard to select Disable driver signature enforcement, whatever it says on screen
        
	if this explanation was bad then im sorry lol. you should search "how to disable driver signature enforcement on windows x" where x is your win version.


2. run kerneltoys with "-startdriver nodse" (or "-sa nodse")

if for some obscure reason the -startdriver nodse doesnt work for you, here are the steps to do this part manually too:

2. Open an elevated command prompt

3. Type in this command: sc create kerneltoys type=kernel binPath="FULL_PATH_TO_KERNELTOYS.SYS"

you have to replace PATH_TO_KERNELTOYS.SYS with the actual full path to the kerneltoys.sys file (no shit sherlock), for example if the path is C:\kerneltoys.sys then you would do: sc create kerneltoys type=kernel binPath="C:\kerneltoys.sys"   easy right?

4. Start the driver using this command: sc start kerneltoys

to stop the driver you can simply use the -stopdriver argument from kerneltoys as it doesnt require kdu.exe (just that kerneltoys.exe needs to be in the directory of the driver), 
but if you want to do this manually too you can use these commands:

sc stop kerneltoys         // stops the driver

sc delete kerneltoys       // deletes the service


if you just want to stop the driver but dont want to recreate it every time you can just do sc stop and dont do sc delete kerneltoys, that way you can just do sc start kerneltoys again without having to delete the service. 
the kerneltoys.sys file will NOT be deleted if you do sc delete kerneltoys, oh and you NEED to name the service you create "kerneltoys", otherwise it wont work.


A HUGE THANKS to [gabrik](https://github.com/gab8192), who allowed me to use his custom IRP file deletion method.

**NEITHER ME, NOR ANYONE ELSE EXCEPT YOU IS RESPONSIBLE FOR WHAT YOU DO WITH THIS TOOL, IT MIGHT CONTAIN BUGS, KERNELTOYS COMES WITH ABSOLUTELY NO WARRANTY, BY USING KERNELTOYS YOU AGREE TO THIS!!**


Made by Hallilo.