#pragma once

/*If you want the kerneltoys kernel options to be usable without admin privilegies, set this to 0,
remember that then unprivilegied normal processes can abuse this*/
#define KERNELTOYS_SECURE_DEVICE 1

#define KERNELTOYS_CTL_CODE(id) CTL_CODE(FILE_DEVICE_UNKNOWN, id, METHOD_BUFFERED, FILE_ANY_ACCESS)


#define IOCTL_TERMINATE_PROCESS	KERNELTOYS_CTL_CODE(0x800)
#define IOCTL_DELETE_LINK		KERNELTOYS_CTL_CODE(0x801)
#define IOCTL_DELETE_FILE		KERNELTOYS_CTL_CODE(0x802)
#define IOCTL_BUGCHECK			KERNELTOYS_CTL_CODE(0x803)
#define IOCTL_PROTECT_PROCESS   KERNELTOYS_CTL_CODE(0x804)
#define IOCTL_CREATE_FILE 		KERNELTOYS_CTL_CODE(0x805)
#define IOCTL_CREATE_DIRECTORY	KERNELTOYS_CTL_CODE(0x806)
#define IOCTL_DELETE_KEY		KERNELTOYS_CTL_CODE(0x807)
#define IOCTL_CREATE_KEY		KERNELTOYS_CTL_CODE(0x808)
#define IOCTL_UNLOAD_DRIVER		KERNELTOYS_CTL_CODE(0x809)
#define IOCTL_CRITICAL_THREAD	KERNELTOYS_CTL_CODE(0x80a)
#define IOCTL_COPY_FILE			KERNELTOYS_CTL_CODE(0x80b)
#define IOCTL_SET_KEY_VALUE		KERNELTOYS_CTL_CODE(0x80c)
#define IOCTL_RET_FIRMWARE		KERNELTOYS_CTL_CODE(0x80d)
#define IOCTL_MINIMAL_PROCESS	KERNELTOYS_CTL_CODE(0x80e)
#define IOCTL_TRIPLE_FAULT		KERNELTOYS_CTL_CODE(0x80f)
#define IOCTL_INJECT_SHELLCODE	KERNELTOYS_CTL_CODE(0x810)
#define IOCTL_PORT_IO           KERNELTOYS_CTL_CODE(0x811)

#if SUPPORT_COLORS
    #define COLOR(text, color) "\033[1;" color "m" text "\033[0m"
#else
    #define COLOR(text, color) text
#endif

#define GREEN(text)   COLOR(text, "92")
#define BLUE(text)    COLOR(text, "94")
#define YELLOW(text)  COLOR(text, "93")
#define RED(text)     COLOR(text, "91")
#define MAGENTA(text) COLOR(text, "95")

#define STRINGIFY_INTERNL(x) #x
#define STRINGIFY(x) STRINGIFY_INTERNL(x)

#if defined(DBG) || defined(DEBUG)
    #define Debug_Log_Internal      PRINTF_FUNCTION
#else 
    #define Debug_Log_Internal      __noop
#endif

#define DBGPRINT(...)           Debug_Log_Internal(__VA_ARGS__)

#define DBGLOG(symbol, ...) 	do { Debug_Log_Internal(symbol " <" __FILE__ ":" STRINGIFY(__LINE__) "> "); PRINTF_FUNCTION(__VA_ARGS__); Debug_Log_Internal("\n"); } while(FALSE)
#define DBGLOG_NN(symbol, ...) 	do { Debug_Log_Internal(symbol " <" __FILE__ ":" STRINGIFY(__LINE__) "> "); PRINTF_FUNCTION(__VA_ARGS__); } while(FALSE)

#define DBGWARN(...)	        DBGLOG("[" YELLOW("!") "]", __VA_ARGS__)
#define DBGWARN_NN(...)	        DBGLOG_NN("[" YELLOW("!") "]", __VA_ARGS__)

#define DBGERR(...)	            DBGLOG("[" RED("X") "]", __VA_ARGS__)
#define DBGERR_NN(...)	        DBGLOG_NN("[" RED("X") "]", __VA_ARGS__)

#define DBGOK(...)	            DBGLOG("[" GREEN("+") "]", __VA_ARGS__)
#define DBGOK_NN(...)	        DBGLOG_NN("[" GREEN("+") "]", __VA_ARGS__)

#define DBGINFO(...)	        DBGLOG("[" BLUE("i") "]", __VA_ARGS__)
#define DBGINFO_NN(...)	        DBGLOG_NN("[" BLUE("i") "]", __VA_ARGS__)


#define PRINT(...)              PRINTF_FUNCTION(__VA_ARGS__)

#define LOG(symbol, ...) 	    do { PRINTF_FUNCTION(symbol " "); PRINTF_FUNCTION(__VA_ARGS__); PRINTF_FUNCTION("\n"); } while(FALSE)
#define LOG_NN(symbol, ...) 	do { PRINTF_FUNCTION(symbol " "); PRINTF_FUNCTION(__VA_ARGS__); } while(FALSE)

#define WARN(...)	            LOG("[" YELLOW("!") "]", __VA_ARGS__)
#define WARN_NN(...)	        LOG_NN("[" YELLOW("!") "]", __VA_ARGS__)

// Can't use ERROR, thanks wingdi
#define ERR(...)	            LOG("[" RED("X") "]", __VA_ARGS__)
#define ERR_NN(...)	            LOG_NN("[" RED("X") "]", __VA_ARGS__)

#define OK(...)	                LOG("[" GREEN("+") "]", __VA_ARGS__)
#define OK_NN(...)	            LOG_NN("[" GREEN("+") "]", __VA_ARGS__)

#define INFO(...)	            LOG("[" BLUE("i") "]", __VA_ARGS__)
#define INFO_NN(...)	        LOG_NN("[" BLUE("i") "]", __VA_ARGS__)