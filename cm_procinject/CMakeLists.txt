﻿# CMakeList.txt: cm_procinject 的 CMake 项目，在此处包括源代码并定义
# 项目特定的逻辑。
#

# 将源代码添加到此项目的可执行文件。
add_executable (
	cm_procinject 
	"cm_procinject.cpp" "cm_procinject.h"
	
 "Early Cascade APC Injection.cpp" "Early Cascade APC Injection.h" 
 "RemoteThreadInject.cpp" "RemoteThreadInject.h" 
 "shellcode.h" 
 "atombombing.cpp" "atombombing.h" 
 "processHypnosis.cpp" "processHypnosis.h" 
 "apc1.cpp" "apcearlybride.cpp" "apc1.h" 
 "suspendinject.cpp" "suspendinject.h"  
 "SetWindowsHookEx.cpp" 
 "ewmi.cpp" "ewmi.h" 
 "kctcallback.cpp" "kctcallback.h" 
 "ntStructs.h" 
 "clipbrdwndclass.cpp" "clipbrdwndclass.h" 
 "propagate.cpp" "propagate.h" 
 "ListPlanting.cpp" "ListPlanting.h" 
 "eminject.cpp" "eminject.h" 
 "wnfcallback.cpp" "wnfcallback.h" 
 "utils.cpp" "utils.h" 
 "ctrlinject.cpp" "ctrlinject.h"
 "alpccallback.cpp" "alpccallback.h"

 # "ntlib_modexp/ntddk.h" "ntlib_modexp/nttpp.h" "ntlib_modexp/util.h"
 "dnscallback.cpp" "dnscallback.h"
 "conhostinject.cpp" "conhostinject.h" "knowndlls.cpp" "knowndlls.h" "svcIDEinject.cpp" "svcIDEinject.h")


 if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET cm_procinject PROPERTY CXX_STANDARD 20)
endif()



# TODO: 如有需要，请添加测试并安装目标。
