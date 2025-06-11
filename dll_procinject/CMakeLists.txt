

 add_library(MyDll SHARED 
    "dll.cpp"
    "dll.h"
)

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET MyDll PROPERTY CXX_STANDARD 20)
endif()

# 确保DLL有导出符号
target_compile_definitions(MyDll PRIVATE BUILDING_DLL)

# 设置输出目录（确保DLL输出到正确位置）
set_target_properties(MyDll PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)