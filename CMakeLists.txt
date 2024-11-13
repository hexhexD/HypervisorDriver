project(Hyperdriver)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_EXPORT_COMPILE_COMMANDS true)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/External/FindWDK/cmake)
find_package(WDK REQUIRED)

add_library(WIL INTERFACE)
target_include_directories(WIL INTERFACE
  ${PROJECT_SOURCE_DIR}/External/wil/include)

file(GLOB_RECURSE DRIVER_FILES CONFIGURES_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/Driver/*)
file(GLOB_RECURSE CLIENT_FILES CONFIGURES_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/Client/*)

add_compile_definitions(UNICODE)
add_compile_options(-fansi-escape-codes -fcolor-diagnostics)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
wdk_add_driver(Hyperdriver
  ${DRIVER_FILES}
  WINVER 0x0A00
  )
target_compile_definitions(Hyperdriver PRIVATE DBG)
target_compile_options(Hyperdriver PRIVATE -Ofast "/Zi" "/volatile:ms" -Wno-sizeof-array-div)
target_link_options(Hyperdriver PRIVATE "/DEBUG" /INCREMENTAL:NO /INTEGRITYCHECK)

add_executable(Client
  ${CLIENT_FILES}
  )
add_dependencies(Client Hyperdriver)
target_compile_options(Client PRIVATE -Ofast "/Zi" "/volatile:ms"
"/clang:-fno-omit-frame-pointer" )
target_link_options(Client PRIVATE "/DEBUG" "/INCREMENTAL:NO")
target_link_libraries(Client PRIVATE WIL)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
set(CMAKE_LINKER link.exe)

add_custom_command(TARGET Hyperdriver POST_BUILD
  COMMAND "signtool.exe" sign /ph /fd "sha256" /sha1 "348efcc00802f0f08895b1eb3a5edd8b29efbaed" "$<TARGET_FILE:Hyperdriver>"
	COMMENT "Test sign this bish")
