project(Accelerator CXX ASM C)

include(cmake/CPM.cmake)

CPMAddPackage(NAME fmt
              GITHUB_REPOSITORY fmtlib/fmt
              GIT_TAG 11.1.4
              OPTIONS "FMT_INSTALL OFF")
			  
CPMAddPackage(NAME breakpad
              GITHUB_REPOSITORY Nukoooo/breakpad
              GIT_TAG e7012124436293ca2b016035cd87bb56c79a7771
              SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/breakpad/)

set(accelerator_SOURCES
	"src/accelerator.cpp"
)

add_library(accelerator SHARED)

target_sources(accelerator PRIVATE ${accelerator_SOURCES})
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${accelerator_SOURCES})

target_compile_features(accelerator PUBLIC
	cxx_std_20
)
target_compile_definitions(accelerator PRIVATE _GLIBCXX_USE_CXX11_ABI=0)

target_include_directories(accelerator PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/includes
	${breakpad_SOURCE_DIR}/src/
)

target_link_libraries(accelerator PUBLIC
	breakpad
	fmt::fmt-header-only
)

target_link_options(accelerator PUBLIC
    -static-libstdc++
    -static-libgcc
)
