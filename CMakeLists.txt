cmake_minimum_required(VERSION 3.20)
project(yyx_pre_analysis)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
# specify C++20 version
set(CMAKE_CXX_STANDARD 20)


# set(DynamoRIO_DIR "C:/HomeSpace/BinaryAnalysis/DynamoRIO-Windows-9.0.1/cmake")
set(DynamoRIO_DIR "C:/HomeSpace/BinaryAnalysis/DynamoRIO-Windows-10.0.0/cmake")
# set(DrMemoryFramework_DIR "C:/HomeSpace/BinaryAnalysis/DrMemory-Windows-2.5.0/drmf")

find_package(DynamoRIO REQUIRED)
find_package(DrMemoryFramework REQUIRED)

# add_library(taint_engine SHARED "lib/engine.c")
# include_directories(PUBLIC "lib")

add_library(yyx_pre_analysis SHARED yyx_pre_analysis.cpp yyx_engine.cpp utils.cpp)
# target_include_directories(yyx_taint PUBLIC "lib")
# target_link_libraries(yyx_taint taint_engine)

configure_DynamoRIO_client(yyx_pre_analysis)
use_DynamoRIO_extension(yyx_pre_analysis drmgr)
use_DynamoRIO_extension(yyx_pre_analysis drreg)
use_DynamoRIO_extension(yyx_pre_analysis drx)
use_DynamoRIO_extension(yyx_pre_analysis drutil)
use_DynamoRIO_extension(yyx_pre_analysis drsyscall)
use_DynamoRIO_extension(yyx_pre_analysis drsyms)
use_DynamoRIO_extension(yyx_pre_analysis drsyms)
use_DynamoRIO_extension(yyx_pre_analysis drwrap)
use_DynamoRIO_extension(yyx_pre_analysis droption) 


