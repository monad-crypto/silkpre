#[[
   Copyright 2022 The Silkpre Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
]]

# find_package(benchmark CONFIG REQUIRED)
# find_package(Catch2 CONFIG REQUIRED)

add_executable(unit_test
    unit_test.cpp
    hex.hpp
    hex.cpp
    precompile_test.cpp
    sha256_test.cpp
)
target_link_libraries(unit_test Catch2::Catch2 silkpre)

add_executable(main main.c)
target_link_libraries(main silkpre)

# Specify the name of your library
add_library(bn_wrapper STATIC IMPORTED)

find_path(BN_WRAPPER_INCLUDE_DIR NAMES bn_wrapper.h PATHS ../third_party/bn_wrapper)
find_library(BN_WRAPPER_LIB NAMES libbn_wrapper.a HINTS ../third_party/bn_wrapper/target/release)

# Set the location of the header files
target_include_directories(bn_wrapper INTERFACE ${BN_WRAPPER_INCLUDE_DIR})

# Set the location of the library file
set_target_properties(bn_wrapper PROPERTIES IMPORTED_LOCATION ${BN_WRAPPER_LIB})

add_executable(silkpre_benchmark benchmark.cpp hex.hpp hex.cpp)
target_link_libraries(silkpre_benchmark silkpre benchmark::benchmark bn_wrapper)

