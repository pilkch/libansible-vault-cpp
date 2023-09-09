# Set the minimum cmake version
CMAKE_MINIMUM_REQUIRED(VERSION 3.10)

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

SET(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

project(fuzz_ansible_vault_password)

add_compile_options(-std=c++20 -Wall -W -Wextra -Werror -Wformat -Wformat-y2k -Winit-self -Wstack-protector -Wunknown-pragmas -Wundef -Wwrite-strings -Wno-unused-parameter -Wpointer-arith -Wno-switch -Woverloaded-virtual -Wno-stack-protector -Wmissing-include-dirs -Wuninitialized -O2)

INCLUDE(FindPkgConfig)


INCLUDE_DIRECTORIES(../include/)
link_directories(../)


# Fuzz Passwords

ADD_EXECUTABLE(fuzz_ansible_vault_password fuzz_ansible_vault_password.cpp)

target_compile_options(fuzz_ansible_vault_password PRIVATE -fsanitize=address,fuzzer)
target_link_options(fuzz_ansible_vault_password PRIVATE -fsanitize=address,fuzzer)

target_link_libraries(fuzz_ansible_vault_password PRIVATE -fsanitize=address,fuzzer
  ansible-vault-cpp
  cryptopp
  pthread
)


# Fuzz Decrypt

ADD_EXECUTABLE(fuzz_ansible_vault_decrypt fuzz_ansible_vault_decrypt.cpp)

target_compile_options(fuzz_ansible_vault_decrypt PRIVATE -fsanitize=address,fuzzer)
target_link_options(fuzz_ansible_vault_decrypt PRIVATE -fsanitize=address,fuzzer)

target_link_libraries(fuzz_ansible_vault_decrypt PRIVATE -fsanitize=address,fuzzer
  ansible-vault-cpp
  cryptopp
  pthread
)
