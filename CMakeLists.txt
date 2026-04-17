cmake_minimum_required(VERSION 3.16)
project(kerberos_demo LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(kerberos_demo
    src/main.cpp
    src/crypto_utils.cpp
    src/messages.cpp
    src/kdc_database.cpp
    src/as_server.cpp
    src/tgs_server.cpp
    src/service_server.cpp
    src/kerberos_client.cpp
)

target_include_directories(kerberos_demo PRIVATE include)
