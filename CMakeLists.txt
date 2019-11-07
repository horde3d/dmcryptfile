cmake_minimum_required(VERSION 3.0)
project(dmcryptfile)

set(SOURCES
    crypto_backend.h
    crypto_cipher_kernel.c
    crypto_kernel.c
    dmcryptfile.c
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_compile_options(${PROJECT_NAME} PRIVATE -Wall)
