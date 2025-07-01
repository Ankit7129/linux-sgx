/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "sgx_tcrypto.h"
#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <stdlib.h>
#include <vector>
#include <string>
#include <mbedtls/aes.h>
#include <cstdio>


#define AES_KEY_SIZE 16
#define GCM_IV_SIZE 12
#define GCM_TAG_SIZE 16
#define MAX_MSG_SIZE 2048
#define MAX_PLAINTEXT_SIZE 1024



/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}


/*
 * ecall_print_message:
 *   Receive an encrypted message (base64 encoded) from untrusted app,
 *   decrypt it, and print it securely inside the enclave.
 */





void ecall_process_file(uint8_t* file_data, size_t len) {
    // Just print the file data as a string here (make sure it's null terminated if text)
    printf("Data received in enclave (%zu bytes):\n", len);
    for (size_t i = 0; i < len; i++) {
    printf("%c", file_data[i]);
}

    printf("\n");
}


void ecall_add_vectors(uint8_t* vec1, uint8_t* vec2, size_t len) {
    printf("🔹 Vector 1: ");
    for (size_t i = 0; i < len; ++i)
        printf("%d ", vec1[i]);
    printf("\n");

    printf("🔹 Vector 2: ");
    for (size_t i = 0; i < len; ++i)
        printf("%d ", vec2[i]);
    printf("\n");

    printf("➕ Sum: ");
    for (size_t i = 0; i < len; ++i)
        printf("%d ", static_cast<uint8_t>(vec1[i] + vec2[i]));
    printf("\n");
}
