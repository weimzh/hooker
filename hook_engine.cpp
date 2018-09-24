/*
 * Copyright (c) 2018, Wei Mingzhi <whistler_wmz@users.sf.net>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author and contributors may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL WASABI SYSTEMS, INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <Zydis/Zydis.h>
#include "hook_engine.h"

#define PAGE_SIZE         sysconf(_SC_PAGESIZE)
#define PAGE_MASK         (~(PAGE_SIZE-1))
#define PAGE_ALIGN(addr)  (unsigned char *)(((uintptr_t)(addr) + PAGE_SIZE - 1) & PAGE_MASK)
#define BYTES_SIZE_REL (1 + sizeof(uint32_t))
#define BYTES_SIZE     (5 + sizeof(uint64_t))

static void ConstructJmpRel(void* x, void* target) {
    ((uint8_t*)x)[0] = 0xe9;
    *(uint32_t*)((uint8_t*)x + 1) = (uintptr_t)target - ((uintptr_t)x + 5);
}

static void ConstructJmp(void* x, void* target) {
    ((uint8_t*)x)[0] = 0x49;
    ((uint8_t*)x)[1] = 0xbb;
    *(uint64_t*)((uint8_t*)x + 2) = (uint64_t)target;
    ((uint8_t*)x)[10] = 0x41;
    ((uint8_t*)x)[11] = 0xff;
    ((uint8_t*)x)[12] = 0xe3;
}

static int CodeCopy(void* dst, void* src, int min_len) {
    ZydisDecoder decoder;
    ZydisDecodedInstruction instruction;
    int offset = 0;
    const char* data = (const char*)src;
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_ADDR_FORMAT,
                              ZYDIS_ADDR_FORMAT_RELATIVE_SIGNED);
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

    while (ZYDIS_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, data + offset, 4096, 0, &instruction))) {
        memcpy((char*)dst + offset, (char*)src + offset, instruction.length);
        char buffer[256];
        ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer));
        if (strstr(buffer, "[rip+0x") != NULL) {
            if (instruction.length == 7 &&
                    (strncmp(buffer, "lea", 3) == 0 || strncmp(buffer, "mov", 3) == 0) &&
                    strstr(buffer, ", [rip+0x") != NULL) {
                // need to patch things like 'lea rax, [rip+0x13BCE]', which
                // happens a lot at the beginning of func
                int reladdr = *(int*)(data + offset + 3);
                int64_t new_reladdr = (uint64_t)src + reladdr - (uint64_t)dst;
                if (new_reladdr > 0xFFFFFFFFLL || new_reladdr < -0xFFFFFFFFLL) {
                    return 0; // cannot patch this
                }
                *(int*)((char*)dst + offset + 3) = (int)new_reladdr;
            } else {
                return 0; // not supported yet
            }
        } else if (buffer[0] == 'j') {
            return 0; // jump instructions not supported
        }

        offset += instruction.length;
        if (offset >= min_len) {
            return offset;
        }
    }
    return 0; // failed
}

void* InstallHook(void* func, void* new_func) {
    static int num_hooks = 0;
    static unsigned char* hook_buf = NULL;

    if (num_hooks >= 65536 / 64) {
        return NULL; // too many hooks
    }

    if (hook_buf == NULL) {
        hook_buf = (unsigned char*)mmap(NULL, 65536, PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }

    void* buf = (void*)(hook_buf + num_hooks * 64);
    mprotect(hook_buf, 65536, PROT_READ | PROT_WRITE | PROT_EXEC);
    int64_t size_diff = (int64_t)buf - (int64_t)func;
    int prot_size = PAGE_SIZE;
    if ((unsigned char*)func + BYTES_SIZE > PAGE_ALIGN(func)) {
        prot_size *= 2;
    }
    if (size_diff > 0xFFFFFFF0LL || size_diff < -0xFFFFFFF0LL) {
        int len = CodeCopy(buf, func, BYTES_SIZE);
        if (len == 0) {
            mprotect(hook_buf, 65536, PROT_READ | PROT_EXEC);
            return NULL;
        }
        mprotect(PAGE_ALIGN(func) - PAGE_SIZE, prot_size,
                 PROT_READ | PROT_WRITE | PROT_EXEC);
        ConstructJmp((unsigned char *)buf + len, (unsigned char*)func + len);
        ConstructJmp(func, new_func);
        mprotect(PAGE_ALIGN(func) - PAGE_SIZE, prot_size, PROT_READ | PROT_EXEC);
    } else {
        int len = CodeCopy(buf, func, BYTES_SIZE_REL);
        if (len == 0) {
            mprotect(hook_buf, 65536, PROT_READ | PROT_EXEC);
            return NULL;
        }
        mprotect(PAGE_ALIGN(func) - PAGE_SIZE, prot_size,
                 PROT_READ | PROT_WRITE | PROT_EXEC);
        ConstructJmpRel((unsigned char *)buf + len, (unsigned char*)func + len);
        ConstructJmpRel(func, new_func);
        mprotect(PAGE_ALIGN(func) - PAGE_SIZE, prot_size, PROT_READ | PROT_EXEC);
    }
    mprotect(hook_buf, 65536, PROT_READ | PROT_EXEC);
    num_hooks++;
    return buf;
}
