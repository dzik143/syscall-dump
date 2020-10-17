/******************************************************************************/
/*                                                                            */
/* Copyright (C) 2020 by Sylwester Wysocki <sw143@wp.pl>                      */
/*                                                                            */
/* Permission is hereby granted, free of charge, to any person obtaining a    */
/* copy of this software and associated documentation files (the "Software"), */
/* to deal in the Software without restriction, including without limitation  */
/* the rights to use, copy, modify, merge, publish, distribute, sublicense,   */
/* and/or sell copies of the Software, and to permit persons to whom the      */
/* Software is furnished to do so, subject to the following conditions:       */
/*                                                                            */
/* The above copyright notice and this permission notice shall be included    */
/* in all copies or substantial portions of the Software.                     */
/*                                                                            */
/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,            */
/* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF         */
/* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.     */
/* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY       */
/* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT  */
/* OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR   */
/* THE USE OR OTHER DEALINGS IN THE SOFTWARE.                                 */
/*                                                                            */
/******************************************************************************/

// Created on: 2020-10-17
// Last modified on: 2020-10-17

#include <stdio.h>
#include <stdint.h>
#include <windows.h>

// -----------------------------------------------------------------------------
//                              Helper macros
// -----------------------------------------------------------------------------

#define VERSION_STRING "1.0"

#define READ_BYTE (BUF, OFFSET) ((uint8_t)  (*(uint8_t  *)(((uint8_t *) BUF) + OFFSET)))
#define READ_WORD (BUF, OFFSET) ((uint16_t) (*(uint16_t *)(((uint8_t *) BUF) + OFFSET)))
#define READ_DWORD(BUF, OFFSET) ((uint32_t) (*(uint32_t *)(((uint8_t *) BUF) + OFFSET)))
#define READ_QWORD(BUF, OFFSET) ((uint64_t) (*(uint64_t *)(((uint8_t *) BUF) + OFFSET)))

// -----------------------------------------------------------------------------
//                             Helper functions
// -----------------------------------------------------------------------------

void _printAbout()
{
  printf("Syscall-dump v.%s for Windows 64-bit, Freeware\n", VERSION_STRING);
  printf("Copyright (C) 2020, Sylwester Wysocki <sw143@wp.pl>\n");
  printf("Source code available at https://github.com/dzik143/syscall-dump\n");
  printf("\n");

  printf("Syscall usage:\n");
  printf("  mov r10, <first parameter> ; rcx cannot be used for syscalls\n");
  printf("  mov eax, <syscall id>      ; number readed from below table\n");
  printf("  syscall                    ; perform so-called fast kernel call\n");
  printf("\n");
}

void _printHeadRow(const char *a, const char *b, const char *c, const char *d)
{
  printf("%4s | %4s | %7s | %s\n", a, b, c, d);
}

void _syscallDump(const char *moduleName)
{
  uint8_t *base = (uint8_t *) LoadLibrary(moduleName);

  if (moduleName)
  {
    // Print table header.
    printf("Module: %s\n", moduleName);
    printf("============================================================\n\n");

    _printHeadRow("no." , "entry" , "syscall" , "function name");
    _printHeadRow("   " , "RVA  " , "id     " , "             ");
    _printHeadRow("---" , "-----" , "-------" , "-----------------------------------");

    // Find ExportsTable in the module memory.
    // Possible improvement: Validate data.
    // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#export-directory-table
    void *peHeader     = base + READ_DWORD(base, 60);
    void *exportsTable = base + READ_DWORD(peHeader, 24 + 112);

    uint32_t  numberOfNamePointers  = READ_DWORD(exportsTable, 24);
    uint32_t *exportAddressTableRva = (uint32_t *) (base + READ_DWORD(exportsTable, 28));
    uint32_t *namePointerTableRva   = (uint32_t *) (base + READ_DWORD(exportsTable, 32));
    uint16_t *ordinalTableRva       = (uint16_t *) (base + READ_DWORD(exportsTable, 36));

    // Scan exported functions one-by-one.
    for (int procIdx = 0; procIdx < numberOfNamePointers; procIdx++)
    {
      // Fetch pointer to function name.
      const char *functionName = (const char *) (base + namePointerTableRva[procIdx]);

      if (*functionName)
      {
        // Fetch function ordinal.
        uint16_t functionOrdinal = ordinalTableRva[procIdx];

        // Fetch function entry point.
        uint32_t  functionEntryRva = exportAddressTableRva[functionOrdinal];
        uint8_t  *functionEntry    = base + functionEntryRva;

        // We're searching for functions, wchich are dump wrappers
        // for syscalls.
        const uint8_t syscallPattern[] = {
          0x4c, 0x8b, 0xd1,                // 0  +3 | mov r10, rcx
          0xb8, 0,    0,    0, 0,          // 3  +5 | mov eax, <syscall id>
          0xf6, 0x04, 0x25, 0, 0, 0, 0, 0, // 8  +8 | test byte [xx xx xx xx], yy
          0x75, 0x03,                      // 16 +2 | jnz +3
          0x0f, 0x05,                      // 18 +2 | syscall
          0xc3                             // 20 +1 | ret
        };                                 // 21 total

        // Compare function body byte-by-byte with pattern.
        int isMatched = 1;

        for (int i = 0; i < sizeof(syscallPattern); i++)
        {
          if (syscallPattern[i] && (syscallPattern[i] != functionEntry[i]))
          {
            // At least one byte not matched.
            // Don't go on anymore.
            isMatched = 0;
            break;
          }
        }

        if (isMatched)
        {
          // Function body matches to syscall pattern.
          // Read syscall id from it.
          int syscallId = READ_DWORD(functionEntry, 4);

          // Print one function entry per line.
          printf(
            "%4d | %4x | %7x | %s\n",
            procIdx,
            functionEntryRva,
            syscallId,
            functionName
          );
        }

        // Go to next entry.
        procIdx++;
      }
    }

    FreeLibrary((HMODULE) base);
  }
}

// -----------------------------------------------------------------------------
//                                Entry point
// -----------------------------------------------------------------------------

int main()
{
  _printAbout();
  _syscallDump("ntdll.dll");
  return 0;
}
