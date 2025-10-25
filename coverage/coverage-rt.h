#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t*, size_t);
void executeSingleTest(const char*);
int getEntryType(const char*);
