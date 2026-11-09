#include <stddef.h>
#include <stdint.h>

/* upstream fuzz/ harnesses expose FuzzerInitialize/FuzzerTestOneInput; this is fuzz/driver.c's
   libFuzzer branch, which upstream only compiles when configured with enable-fuzz-libfuzzer. */
int FuzzerInitialize(int *argc, char ***argv);
int FuzzerTestOneInput(const uint8_t *buf, size_t len);

int LLVMFuzzerInitialize(int *argc, char ***argv) { return FuzzerInitialize(argc, argv); }
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) { return FuzzerTestOneInput(buf, len); }
