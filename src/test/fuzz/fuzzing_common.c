#include "orconfig.h"
#include "torint.h"
#include "util.h"
#include "torlog.h"
#include "backtrace.h"
#include "fuzzing.h"

extern const char tor_git_revision[];
const char tor_git_revision[] = "";

#define MAX_FUZZ_SIZE (128*1024)

#ifdef LLVM_FUZZ
int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  static int initialized = 0;
  if (!initialized) {
    if (fuzz_init() < 0)
      abort();
  }

  return fuzz_main(Data, Size);
}

#else /* Not LLVM_FUZZ, so AFL. */

int
main(int argc, char **argv)
{
  size_t size;
  char *input = read_file_to_str_until_eof(0, MAX_FUZZ_SIZE, &size);

  tor_threads_init();
  init_logging(1);

  if (argc > 1 && !strcmp(argv[1], "--info")) {
    log_severity_list_t sev;
    set_log_severity_config(LOG_INFO, LOG_ERR, &sev);
    add_stream_log(&sev, "stdout", 1);
    configure_backtrace_handler(NULL);
  }

  tor_assert(input);
  if (fuzz_init() < 0)
    abort();
  fuzz_main((const uint8_t*)input, size);
  tor_free(input);
  return 0;
}

#endif

