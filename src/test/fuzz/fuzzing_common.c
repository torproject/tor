#include "orconfig.h"
#include "or.h"
#include "backtrace.h"
#include "config.h"
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

  tor_threads_init();
  init_logging(1);

  /* Disable logging by default to speed up fuzzing. */
  int loglevel = LOG_ERR;

  /* Initialise logging first */
  init_logging(1);
  configure_backtrace_handler(get_version());

  for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--warn")) {
      loglevel = LOG_WARN;
    } else if (!strcmp(argv[i], "--notice")) {
      loglevel = LOG_NOTICE;
    } else if (!strcmp(argv[i], "--info")) {
      loglevel = LOG_INFO;
    } else if (!strcmp(argv[i], "--debug")) {
      loglevel = LOG_DEBUG;
    }
  }

  {
    log_severity_list_t s;
    memset(&s, 0, sizeof(s));
    set_log_severity_config(loglevel, LOG_ERR, &s);
    /* ALWAYS log bug warnings. */
    s.masks[LOG_WARN-LOG_ERR] |= LD_BUG;
    add_stream_log(&s, "", fileno(stdout));
  }

  /* Make BUG() and nonfatal asserts crash */
  tor_set_failed_assertion_callback(abort);

  if (fuzz_init() < 0)
    abort();

#ifdef __AFL_HAVE_MANUAL_CONTROL
  /* Tell AFL to pause and fork here - ignored if not using AFL */
  __AFL_INIT();
#endif

  char *input = read_file_to_str_until_eof(0, MAX_FUZZ_SIZE, &size);
  tor_assert(input);
  fuzz_main((const uint8_t*)input, size);
  tor_free(input);

  if (fuzz_cleanup() < 0)
    abort();
  return 0;
}

#endif

