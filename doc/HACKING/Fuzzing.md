= Fuzzing Tor

To run the fuzzing test cases in a deterministic fashion, use:
  make fuzz

  [I've turned this off for now. - NM]

To build the fuzzing harness binaries, use:
  make fuzzers

== Guided Fuzzing with AFL

There is no HTTPS, hash, or signature for American Fuzzy Lop's source code, so
its integrity can't be verified. That said, you really shouldn't fuzz on a
machine you care about, anyway.

To Build:
  Get AFL from http://lcamtuf.coredump.cx/afl/ and unpack it
  cd afl
  make
  cd ../tor
  PATH=$PATH:../afl/ CC="../afl/afl-gcc" ./configure --enable-expensive-hardening
  AFL_HARDEN=1 make clean fuzz

To Find The ASAN Memory Limit: (64-bit only)

On 64-bit platforms, afl needs to know how much memory ASAN uses.
Or, you can configure tor without --enable-expensive-hardening, then use
  make fuzz
to run the generated test cases through an ASAN-enabled fuzz-http.
Read afl/docs/notes_for_asan.txt for more details.

  Download recidivm from http://jwilk.net/software/recidivm
  Download the signature
  Check the signature
  tar xvzf recidivm*.tar.gz
  cd recidivm*
  make
  /path/to/recidivm -v src/test/fuzz_dir
  Use the final "ok" figure as the input to -m when calling afl-fuzz
  (Normally, recidivm would output a figure automatically, but in some cases,
  the fuzzing harness will hang when the memory limit is too small.)

You could also just say "none" instead of the memory limit below, if you
don't care about memory limits.


To Run:
  mkdir -p src/test/fuzz/fuzz_http_findings
  ../afl/afl-fuzz -i src/test/fuzz/data/http -x src/test/fuzz/dict/http -o src/test/fuzz/fuzz_http_findings -m <asan-memory-limit> -- src/test/fuzz_dir


AFL has a multi-core mode, check the documentation for details.
You might find the included fuzz-multi.sh script useful for this.

macOS (OS X) requires slightly more preparation, including:
* using afl-clang (or afl-clang-fast from the llvm directory)
* disabling external crash reporting (AFL will guide you through this step)

== Writing Tor fuzzers

A tor fuzzing harness should have:
* a fuzz_init() function to set up any necessary global state.
* a fuzz_main() function to receive input and pass it to a parser.
* a fuzz_cleanup() function to clear global state.

Most fuzzing frameworks will produce many invalid inputs - a tor fuzzing
harness should rejecting invalid inputs without crashing or behaving badly.

But the fuzzing harness should crash if tor fails an assertion, triggers a
bug, or accesses memory it shouldn't. This helps fuzzing frameworks detect
"interesting" cases.

== Triaging Issues

Crashes are usually interesting, particularly if using AFL_HARDEN=1 and --enable-expensive-hardening. Sometimes crashes are due to bugs in the harness code.

Hangs might be interesting, but they might also be spurious machine slowdowns.
Check if a hang is reproducible before reporting it. Sometimes, processing
valid inputs may take a second or so, particularly with the fuzzer and
sanitizers enabled.

To see what fuzz-http is doing with a test case, call it like this:
  src/test/fuzz/fuzz-http --debug < /path/to/test.case

(Logging is disabled while fuzzing to increase fuzzing speed.)

== Reporting Issues

Please report any issues discovered using the process in Tor's security issue
policy:

https://trac.torproject.org/projects/tor/wiki/org/meetings/2016SummerDevMeeting/Notes/SecurityIssuePolicy
