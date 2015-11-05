Useful tools
============

These aren't strictly necessary for hacking on Tor, but they can help track
down bugs.

Jenkins
-------

    https://jenkins.torproject.org

Dmalloc
-------

The dmalloc library will keep track of memory allocation, so you can find out
if we're leaking memory, doing any double-frees, or so on.

    dmalloc -l -/dmalloc.log
    (run the commands it tells you)
    ./configure --with-dmalloc

Valgrind
--------

    valgrind --leak-check=yes --error-limit=no --show-reachable=yes src/or/tor

(Note that if you get a zillion openssl warnings, you will also need to
pass `--undef-value-errors=no` to valgrind, or rebuild your openssl
with `-DPURIFY`.)

Coverity
--------

Nick regularly runs the coverity static analyzer on the Tor codebase.

The preprocessor define `__COVERITY__` is used to work around instances
where coverity picks up behavior that we wish to permit.

clang Static Analyzer
---------------------

The clang static analyzer can be run on the Tor codebase using Xcode (WIP)
or a command-line build.

The preprocessor define `__clang_analyzer__` is used to work around instances
where clang picks up behavior that we wish to permit.

clang Runtime Sanitizers
------------------------

To build the Tor codebase with the clang Address and Undefined Behavior
sanitizers, see the file `contrib/clang/sanitize_blacklist.txt`.

Preprocessor workarounds for instances where clang picks up behavior that
we wish to permit are also documented in the blacklist file.

Running lcov for unit test coverage
-----------------------------------

Lcov is a utility that generates pretty HTML reports of test code coverage.
To generate such a report:

    ./configure --enable-coverage
    make
    make coverage-html
    $BROWSER ./coverage_html/index.html

This will run the tor unit test suite `./src/test/test` and generate the HTML
coverage code report under the directory `./coverage_html/`. To change the
output directory, use `make coverage-html HTML_COVER_DIR=./funky_new_cov_dir`.

Coverage diffs using lcov are not currently implemented, but are being
investigated (as of July 2014).

Running the unit tests
----------------------

To quickly run all the tests distributed with Tor:

    make check

To run the fast unit tests only:

    make test

To selectively run just some tests (the following can be combined
arbitrarily):

    ./src/test/test <name_of_test> [<name of test 2>] ...
    ./src/test/test <prefix_of_name_of_test>.. [<prefix_of_name_of_test2>..] ...
    ./src/test/test :<name_of_excluded_test> [:<name_of_excluded_test2]...

To run all tests, including those based on Stem or Chutney:

    make test-full

To run all tests, including those based on Stem or Chutney that require a
working connection to the internet:

    make test-full-online

Running gcov for unit test coverage
-----------------------------------

    ./configure --enable-coverage
    make
    make check
    # or--- make test-full ? make test-full-online?
    mkdir coverage-output
    ./scripts/test/coverage coverage-output

(On OSX, you'll need to start with `--enable-coverage CC=clang`.)

Then, look at the .gcov files in `coverage-output`.  '-' before a line means
that the compiler generated no code for that line.  '######' means that the
line was never reached.  Lines with numbers were called that number of times.

If that doesn't work:

   * Try configuring Tor with `--disable-gcc-hardening`
   * You might need to run `make clean` after you run `./configure`.

If you make changes to Tor and want to get another set of coverage results,
you can run `make reset-gcov` to clear the intermediary gcov output.

If you have two different `coverage-output` directories, and you want to see
a meaningful diff between them, you can run:

    ./scripts/test/cov-diff coverage-output1 coverage-output2 | less

In this diff, any lines that were visited at least once will have coverage
"1".  This lets you inspect what you (probably) really want to know: which
untested lines were changed?  Are there any new untested lines?

Running integration tests
-------------------------

We have the beginnings of a set of scripts to run integration tests using
Chutney. To try them, set CHUTNEY_PATH to your chutney source directory, and
run `make test-network`.

We also have scripts to run integration tests using Stem.  To try them, set
`STEM_SOURCE_DIR` to your Stem source directory, and run `test-stem`.

Profiling Tor with oprofile
---------------------------

The oprofile tool runs (on Linux only!) to tell you what functions Tor is
spending its CPU time in, so we can identify performance bottlenecks.

Here are some basic instructions

 - Build tor with debugging symbols (you probably already have, unless
   you messed with CFLAGS during the build process).
 - Build all the libraries you care about with debugging symbols
   (probably you only care about libssl, maybe zlib and Libevent).
 - Copy this tor to a new directory
 - Copy all the libraries it uses to that dir too (`ldd ./tor` will
   tell you)
 - Set LD_LIBRARY_PATH to include that dir.  `ldd ./tor` should now
   show you it's using the libs in that dir
 - Run that tor
 - Reset oprofiles counters/start it
   * `opcontrol --reset; opcontrol --start`, if Nick remembers right.
 - After a while, have it dump the stats on tor and all the libs
   in that dir you created.
   * `opcontrol --dump;`
   * `opreport -l that_dir/*`
 - Profit

Generating and analyzing a callgraph
------------------------------------

1. Run `./scripts/maint/generate_callgraph.sh`.  This will generate a
   bunch of files in a new ./callgraph directory.

2. Run `./scripts/maint/analyze_callgraph.py callgraph/src/*/*`.  This
   will do a lot of graph operations and then dump out a new
   `callgraph.pkl` file, containing data in Python's 'pickle' format.

3. Run `./scripts/maint/display_callgraph.py`.  It will display:
    - the number of functions reachable from each function.
    - all strongly-connnected components in the Tor callgraph
    - the largest bottlenecks in the largest SCC in the Tor callgraph.

Note that currently the callgraph generator can't detect calls that pass
through function pointers.

Getting emacs to edit Tor source properly
-----------------------------------------

Nick likes to put the following snippet in his .emacs file:


    (add-hook 'c-mode-hook
          (lambda ()
            (font-lock-mode 1)
            (set-variable 'show-trailing-whitespace t)

            (let ((fname (expand-file-name (buffer-file-name))))
              (cond
               ((string-match "^/home/nickm/src/libevent" fname)
                (set-variable 'indent-tabs-mode t)
                (set-variable 'c-basic-offset 4)
                (set-variable 'tab-width 4))
               ((string-match "^/home/nickm/src/tor" fname)
                (set-variable 'indent-tabs-mode nil)
                (set-variable 'c-basic-offset 2))
               ((string-match "^/home/nickm/src/openssl" fname)
                (set-variable 'indent-tabs-mode t)
                (set-variable 'c-basic-offset 8)
                (set-variable 'tab-width 8))
            ))))


You'll note that it defaults to showing all trailing whitespace.  The `cond`
test detects whether the file is one of a few C free software projects that I
often edit, and sets up the indentation level and tab preferences to match
what they want.

If you want to try this out, you'll need to change the filename regex
patterns to match where you keep your Tor files.

If you use emacs for editing Tor and nothing else, you could always just say:


    (add-hook 'c-mode-hook
        (lambda ()
            (font-lock-mode 1)
            (set-variable 'show-trailing-whitespace t)
            (set-variable 'indent-tabs-mode nil)
            (set-variable 'c-basic-offset 2)))


There is probably a better way to do this.  No, we are probably not going
to clutter the files with emacs stuff.


Doxygen
-------

We use the 'doxygen' utility to generate documentation from our
source code. Here's how to use it:

  1. Begin every file that should be documented with

         /**
          * \file filename.c
          * \brief Short description of the file.
          */

     (Doxygen will recognize any comment beginning with /** as special.)

  2. Before any function, structure, #define, or variable you want to
     document, add a comment of the form:

        /** Describe the function's actions in imperative sentences.
         *
         * Use blank lines for paragraph breaks
         *   - and
         *   - hyphens
         *   - for
         *   - lists.
         *
         * Write <b>argument_names</b> in boldface.
         *
         * \code
         *     place_example_code();
         *     between_code_and_endcode_commands();
         * \endcode
         */

  3. Make sure to escape the characters `<`, `>`, `\`, `%` and `#` as `\<`,
     `\>`, `\\`, `\%` and `\#`.

  4. To document structure members, you can use two forms:

        struct foo {
          /** You can put the comment before an element; */
          int a;
          int b; /**< Or use the less-than symbol to put the comment
                 * after the element. */
        };

  5. To generate documentation from the Tor source code, type:

        $ doxygen -g

     to generate a file called `Doxyfile`.  Edit that file and run
     `doxygen` to generate the API documentation.

  6. See the Doxygen manual for more information; this summary just
     scratches the surface.
