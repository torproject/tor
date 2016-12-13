MEMLIMIT_BYTES=21990500990976

N_CPUS=1
if [ $# -ge 1 ]; then
    N_CPUS="$1"
    shift
fi

FILTER=echo

for i in `seq -w "$N_CPUS"`; do
    if [ "$i" -eq 1 ]; then
        if [ "$N_CPUS" -eq 1 ]; then
            INSTANCE=""
            NUMBER=""
        else
            INSTANCE="-M"
            NUMBER="$i"
        fi
    else
        INSTANCE="-S"
        NUMBER="$i"
    fi
    # use whatever remains on the command-line to prefix the fuzzer command
    # you have to copy and paste and run these commands yourself
    "$FILTER" "$@" \
        ../afl/afl-fuzz \
        -i src/test/fuzz/fuzz_dir_testcase \
        -o src/test/fuzz/fuzz_dir_findings \
        -x src/test/fuzz/fuzz_dir_dictionary/fuzz_dir_http_header.dct \
        -m "$MEMLIMIT_BYTES" \
        "$INSTANCE" "$NUMBER" \
        -- src/test/fuzz_dir
done
