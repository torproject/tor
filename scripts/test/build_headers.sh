#!/bin/sh

mkdir -p test_headers
rm -f test_headers/Makefile

cat >> test_headers/Makefile <<EOF

all: objects

%.o: %.c
	gcc -c -Wall -Werror @../warning_flags -I .. -I ../src -I ../src/ext -o \$@ \$<
EOF

add_obj()
{
    NAME="$1"
    HDR="$2"
    cat >> test_headers/Makefile <<EOF
objects: ${NAME}.o
${NAME}.o: ${NAME}.c ${HDR}
EOF
}


for hdr in $(cd ./src && find lib core feature app -name '*.h'); do
  name=$(basename "$hdr" .h)

  grep '^ *# *ifdef *[A-Z_]*_PRIVATE' "src/${hdr}" | \
      sed -e 's/.*ifdef */#define /' | \
      uniq > \
           test_headers/"${name}"_t.c

  cat >>test_headers/"${name}"_t.c <<EOF

#include "$hdr"

EOF

  add_obj "${name}_t" "../src/${hdr}"

done
