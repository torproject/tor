#!/usr/bin/perl -w

use strict;
my %syscalls = ();

while (<>) {
    if (/^#define (__NR_\w+) /) {
	$syscalls{$1} = 1;
    }
}

print <<EOL;
/* Automatically generated with
        gen_sandbox_syscalls.pl /usr/include/asm/unistd*.h
   Do not edit.
 */
static const struct {
  int syscall_num; const char *syscall_name;
} SYSCALLS_BY_NUMBER[] = {
EOL

for my $k (sort keys %syscalls) {
    my $name = $k;
    $name =~ s/^__NR_//;
    print <<EOL;
#ifdef $k
  { $k, "$name" },
#endif
EOL

}

print <<EOL
  {0, NULL}
};

EOL
