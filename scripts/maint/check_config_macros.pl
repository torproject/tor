#!/usr/bin/perl -w

use strict;

my @macros = ();

open(F, 'orconfig.h.in');
while(<F>) {
    if (/^#undef +([A-Za-z0-9_]*)/) {
        push @macros, $1;
    }
}
close F;

for my $m (@macros) {
    my $s = `git grep '$m' src`;
    if ($s eq '') {
        print "Unused: $m\n";
    }
}
