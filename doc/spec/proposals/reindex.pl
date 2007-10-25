#!/usr/bin/perl -w
# Copyright 2007 Nick Mathewson.  See LICENSE for licensing information.

use strict;

my $propdir = ".";
local *DIR;
local *F;

opendir(DIR, $propdir) || die "Can't open $propdir";
my @files = sort grep { /^\d\d\d-.*[^\~]$/ } readdir(DIR);
closedir DIR;

my %title = ();
my %status = ();

my @KNOWN_STATUSES = qw{
    OPEN ACCEPTED NEEDS-RESEARCH META FINISHED CLOSED SUPERSEDED DEAD};

for my $f (@files) {
    my $num = substr($f, 0, 3);
    my $status = undef;
    my $title = undef;
    open(F, "$f");
    while (<F>) {
	last if (/^\s*$/);
	if (/^Status: (.*)/) {
	    $status = uc $1;
	    chomp $status;
	}
	if (/^Title: (.*)/) {
	    $title = $1;
	    $title =~ s/\.$//;
	    chomp $title;
	}
    }
    close F;
    die "I've never heard of status $status in proposal $num"
	unless (grep(/$status/, @KNOWN_STATUSES) == 1);
    die "Proposal $num has a bad status line" if (!defined $status);
    die "Proposal $num has a bad title line" if (!defined $title);
    $title{$num} = $title;
    $status{$num} = $status;
}

local *OUT;
open(OUT, ">000-index.txt.tmp");

open(F, "000-index.txt") or die "Can't open index file.";
while (<F>) {
    print OUT;
    last if (/^={3,}/);
}
close(F);

print OUT "Proposals by number:\n\n";

for my $num (sort keys %title) {
    print OUT "$num  $title{$num} [$status{$num}]\n";
}

print OUT "\n\nProposals by status:\n\n";
for my $status (@KNOWN_STATUSES) {
    print OUT " $status:\n";
    for my $num (sort keys %status) {
	next unless ($status{$num} eq $status);
	print OUT "   $num  $title{$num}\n";
    }
}

rename('000-index.txt.tmp', '000-index.txt');
