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
    DRAFT OPEN NEEDS-REVISION NEEDS-RESEARCH ACCEPTED META FINISHED CLOSED
    SUPERSEDED DEAD};

for my $f (@files) {
    my $num = substr($f, 0, 3);
    my $status = undef;
    my $title = undef;
    my $implemented_in = undef;
    my $target = undef;
    my $alleged_fname = undef;
    if ($f !~ /\.txt/) { print "$f doesn't end with .txt\n"; }
    open(F, "$f");
    while (<F>) {
	last if (/^\s*$/);
	if (/^Status: (.*)/) {
	    $status = uc $1;
	    chomp $status;
	}
	if (/^Filename: (.*)/) {
	    $alleged_fname = $1;
	    chomp $alleged_fname;
	}
	if (/^Title: (.*)/) {
	    $title = $1;
	    $title =~ s/\.$//;
	    chomp $title;
	}
	if (/^Implemented-In: (.*)/) {
	    $implemented_in = $1;
	    chomp $implemented_in;
	}
	if (/^Target: (.*)/) {
	    $target = $1;
	    chomp $target;
	}
    }
    close F;
    die "Proposal $num has no status line" if (!defined $status);
    die "I've never heard of status $status in proposal $num"
	unless (grep(/$status/, @KNOWN_STATUSES) == 1);
    die "Proposal $num has no title line" if (!defined $title);
    die "Proposal $num has no Filename line" unless (defined $alleged_fname);
    die "Proposal $num says its fname is $alleged_fname, but it's really $f"
	if ($alleged_fname ne $f);
    print "No Target for proposal $num\n" if (($status eq 'OPEN' or
					       $status eq 'ACCEPTED')
					      and !defined $target);
    print "No Implemented-In for proposal $num\n"
	if (($status eq 'CLOSED' or $status eq 'FINISHED')
	    and !defined $implemented_in);

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
