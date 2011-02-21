#!/usr/bin/perl

use warnings;
use strict;

sub nChanges {
    my ($branches, $fname) = @_;
    local *F;
    # requires perl 5.8.  Avoids shell issues if we ever get a changes
    # file named by the parents of Little Johnny Tables.
    open F, "-|", "git", "log", "--pretty=format:%H", $branches, "--", $fname
	or die "$!";
    my @changes = <F>;
    return scalar @changes
}

my $look_for_type = "merged";

while (@ARGV and $ARGV[0] =~ /^--/) {
    my $flag = shift @ARGV;
    if ($flag =~ /^--(weird|merged|unmerged|list)/) {
	$look_for_type = $1;
    } else {
	die "Unrecognized flag $flag";
    }
}

for my $changefile (@ARGV) {
    my $n_merged = nChanges("origin/release-0.2.2", $changefile);
    my $n_postmerged = nChanges("origin/release-0.2.2..origin/master", $changefile);
    my $type;

    if ($n_merged != 0 and $n_postmerged == 0) {
	$type = "merged";
    } elsif ($n_merged == 0 and $n_postmerged != 0) {
	$type = "unmerged";
    } else {
	$type = "weird";
    }

    if ($type eq $look_for_type) {
	print "$changefile\n";
    } elsif ($look_for_type eq 'list') {
	printf "% 8s: %s\n", $type, $changefile;
    }
}
