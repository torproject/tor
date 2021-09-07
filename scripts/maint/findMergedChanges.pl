#!/usr/bin/perl

use warnings;
use strict;

sub nChanges {
    my ($branches, $fname) = @_;
    local *F;
    # requires perl 5.8.  Avoids shell issues if we ever get a changes
    # file named by the parents of Little Johnny Tables.
    open F, "-|", "git", "log", "--no-merges", "--pretty=format:%H", $branches, "--", $fname
        or die "$!";
    my @changes = <F>;
    return scalar @changes
}

my $look_for_type = "merged";

if (! @ARGV) {
    print <<EOF
Usage:
   findMergedChanges.pl [--merged/--unmerged/--weird/--list] [--branch=<branchname] [--head=<branchname>] changes/*

A change is "merged" if it has ever been merged to release-0.2.4 and it has had
no subsequent changes in main.

A change is "unmerged" if it has never been merged to release-0.2.4 and it
has had changes in main.

A change is "weird" if it has been merged to release-0.2.4 and it *has* had
subsequent changes in main.

Suggested application:
   findMergedChanges.pl --merged changes/* | xargs -n 1 git rm

EOF
}

my $target_branch = "origin/release-0.2.4";
my $head = "origin/main";

while (@ARGV and $ARGV[0] =~ /^--/) {
    my $flag = shift @ARGV;
    if ($flag =~ /^--(weird|merged|unmerged|list)/) {
        $look_for_type = $1;
    } elsif ($flag =~ /^--branch=(\S+)/) {
        $target_branch = $1;
    } elsif ($flag =~ /^--head=(\S+)/) {
        $head = $1;
    } else {
        die "Unrecognized flag $flag";
    }
}

for my $changefile (@ARGV) {
    my $n_merged = nChanges($target_branch, $changefile);
    my $n_postmerged = nChanges("${target_branch}..${head}", $changefile);
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
