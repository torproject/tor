#!/usr/bin/perl -w

for $fn (@ARGV) {
    open(F, "$fn");
    $lastnil = 0;
    while (<F>) {
        if (/\r/) {
            print "       CR:$fn:$.\n";
        }
        if (/\t/) {
            print "      TAB:$fn:$.\n";
        }
        if (/ +$/) {
            print "Space\@EOL:$fn:$.\n";
        }
        if ($lastnil && /^$/) {
            print " DoubleNL:$fn:$.\n";
        } elsif (/^$/) {
            $lastnil = 1;
        } else {
            $lastnil = 0;
        }
    }
    close(F);
}
