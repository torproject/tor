#!/usr/bin/perl -w

for $fn (@ARGV) {
    open(F, "$fn");
    $lastnil = 0;
    $incomment = 0;
    while (<F>) {
	## Warn about windows-style newlines.
        if (/\r/) {
            print "       CR:$fn:$.\n";
        }
	## Warn about tabs.
        if (/\t/) {
            print "      TAB:$fn:$.\n";
        }
	## Warn about trailing whitespace.
        if (/ +$/) {
            print "Space\@EOL:$fn:$.\n";
        }
	## Warn about control keywords without following space.
	if (/\s(?:if|while|for|switch)\(/) {
	    print "      KW(:$fn:$.\n";
	}
	## Warn about multiple empty lines.
        if ($lastnil && /^$/) {
            print " DoubleNL:$fn:$.\n";
        } elsif (/^$/) {
            $lastnil = 1;
        } else {
            $lastnil = 0;
        }
	### Juju to skip over comments and strings, since the tests
	### we're about to do are okay there.
	if ($incomment) {
	    if (m!\*/!) {
		s!.*?\*/!!;
		$incomment = 0;
	    } else {
		next;
	    }
	}
	if (m!/\*.*?\*/!) {
	    s!\s*/\*.*?\*/!!;
	} elsif (m!/\*!) {
	    s!\s*/\*!!;
	    $incomment = 1;
	    next;
	}
	s!"(?:[^\"]+|\\.)*"!"X"!g;
	next if /^\#/;
	## Warn about C++-style comments.
	if (m!//!) {
	#    print "       //:$fn:$.\n";
	    s!//.*!!;
	}
        ## Warn about braces preceded by non-space.
	if (/([^\s])\{/) {
	    print "       $1\{:$fn:$.\n";
	}
	## Warn about multiple internal spaces.
	#if (/[^\s,:]\s{2,}[^\s\\=]/) {
	#    print "     X  X:$fn:$.\n";
	#}
	## Warn about { with stuff after.
	#s/\s+$//;
	#if (/\{[^\}\\]+$/) {
	#    print "     {X:$fn:$.\n";
	#}
	## Warn about function calls with space before parens.
	if (/(\w+)\s\(/) {
	    if ($1 ne "if" and $1 ne "while" and $1 ne "for" and 
		$1 ne "switch" and $1 ne "return" and $1 ne "int" and 
                $1 ne "void" and $1 ne "__attribute__") {
		print "     fn ():$fn:$.\n";
	    }
	}
    }
    close(F);
}
