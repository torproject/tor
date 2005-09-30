#!/usr/bin/perl -w

if ($ARGV[0] =~ /^-/) {
    $lang = shift @ARGV;
    $C = ($lang eq '-C');
#    $TXT = ($lang eq '-txt');
}

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
	if ($C && /\s(?:if|while|for|switch)\(/) {
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
	if ($C) {
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
	    ## Warn about functions not declared at start of line.
	    if ($in_func_head || 
		($fn !~ /\.h$/ && /^[a-zA-Z0-9_]/ &&
		 ! /^(?:static )?(?:typedef|struct|union)[^\(]*$/ &&
		 ! /= *\{$/ && ! /;$/)) {
		
		if (/.\{$/){
		    print "fn() {:$fn:$.\n";
		    $in_func_head = 0;
		} elsif (/^\S[^\(]* +\**[a-zA-Z0-9_]+\(/) {
		    $in_func_head = -1; # started with tp fn
		} elsif (/;$/) {
		    $in_func_head = 0;
		} elsif (/\{/) {
		    if ($in_func_head == -1) {
			print "tp fn():$fn:$.\n";
		    }
		    $in_func_head = 0;
		}
	    }
        }
    }
    if (! $lastnil) {
        print "  EOL\@EOF:$fn:$.\n";
    }
    close(F);
}
