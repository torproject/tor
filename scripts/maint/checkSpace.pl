#!/usr/bin/perl -w

if ($ARGV[0] =~ /^-/) {
    $lang = shift @ARGV;
    $C = ($lang eq '-C');
#    $TXT = ($lang eq '-txt');
}

for $fn (@ARGV) {
    open(F, "$fn");
    $lastnil = 0;
    $lastline = "";
    $incomment = 0;
    while (<F>) {
        ## Warn about windows-style newlines.
	#    (We insist on lines that end with a single LF character, not
	#    CR LF.)
        if (/\r/) {
            print "       CR:$fn:$.\n";
        }
        ## Warn about tabs.
	#    (We only use spaces)
        if (/\t/) {
            print "      TAB:$fn:$.\n";
        }
        ## Warn about labels that don't have a space in front of them
	#    (We indent every label at least one space)
        if (/^[a-zA-Z_][a-zA-Z_0-9]*:/) {
            print "nosplabel:$fn:$.\n";
        }
        ## Warn about trailing whitespace.
	#    (We don't allow whitespace at the end of the line; make your
	#    editor highlight it for you so you can stop adding it in.)
        if (/ +$/) {
            print "Space\@EOL:$fn:$.\n";
        }
        ## Warn about control keywords without following space.
	#    (We put a space after every 'if', 'while', 'for', 'switch', etc)
        if ($C && /\s(?:if|while|for|switch)\(/) {
            print "      KW(:$fn:$.\n";
        }
        ## Warn about #else #if instead of #elif.
        #    (We only allow #elif)
        if (($lastline =~ /^\# *else/) and ($_ =~ /^\# *if/)) {
            print " #else#if:$fn:$.\n";
        }
        ## Warn about some K&R violations
        #    (We use K&R-style C, where open braces go on the same line as
        #    the statement that introduces them.  In other words:
        #          if (a) {
        #            stuff;
        #          } else {
        #            other stuff;
        #          }
        if (/^\s+\{/ and $lastline =~ /^\s*(if|while|for|else if)/ and
	    $lastline !~ /\{$/) {
            print "non-K&R {:$fn:$.\n";
	}
        if (/^\s*else/ and $lastline =~ /\}$/) {
	    print "  }\\nelse:$fn:$.\n";
	}
        $lastline = $_;
        ## Warn about unnecessary empty lines.
        #   (Don't put an empty line before a line that contains nothing
        #   but a closing brace.)
        if ($lastnil && /^\s*}\n/) {
            print "  UnnecNL:$fn:$.\n";
        }
        ## Warn about multiple empty lines.
        #   (At most one blank line in a row.)
        if ($lastnil && /^$/) {
            print " DoubleNL:$fn:$.\n";
        } elsif (/^$/) {
            $lastnil = 1;
        } else {
            $lastnil = 0;
        }
        ## Terminals are still 80 columns wide in my world.  I refuse to
        ## accept double-line lines.
        #   (Don't make lines wider than 80 characters, including newline.)
        if (/^.{80}/) {
            print "     Wide:$fn:$.\n";
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
	    #   (Use C style comments only.)
            if (m!//!) {
                #    print "       //:$fn:$.\n";
                s!//.*!!;
            }
            ## Warn about unquoted braces preceded by non-space.
	    #   (No character except a space should come before a {)
            if (/([^\s'])\{/) {
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
	    #   (Don't put a space between the name of a function and its
	    #   arguments.)
            if (/(\w+)\s\(([A-Z]*)/) {
                if ($1 ne "if" and $1 ne "while" and $1 ne "for" and
                    $1 ne "switch" and $1 ne "return" and $1 ne "int" and
                    $1 ne "elsif" and $1 ne "WINAPI" and $2 ne "WINAPI" and
                    $1 ne "void" and $1 ne "__attribute__" and $1 ne "op") {
                    print "     fn ():$fn:$.\n";
                }
            }
            ## Warn about functions not declared at start of line.
	    #    (When you're declaring functions, put "static" and "const"
	    #    and the return type on one line, and the function name at
	    #    the start of a new line.)
            if ($in_func_head ||
                ($fn !~ /\.h$/ && /^[a-zA-Z0-9_]/ &&
                 ! /^(?:const |static )*(?:typedef|struct|union)[^\(]*$/ &&
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
    ## Warn if the file doesn't end with a blank line.
    #    (End each file with a single blank line.)
    if (! $lastnil) {
        print "  EOL\@EOF:$fn:$.\n";
    }
    close(F);
}

