#!/usr/bin/perl -w

$CONFIGURE_IN = './configure.in';
$ORCONFIG_H = './src/win32/orconfig.h';
$TOR_NSI = './contrib/tor-mingw.nsi.in';

sub demand {
    my $fn = shift;
    die "Missing file $fn" unless (-f $fn);
}

demand($CONFIGURE_IN);
demand($ORCONFIG_H);
demand($TOR_NSI);

# extract version from configure.in

open(F, $CONFIGURE_IN) or die "$!";
$version = undef;
while (<F>) {
    if (/AM_INIT_AUTOMAKE\(tor,\s*([^\)]*)\)/) {
	$version = $1;
	last;
    }
}
die "No version found" unless $version;
print "Tor version is $version\n";
close F;

sub correctversion {
    my ($fn, $defchar) = @_;
    undef $/;
    open(F, $fn) or die "$!";
    my $s = <F>;
    close F;
    if ($s =~ /^$defchar(?:)define\s+VERSION\s+\"([^\"]+)\"/m) {
	$oldver = $1;
	if ($oldver ne $version) {
	    print "Version mismatch in $fn: It thinks that the version is $oldver.  Fixing.\n";
	    $line = $defchar . "define VERSION \"$version\"";
	    open(F, ">$fn.bak");
	    print F $s;
	    close F;
	    $s =~ s/^$defchar(?:)define\s+VERSION.*?$/$line/m;
	    open(F, ">$fn");
	    print F $s;
	    close F;	    
	} else {
	    print "$fn has the correct version. Good.\n";
	}
    } else {
	print "Didn't find a version line in $fn -- uh oh.\n";
    }
}

correctversion($TOR_NSI, "!");
correctversion($ORCONFIG_H, "#");
