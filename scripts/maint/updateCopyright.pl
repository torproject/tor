#!/usr/bin/perl -i -w -p

$NEWYEAR=2015;

s/Copyright(.*) (201[^5]), The Tor Project/Copyright$1 $2-${NEWYEAR}, The Tor Project/;

s/Copyright(.*)-(20..), The Tor Project/Copyright$1-${NEWYEAR}, The Tor Project/;
