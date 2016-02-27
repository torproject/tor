#!/usr/bin/perl -i -w -p

$NEWYEAR=2016;

s/Copyright(.*) (201[^6]), The Tor Project/Copyright$1 $2-${NEWYEAR}, The Tor Project/;

s/Copyright(.*)-(20..), The Tor Project/Copyright$1-${NEWYEAR}, The Tor Project/;
