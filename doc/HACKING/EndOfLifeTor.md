
End of Life on an old release series
------------------------------------

Here are the steps that the maintainer should take when an old Tor release
series reaches End of Life.  Note that they are _only_ for entire series that
have reached their planned EOL: they do not apply to security-related
deprecations of individual versions.

=== 0. Preliminaries

0. A few months before End of Life:
   Write a deprecation announcement.
   Send the announcement out with every new release announcement.

1. A month before End of Life:
   Send the announcement to tor-announce, tor-talk, tor-relays, and the
   packagers.

=== 1. On the day

1. Open tickets to remove the release from:
   - the jenkins builds
   - tor's Travis CI cron jobs
   - chutney's Travis CI tests (#)
   - stem's Travis CI tests (#)

2. Close the milestone in Trac. To do this, go to Trac, log in,
   select "Admin" near the top of the screen, then select "Milestones" from
   the menu on the left.  Click on the milestone for this version, and
   select the "Completed" checkbox. By convention, we select the date as
   the End of Life date.

3. Replace NNN-backport with NNN-unreached-backport in all open trac tickets.

4. If there are any remaining tickets in the milestone:
     - merge_ready tickets are for backports:
       - if there are no supported releases for the backport, close the ticket
       - if there is an earlier (LTS) release for the backport, move the ticket
         to that release
     - other tickets should be closed (if we won't fix them) or moved to a
       supported release (if we will fix them)

5. Mail the end of life announcement to tor-announce, the packagers list,
   and tor-relays. The current list of packagers is in ReleasingTor.md.

6. Ask at least two of weasel/arma/Sebastian to remove the old version
   number from their approved versions list.

7. Update the CoreTorReleases wiki page.
