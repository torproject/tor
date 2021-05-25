# Release Series Lifecycle


## End Of Life On An Old Release Series

Here are the steps that the maintainer should take when an old Tor release
series reaches End of Life.

Note that they are _only_ for an entire series that has reached its planned
EOL: they do not apply to security-related deprecations of individual
patch versions.


### 1. Preliminaries

1. A few months before End of Life:
   Write a deprecation announcement.
   Send the announcement out with every new release announcement.

2. A month before End of Life:
   Send the announcement to tor-announce, tor-talk, tor-relays, and the
   packagers.


### 2. On The Day

1. Open tickets to remove the release from:
   - the jenkins builds
   - tor's Travis CI cron jobs
   - chutney's Travis CI tests
   - sbws' Travis CI tests
   - stem's Travis CI tests (but see
     https://github.com/torproject/stem/issues/51)
   - tor's scripts/git/gist-list-tor-branches.sh script

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

8. Open a ticket (if there is not one already) for authorities to
    start rejecting relays that are running that release series.
    This ticket should be targeted for at least a month or two
    after the series is officially EOL, unless there is an important
    reason to un-list relays early.

9. (LTS end-of-life only) Open a ticket (if appropriate) for updates to the
    set of required and recommended subprotocol versions.  (For the process
    here, see proposal 303.)

10. (LTS end-of-life only) Open a ticket to remove no-longer-needed
    consensus methods. (For the process here, see proposal 290.)

11. (All EOL) Open a ticket to grep for obsolete series names (e.g., "0.2.9"
    and "029") in tor, chutney, sbws, fallback-scripts, and so on. These
    should be updated or removed.

12. Finally, make sure this document is up to date with our latest
   process.

## Starting A New Release Series

Here are the steps that the maintainer should take to start new maint and
release branches for a stable release.

Note that they are _only_ for an entire series, when it first becomes stable:
they do not apply to security-related patch release versions.

(Ideally, do this immediately after a release.)

1. Start a new maint-x.y.z branch based on main, and a new
   release-x.y.z branch based on main. They should have the same
   starting point.

   Push both of these branches to the canonical git repository.

2. In the main branch, change the version to "0.x.y.0-alpha-dev". Run the
   update_versions.py script, and commit this version bump.

3. Tag the version bump with "tor-0.x.y.0-alpha-dev". Push the tag
   and main branch.

4. Open tickets for connecting the new branches to various other
   places.  See section 2 above for a list of affected locations.

5. Stop running practracker on maintenance and release branches:
   * Remove "check-best-practices" from the check-local Makefile
     target in the maint-x.y.z branch only.
   * Delete the file scripts/maint/practracker/.enable_practracker_in_hooks
     in the maint-x.y.z branch only.
   * Merge to release-x.y.z, but do not forward-port to the main branch.

6. Finally, make sure this document is up to date with our latest
   process.
