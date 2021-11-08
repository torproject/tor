# How to Release Tor

Here are the steps that the maintainer should take when putting out a
new Tor release. It is split in 3 stages and coupled with our Tor CI Release
pipeline.

Before we begin, first rule is to make sure:

   - Our CI pass for each version to release
   - Coverity has no new alerts

## 0. Security Release

To start with, if you are doing a security release, this must be done few days
prior to the release:

   1. If this is going to be an important security release, give the packagers
      advance warning, via `tor-packagers@lists.torproject.org`.


## 1. Preliminaries

The following must be done 2 days at the very least prior to the release:

   1. Add the version(s) in the dirauth-conf git repository as the
      RecommendedVersion and RequiredVersion so they can be approved by the
      authorities and be in the consensus before the release.

   2. Send a pre-release announcement to `tor-project@lists.torproject.org` in
      order to inform every teams in Tor of the upcoming release. This is so
      we can avoid creating release surprises and sync with other teams.

   3. Ask the network-team to review the `changes/` files in all versions we
      are about to release. This step is encouraged but not mandatory.


## 2. Tarballs

To build the tarballs to release, we need to launch the CI release pipeline:

   https://gitlab.torproject.org/tpo/core/tor-ci-release

The `versions.yml` needs to be modified with the Tor versions you want to
release. Once done, git commit and push to trigger the release pipeline.

The first two stages (Preliminary and Patches) will be run automatically. The
Build stage needs to be triggered manually once all generated patches have
been merged upstream.

   1. Download the generated patches from the `Patches` stage.

   2. For the ChangeLog and ReleaseNotes, you need to write a blurb at the top
      explaining a bit the release.

   3. Review, modify if needed, and merged them upstream.

   4. Manually trigger the `maintained` job in the `Build` stage so the CI can
      build the tarballs without errors.

Once this is done, each selected developers need to build the tarballs in a
reproducible way using:

   https://gitlab.torproject.org/tpo/core/tor-ci-reproducible

Simply run the `./build.sh` which will commit interactively the signature for
you. You then only need to git push.

Once all signatures have been committed:

   1. Manually trigger the `signature` job in the `Post-process` stage of the
      CI release pipeline.

   2. If it passes, the tarball(s) and signature(s) will be available as
      artifacts and should be used for the release.

   3. Put them on `dist.torproject.org`:

      Upload the tarball and its sig to the dist website, i.e.
      `/srv/dist-master.torproject.org/htdocs/` on dist-master. Run
      "static-update-component dist.torproject.org" on dist-master.

      In the `project/web/tpo.git` repository, update `databags/versions.ini`
      to note the new version. Push these changes to `master`.

      (NOTE: Due to #17805, there can only be one stable version listed at once.
      Nonetheless, do not call your version "alpha" if it is stable, or people
      will get confused.)

      (NOTE: It will take a while for the website update scripts to update the
      website.)


## 3. Post Process

Once the tarballs have been uploaded and are ready to be announced, we need to
do the following:

   1. Merge upstream the artifacts from the `patches` job in the
      `Post-process` stage of the CI release pipeline.

   2. Write and post the release announcement for the `forum.torproject.net`
      in the `News -> Tor Release Announcement` category.

      Mention in which Tor Browser version (with dates) the release will be
      in. This usually only applies to the latest stable.

### New Stable

   1. Create the `maint-x.y.z` and `release-x.y.z` branches and update the
      `./scripts/git/git-list-tor-branches.sh` with the new version.


## Appendix: An alternative means to notify packagers

If for some reason you need to contact a bunch of packagers without
using the publicly archived tor-packagers list, you can try these
people:

       - {weasel,sysrqb,mikeperry} at torproject dot org
       - {blueness} at gentoo dot org
       - {paul} at invizbox dot io
       - {vincent} at invizbox dot com
       - {lfleischer} at archlinux dot org
       - {Nathan} at freitas dot net
       - {mike} at tig dot as
       - {tails-rm} at boum dot org
       - {simon} at sdeziel.info
       - {yuri} at freebsd.org
       - {mh+tor} at scrit.ch
       - {security} at brave.com
