@dir /feature/hibernate
@brief feature/hibernate: Bandwidth accounting and hibernation (!)

This module implements two features that are only somewhat related, and
should probably be separated in the future.  One feature is bandwidth
accounting (making sure we use no more than so many gigabytes in a day) and
hibernation (avoiding network activity while we have used up all/most of our
configured gigabytes).  The other feature is clean shutdown, where we stop
accepting new connections for a while and give the old ones time to close.

The two features are related only in the sense that "soft hibernation" (being
almost out of ) is very close to the "shutting down" state.  But it would be
better in the long run to make the two completely separate.

