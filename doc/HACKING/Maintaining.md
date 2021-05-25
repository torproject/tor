# Maintaining Tor

This document details the duties and processes on maintaining the Tor code
base.

The first section describes who is the current Tor maintainer and what are the
responsibilities. Tor has one main single maintainer but does have many
committers and subsystem maintainers.

The second third section describes how the **alpha and main** branches are
maintained and by whom.

Finally, the last section describes how the **stable** branches are maintained
and by whom.

This document does not cover how Tor is released, please see
[ReleasingTor.md](ReleasingTor.md) for that information.

## Tor Maintainer

The current maintainer is Nick Mathewson <nickm@torproject.org>.

The maintainer takes final decisions in terms of engineering, architecture and
protocol design. Releasing Tor falls under their responsibility.

## Alpha and Master Branches

The Tor repository always has at all times a **main** branch which contains
the upstream ongoing development.

It may also contain a branch for a released feature freezed version which is
called the **alpha** branch. The git tag and version number is always
postfixed with `-alpha[-dev]`. For example: `tor-0.3.5.0-alpha-dev` or
`tor-0.3.5.3-alpha`.

Tor is separated into subsystems and some of those are maintained by other
developers than the main maintainer. Those people have commit access to the
code base but only commit (in most cases) into the subsystem they maintain.

Upstream merges are restricted to the alpha and main branches. Subsystem
maintainers should never push a patch into a stable branch which is the
responsibility of the [stable branch maintainer](#stable-branches).

### Who

In alphabetical order, the following people have upstream commit access and
maintain the following subsystems:

- David Goulet <dgoulet@torproject.org>
  * Onion Service (including Shared Random).  
    ***keywords:*** *[tor-hs]*
  * Channels, Circuitmux, Connection, Scheduler.  
    ***keywords:*** *[tor-chan, tor-cmux, tor-sched, tor-conn]*
  * Cell Logic (Handling/Parsing).  
    ***keywords:*** *[tor-cell]*
  * Threading backend.
    ***keywords:*** *[tor-thread]*  

- George Kadianakis <asn@torproject.org>
  * Onion Service (including Shared Random).  
    ***keywords:*** *[tor-hs]*
  * Guard.  
    ***keywords:*** *[tor-guard]*
  * Pluggable Transport (excluding Bridge networking).  
    ***keywords:*** *[tor-pt]*

### Tasks

These are the tasks of a subsystem maintainer:

1. Regularly go over `merge_ready` tickets relevant to the related subsystem
   and for the current alpha or development (main branch) Milestone.

2. A subsystem maintainer is expected to contribute to any design changes
   (including proposals) or large patch set about the subsystem.

3. Leave their ego at the door. Mistakes will be made but they have to be
   taking care of seriously. Learn and move on quickly.

### Merging Policy

These are few important items to follow when merging code upstream:

1. To merge code upstream, the patch must have passed our CI (currently
   github.com/torproject), have a corresponding ticket and reviewed by
   **at least** one person that is not the original coder.

   Example A: If Alice writes a patch then Bob, a Tor network team member,
   reviews it and flags it `merge_ready`. Then, the maintainer is required
   to look at the patch and makes a decision.

   Example B: If the maintainer writes a patch then Bob, a Tor network
   team member, reviews it and flags it `merge_ready`, then the maintainer
   can merge the code upstream.

2. Maintainer makes sure the commit message should describe what was fixed
   and, if it applies, how was it fixed. It should also always refer to
   the ticket number.

3. Trivial patches such as comment change, documentation, syntax issues or
   typos can be merged without a ticket or reviewers.

4. Tor uses the "merge forward" method, that is, if a patch applies to the
   alpha branch, it has to be merged there first and then merged forward
   into main.

5. Maintainer should always consult with the network team about any doubts,
   mis-understandings or unknowns of a patch. Final word will always go to the
   main Tor maintainer.

## Stable Branches

(Currently being drafted and reviewed by the network team.)
