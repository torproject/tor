
## Overview ##


### The rest of this document. ###

> **Note**: This section describes the eventual organization of this
> document, which is not yet complete.

We'll begin with an overview of the facilities provided by the modules
in src/lib.  Knowing about these is key to writing portable, simple code
in Tor.

Then we'll move on to a discussion of how parts of the Tor codebase are
initialized, finalized, configured, and managed.

Then we'll go on and talk about the main data-flow of the Tor network:
how Tor generates and responds to network traffic.  This will occupy a
chapter for the main overview, with other chapters for special topics.

After that, we'll mention the main modules in src/features and describe the
functions of each.

We'll close with a meandering overview of important pending issues in
the Tor codebase, and how they affect the future of the Tor software.
