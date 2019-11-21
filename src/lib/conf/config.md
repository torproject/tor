
@page configuration Configuration options and persistent state

@tableofcontents

## Introduction

Tor uses a shared, table-driven mechanism to handle its
configuration (torrc) files and its state files.  Each module can
declare a set of named fields for these files, and get notified
whenever the configuration changes, or when the state is about to be
flushed to disk.

## Declaring options

Most modules will only need to use the macros in confdecl.h to
declare a configuration or state structure.

You'll write something like this:

    // my_module_config.inc
    BEGIN_CONF_STRUCT(module_options_t)
    CONF_VAR(FieldOne, INT, 0, "7")
    CONF_VAR(FieldTwo, STRING, 0, NULL)
    END_CONF_STRUCT(module_options_t)

The above example will result in a structure called module_config_t
with two fields: one an integer called FieldOne and one a string
called FieldTwo.  The integer gets a default value of 7; the
string's default value is NULL.

After making a definition file like that, you include it twice: once
in a header, after saying \#define CONF_CONTEXT STRUCT, and once in
a C file, after saying \#define CONF_CONTEXT TABLE.  The first time
defines a module_options_t structure, and the second time defines a
table that tells the configuration manager how to use it.

Using the table, you declare a `const` config_format_t, which
associates the fields with a set of functions for validating and
normalizing them, a list of abbreviations and deprecations, and
other features.

See confdecl.h and conftypes.h for more information. For example
usage, see crypto_options.inc or mainloop_state.inc.

## Getting notifications

After using those macros, you must tell the subsystem management
code about your module's configuration/state.

If you're writing configuration code, you'll need a function that receives
the configuration object, and acts upon it.  This function needs to be safe
to call multiple times, since Tor will reconfigure its subsystems whenever it
re-reads the torrc, gets a configuration change from a controller, or
restarts in process.  This function goes in your subsystem's
subsys_fns_t.set_options field.

If you're writing state code, you'll need a function that receives
state (subsys_fns_t.set_state), and a function that flushes the
application state into a state object (subsys_fns_t.flush_state).
The `set_state` function will be called once (@ref config_once_per
"1") when Tor is starting, whereas the `flush_state` function will
be called whenever Tor is about to save the state to disk.

See subsys_fns_t for more information here, and \ref initialization
for more information about initialization and subsystems in general.

> @anchor config_once_per 1. Technically, state is set once _per startup_.
> Remember that Tor can be stopped and started multiple times in
> the same process.  If this happens, then your set_state() function
> is called once every time Tor starts.

## How it works

The common logic used to handle configuration and state files lives
in @refdir{lib/confmgt}.  At the highest level, a configuration
manager object (config_mgr_t) maintains a list of each module's
configuration objects, and a list of all their fields.  When the
user specifies a configuration value, the manager finds out how to
parse it, where to store it, and which configuration object is
affected.

The top-level configuration module (config.c) and state module
(statefile.c) use config_mgr_t to create, initialize, set, compare,
and free a "top level configuration object".  This object contains a
list of sub-objects: one for each module that participates in the
configuration/state system.  This top-level code then invokes the
subsystem manager code (subsysmgr.c) to pass the corresponding
configuration or state objects to each module that has one.

Note that the top level code does not have easy access to the
configuration objects used by the sub-modules.  This is by design.  A
module _may_ expose some or all of its configuration or state object via
accessor functions, if it likes, but if it does not, that object should
be considered module-local.

## Adding new types

Configuration and state fields each have a "type".  These types
specify how the fields' values are represented in C; how they are
stored in files; and how they are encoded back and forth.

There is a set of built-in types listed in conftypes.h, but
higher-level code can define its own types.  To do so, you make an
instance of var_type_fns_t that describes how to manage your type,
and an instance of var_type_def_t that wraps your var_type_fns_t
with a name and optional parameters and flags.

For an example of how a higher-level type is defined, see
ROUTERSET_type_defn in routerset.c.  Also see the typedef
`config_decl_ROUTERSET`.  Together, these let the routerset type be
used with the macros in confdecl.h.

## Legacy configuration and state

As of this writing (November 2019), most of the configuration and state is
still handled directly in config.c and statefile.c, and stored in the
monolithic structures or_options_t and or_state_t respectively.

These top-level structures are accessed with get_options() and
get_state(), and used throughout much of the code, at the level of
@refdir{core} and higher.

With time we hope to refactor this configuration into more
reasonable pieces, so that they are no longer (effectively) global
variables used throughout the code.
