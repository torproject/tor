import os

# We don't want to run metrics for unittests, automatically-generated C files,
# external libraries or git leftovers.
EXCLUDE_SOURCE_DIRS = {"src/test/", "src/trunnel/", "src/rust/",
                       "src/ext/", ".git/"}

def _norm(p):
    return os.path.normcase(os.path.normpath(p))

def get_tor_c_files(tor_topdir):
    """
    Return a list with the .c filenames we want to get metrics of.
    """
    files_list = []
    exclude_dirs = { _norm(os.path.join(tor_topdir, p)) for p in EXCLUDE_SOURCE_DIRS }


    for root, directories, filenames in os.walk(tor_topdir):
        # Remove all the directories that are excluded.
        directories[:] = [ d for d in directories
                           if _norm(os.path.join(root,d)) not in exclude_dirs ]
        directories.sort()
        filenames.sort()
        for filename in filenames:
            # We only care about .c files
            if not filename.endswith(".c"):
                continue

            full_path = os.path.join(root,filename)

            files_list.append(full_path)

    return files_list
