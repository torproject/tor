import os

# We don't want to run metrics for unittests, automatically-generated C files,
# external libraries or git leftovers.
EXCLUDE_SOURCE_DIRS = {"/src/test/", "/src/trunnel/", "/src/ext/", "/.git/"}

def get_tor_c_files(tor_topdir):
    """
    Return a list with the .c filenames we want to get metrics of.
    """
    files_list = []

    for root, directories, filenames in os.walk(tor_topdir):
        directories.sort()
        filenames.sort()
        for filename in filenames:
            # We only care about .c files
            if not filename.endswith(".c"):
                continue

            # Exclude the excluded paths
            full_path = os.path.join(root,filename)
            if any(os.path.normcase(exclude_dir) in full_path for exclude_dir in EXCLUDE_SOURCE_DIRS):
                continue

            files_list.append(full_path)

    return files_list
