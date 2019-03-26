"""
In this file we define a ProblemVault class where we store all the
exceptions and all the problems we find with the code.

The ProblemVault is capable of registering problems and also figuring out if a
problem is worse than a registered exception so that it only warns when things
get worse.
"""

from __future__ import print_function

import os.path
import re
import sys

class ProblemVault(object):
    """
    Singleton where we store the various new problems we
    found in the code, and also the old problems we read from the exception
    file.
    """
    def __init__(self, exception_fname=None):
        # Exception dictionary: { problem.key() : Problem object }
        self.exceptions = {}

        if exception_fname == None:
            return

        try:
            with open(exception_fname, 'r') as exception_f:
                self.register_exceptions(exception_f)
        except IOError:
            print("No exception file provided", file=sys.stderr)

    def register_exceptions(self, exception_file):
        # Register exceptions
        for lineno, line in enumerate(exception_file, 1):
            try:
                problem = get_old_problem_from_exception_str(line)
            except ValueError as v:
                print("Exception file line {} not recognized: {}"
                      .format(lineno,v),
                      file=sys.stderr)
                continue

            if problem is None:
                continue

            # Fail if we see dup exceptions. There is really no reason to have dup exceptions.
            if problem.key() in self.exceptions:
                print("Duplicate exceptions lines found in exception file:\n\t{}\n\t{}\nAborting...".format(problem, self.exceptions[problem.key()]),
                      file=sys.stderr)
                sys.exit(1)

            self.exceptions[problem.key()] = problem
            #print "Registering exception: %s" % problem

    def register_problem(self, problem):
        """
        Register this problem to the problem value. Return True if it was a new
        problem or it worsens an already existing problem.
        """
        # This is a new problem, print it
        if problem.key() not in self.exceptions:
            print(problem)
            return True

        # If it's an old problem, we don't warn if the situation got better
        # (e.g. we went from 4k LoC to 3k LoC), but we do warn if the
        # situation worsened (e.g. we went from 60 includes to 80).
        if problem.is_worse_than(self.exceptions[problem.key()]):
            print(problem)
            return True

        return False

class Problem(object):
    """
    A generic problem in our source code. See the subclasses below for the
    specific problems we are trying to tackle.
    """
    def __init__(self, problem_type, problem_location, metric_value):
        self.problem_location = problem_location
        self.metric_value = int(metric_value)
        self.problem_type = problem_type

    def is_worse_than(self, other_problem):
        """Return True if this is a worse problem than other_problem"""
        if self.metric_value > other_problem.metric_value:
            return True
        return False

    def key(self):
        """Generate a unique key that describes this problem that can be used as a dictionary key"""
        # Problem location is a filesystem path, so we need to normalize this
        # across platforms otherwise same paths are not gonna match.
        canonical_location = os.path.normcase(self.problem_location)
        return "%s:%s" % (canonical_location, self.problem_type)

    def __str__(self):
        return "problem %s %s %s" % (self.problem_type, self.problem_location, self.metric_value)

class FileSizeProblem(Problem):
    """
    Denotes a problem with the size of a .c file.

    The 'problem_location' is the filesystem path of the .c file, and the
    'metric_value' is the number of lines in the .c file.
    """
    def __init__(self, problem_location, metric_value):
        super(FileSizeProblem, self).__init__("file-size", problem_location, metric_value)

class IncludeCountProblem(Problem):
    """
    Denotes a problem with the number of #includes in a .c file.

    The 'problem_location' is the filesystem path of the .c file, and the
    'metric_value' is the number of #includes in the .c file.
    """
    def __init__(self, problem_location, metric_value):
        super(IncludeCountProblem, self).__init__("include-count", problem_location, metric_value)

class FunctionSizeProblem(Problem):
    """
    Denotes a problem with a size of a function in a .c file.

    The 'problem_location' is "<path>:<function>()" where <path> is the
    filesystem path of the .c file and <function> is the name of the offending
    function.

    The 'metric_value' is the size of the offending function in lines.
    """
    def __init__(self, problem_location, metric_value):
        super(FunctionSizeProblem, self).__init__("function-size", problem_location, metric_value)

comment_re = re.compile(r'#.*$')

def get_old_problem_from_exception_str(exception_str):
    orig_str = exception_str
    exception_str = comment_re.sub("", exception_str)
    fields = exception_str.split()
    if len(fields) == 0:
        # empty line or comment
        return None
    elif len(fields) == 4:
        # valid line
        _, problem_type, problem_location, metric_value = fields
    else:
        raise ValueError("Misformatted line {!r}".format(orig_str))

    if problem_type == "file-size":
        return FileSizeProblem(problem_location, metric_value)
    elif problem_type == "include-count":
        return IncludeCountProblem(problem_location, metric_value)
    elif problem_type == "function-size":
        return FunctionSizeProblem(problem_location, metric_value)
    else:
        raise ValueError("Unknown exception type {!r}".format(orig_str))
