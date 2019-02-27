"""Some simple tests for practracker metrics"""

import unittest

import StringIO

import metrics

function_file = """static void
fun(directory_request_t *req, const char *resource)
{
  time_t if_modified_since = 0;
  uint8_t or_diff_from[DIGEST256_LEN];
}

static void
fun(directory_request_t *req,
      const char *resource)
{
  time_t if_modified_since = 0;
  uint8_t or_diff_from[DIGEST256_LEN];
}

MOCK_IMPL(void,
fun,(
       uint8_t dir_purpose,
       uint8_t router_purpose,
       const char *resource,
       int pds_flags,
       download_want_authority_t want_authority))
{
  const routerstatus_t *rs = NULL;
  const or_options_t *options = get_options();
}
"""

class TestFunctionLength(unittest.TestCase):
    def test_function_length(self):
        funcs = StringIO.StringIO(function_file)
        # All functions should have length 2
        for name, lines in metrics.function_lines(funcs):
            self.assertEqual(name, "fun")

        funcs.seek(0)

        for name, lines in metrics.function_lines(funcs):
            self.assertEqual(lines, 2)

if __name__ == '__main__':
    unittest.main()
