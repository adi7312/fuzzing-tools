import unittest


class TestUtilitiesUtils(unittest.TestCase):
    def test_parse_duration_hours(self):
        from utilities.utils import parse_duration

        self.assertEqual(parse_duration("1h"), 3600)
        self.assertEqual(parse_duration("12h"), 12 * 3600)

    def test_parse_duration_days_minutes(self):
        from utilities.utils import parse_duration

        self.assertEqual(parse_duration("1d"), 86400)
        self.assertEqual(parse_duration("30m"), 1800)

    def test_parse_duration_invalid_unit(self):
        from utilities.utils import parse_duration

        with self.assertRaises(ValueError):
            parse_duration("10s")

    def test_format_fuzzer_name_mapping_and_fallback(self):
        from utilities.utils import format_fuzzer_name

        self.assertEqual(format_fuzzer_name("/tmp/aflpp_out"), "AFL++")
        self.assertEqual(format_fuzzer_name("/tmp/hfuzz"), "Honggfuzz")
        # fallback: title case, underscores -> spaces, strips _out
        self.assertEqual(format_fuzzer_name("/tmp/my_fuzzer_out"), "My Fuzzer")
