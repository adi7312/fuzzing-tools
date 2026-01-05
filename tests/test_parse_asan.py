import unittest

from analysis.parse.parse_asan import parse_asan


class TestParseAsan(unittest.TestCase):
    def test_parse_asan_basic_fields_and_frames(self):
        log = """
==123==ERROR: AddressSanitizer: heap-use-after-free on address 0x603000000010 at pc 0x000000401234 bp 0x7fffffffe000 sp 0x7fffffffdff8
READ of size 4 at 0x603000000010 thread T0
    #0 0x000000401234 in my_func /src/main.c:10:5
    #1 0x000000401235 in __internal /src/internal.c:20:1
freed by thread T0 here:
    #0 0x000000401999 in free /src/alloc.c:55:3
allocated by thread T0 here:
    #0 0x000000402000 in malloc /src/alloc.c:42:2
SUMMARY: AddressSanitizer: heap-use-after-free /src/main.c:10 in my_func
"""

        parsed = parse_asan(log)
        self.assertEqual(parsed["error_type"], "heap-use-after-free")
        self.assertEqual(parsed["address"], "0x603000000010")
        self.assertEqual(parsed["access"], {"type": "READ", "size": 4})

        self.assertGreaterEqual(len(parsed["source_frames"]), 1)
        self.assertEqual(parsed["source_frames"][0]["function"], "my_func")
        self.assertEqual(parsed["source_frames"][0]["file"], "/src/main.c")
        self.assertEqual(parsed["source_frames"][0]["line"], 10)

        self.assertEqual(len(parsed["freed_frames"]), 1)
        self.assertEqual(parsed["freed_frames"][0]["function"], "free")

        self.assertEqual(len(parsed["alloc_frames"]), 1)
        self.assertEqual(parsed["alloc_frames"][0]["function"], "malloc")

        self.assertEqual(parsed["summary"]["error_type"], "heap-use-after-free")
        self.assertEqual(parsed["summary"]["file"], "/src/main.c")
        self.assertEqual(parsed["summary"]["line"], 10)
