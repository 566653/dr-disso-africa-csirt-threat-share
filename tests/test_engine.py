import unittest,sys,pathlib
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from engine import assess,run
class TestEngine(unittest.TestCase):
 def test_high(self):self.assertEqual(assess([{"event":"unexpected access"}])[0]["severity"],"high")
 def test_critical(self):self.assertEqual(assess([{"event":"ransomware detected"}])[0]["severity"],"critical")
 def test_clean(self):self.assertEqual(assess([{"event":"normal"}])[0]["severity"],"info")
 def test_bad_input(self):
  with self.assertRaises(ValueError):assess({"event":"wrong"})
 def test_sample(self):self.assertEqual(run(pathlib.Path(__file__).resolve().parents[1]/"examples"/"events.json")["count"],3)
