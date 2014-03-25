import os
import sys
import unittest

if os.path.exists(os.sep.join([os.getcwd(), 'pyspv'])):
    sys.path.insert(0, os.getcwd())

unittest.TextTestRunner().run(unittest.TestLoader().discover('tests'))
