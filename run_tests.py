import os
import sys
import unittest

if os.path.exists(os.sep.join([os.getcwd(), 'pyspv'])):
    sys.path.insert(0, os.getcwd())

test_suite = unittest.TestLoader().discover('tests')
text_runner = unittest.TextTestRunner().run(test_suite)

