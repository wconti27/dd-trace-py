from ddtrace.internal import core
from .product_code import TestGenerator

_test_generator = TestGenerator()
core.on('span.create', _test_generator._run_test)