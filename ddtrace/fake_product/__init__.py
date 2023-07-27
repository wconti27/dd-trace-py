from ddtrace.internal import core
from . import TestGenerator()

_span_generator = TestGenerator()
core.on('span.create', _span_generator._run_test)