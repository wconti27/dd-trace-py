from ddtrace import tracer
from ddtrace.internal.utils import get_argument_value
from ddtrace.internal.wrapping import unwrap
from ddtrace.internal.wrapping import wrap


def _wrapped_evaluate_internal(func, args, kwargs):
    # def _evaluate_internal(self, key: str, context: Union[Context, dict], default: Any, event_factory):
    span = tracer.current_root_span()
    if not span:
        return func(*args, **kwargs)

    evaluation_detail = func(*args, **kwargs)
    try:
        key = get_argument_value(args, kwargs, 1, "key")
        tag_prefix = "features.{}".format(key)
        span.set_tag("{}.variation_index".format(tag_prefix), evaluation_detail.variation_index)
        span.set_tag("{}.value".format(tag_prefix), evaluation_detail.value)
        span.set_tag("{}.reason.kind".format(tag_prefix), evaluation_detail.reason.kind)
    finally:
        return evaluation_detail


def patch():
    import ldclient

    if getattr(ldclient, "_datadog_patch", False):
        return
    setattr(ldclient, "_datadog_patch", True)

    wrap(ldclient.LDClient._evaluate_internal, _wrapped_evaluate_internal)


def unpatch():
    import ldclient

    if not getattr(ldclient, "_datadog_patch", False):
        return
    setattr(ldclient, "_datadog_patch", False)

    unwrap(ldclient.LDClient._evaluate_internal, _wrapped_evaluate_internal)
