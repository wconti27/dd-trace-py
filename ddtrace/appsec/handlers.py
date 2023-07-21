import json

from six import BytesIO
import xmltodict

from ddtrace import config
from ddtrace.appsec._constants import WAF_CONTEXT_NAMES
from ddtrace.appsec.iast._patch import if_iast_taint_returned_object_for
from ddtrace.appsec.iast._patch import if_iast_taint_yield_tuple_for
from ddtrace.appsec.iast._util import _is_iast_enabled
from ddtrace.internal import core
from ddtrace.internal.constants import REQUEST_PATH_PARAMS
from ddtrace.internal.logger import get_logger


try:
    from json import JSONDecodeError
except ImportError:
    # handling python 2.X import error
    JSONDecodeError = ValueError  # type: ignore

log = get_logger(__name__)
_BODY_METHODS = {"POST", "PUT", "DELETE", "PATCH"}


def _on_set_request_tags(request, span, flask_config):
    if _is_iast_enabled():
        from ddtrace.appsec.iast._taint_tracking import OriginType
        from ddtrace.appsec.iast._taint_utils import LazyTaintDict

        request.cookies = LazyTaintDict(
            request.cookies,
            origins=(OriginType.COOKIE_NAME, OriginType.COOKIE),
            override_pyobject_tainted=True,
        )


def _on_request_span_modifier(request, environ, _HAS_JSON_MIXIN, exception_type):
    req_body = None
    if config._appsec_enabled and request.method in _BODY_METHODS:
        content_type = request.content_type
        wsgi_input = environ.get("wsgi.input", "")

        # Copy wsgi input if not seekable
        if wsgi_input:
            try:
                seekable = wsgi_input.seekable()
            except AttributeError:
                seekable = False
            if not seekable:
                content_length = int(environ.get("CONTENT_LENGTH", 0))
                body = wsgi_input.read(content_length) if content_length else wsgi_input.read()
                environ["wsgi.input"] = BytesIO(body)

        try:
            if content_type == "application/json" or content_type == "text/json":
                if _HAS_JSON_MIXIN and hasattr(request, "json") and request.json:
                    req_body = request.json
                else:
                    req_body = json.loads(request.data.decode("UTF-8"))
            elif content_type in ("application/xml", "text/xml"):
                req_body = xmltodict.parse(request.get_data())
            elif hasattr(request, "form"):
                req_body = request.form.to_dict()
            else:
                # no raw body
                req_body = None
        except (
            exception_type,
            AttributeError,
            RuntimeError,
            TypeError,
            ValueError,
            JSONDecodeError,
            xmltodict.expat.ExpatError,
            xmltodict.ParsingInterrupted,
        ):
            log.warning("Failed to parse request body", exc_info=True)
        finally:
            # Reset wsgi input to the beginning
            if wsgi_input:
                if seekable:
                    wsgi_input.seek(0)
                else:
                    environ["wsgi.input"] = BytesIO(body)
    return req_body


def _on_start_response():
    from ddtrace.appsec import _asm_request_context

    log.debug("Flask WAF call for Suspicious Request Blocking on response")
    _asm_request_context.call_waf_callback()
    return _asm_request_context.get_headers().get("Accept", "").lower()


def _on_block_decided(callback):
    from ddtrace.appsec import _asm_request_context

    _asm_request_context.set_value(_asm_request_context._CALLBACKS, "flask_block", callback)


def _on_request_init(instance):
    if _is_iast_enabled():
        try:
            from ddtrace.appsec.iast._taint_tracking import OriginType
            from ddtrace.appsec.iast._taint_tracking import taint_pyobject

            # TODO: instance.query_string = ??
            instance.query_string = taint_pyobject(
                pyobject=instance.query_string,
                source_name=OriginType.QUERY,
                source_value=instance.query_string,
                source_origin=OriginType.QUERY,
            )
            instance.path = taint_pyobject(
                pyobject=instance.path,
                source_name=OriginType.PATH,
                source_value=instance.path,
                source_origin=OriginType.PATH,
            )
        except Exception:
            log.debug("Unexpected exception while tainting pyobject", exc_info=True)


def _on_werkzeug(*args):
    if isinstance(args[0], tuple):
        return if_iast_taint_yield_tuple_for(*args)
    return if_iast_taint_returned_object_for(*args)


def listen():
    core.on("flask.set_request_tags", _on_set_request_tags)
    core.on("flask.request_span_modifier", _on_request_span_modifier)


core.on("flask.werkzeug.datastructures.Headers.items", _on_werkzeug)
core.on("flask.werkzeug.datastructures.EnvironHeaders.__getitem__", _on_werkzeug)
core.on("flask.werkzeug.datastructures.ImmutableMultiDict.__getitem__", _on_werkzeug)
core.on("flask.werkzeug.wrappers.request.Request.get_data", _on_werkzeug)
core.on("flask.werkzeug._internal._DictAccessorProperty.__get__", _on_werkzeug)
