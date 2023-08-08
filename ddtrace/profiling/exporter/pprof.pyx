import collections
import itertools
import operator
import platform
import sysconfig
import typing

import attr
import six

from ddtrace import ext
from ddtrace.internal import packages
from ddtrace.internal._encoding import ListStringTable as _StringTable
from ddtrace.internal.compat import ensure_str
from ddtrace.internal.utils import config
from ddtrace.profiling import _threading
from ddtrace.profiling import event
from ddtrace.profiling import exporter
from ddtrace.profiling import recorder
from ddtrace.profiling.collector import _lock
from ddtrace.profiling.collector import memalloc
from ddtrace.profiling.collector import stack_event


if hasattr(typing, "TypedDict"):
    Package = typing.TypedDict(
        "Package",
        {
            "name": str,
            "version": str,
            "kind": typing.Literal["standard library", "library"],
            "paths": typing.List[str],
        },
    )
else:
    Package = dict  # type: ignore


stdlib_path = sysconfig.get_path("stdlib")
platstdlib_path = sysconfig.get_path("platstdlib")
purelib_path = sysconfig.get_path("purelib")
platlib_path = sysconfig.get_path("platlib")


STDLIB = []  # type: typing.List[Package]


if stdlib_path is not None:
    STDLIB.append(
        Package(
            {
                "name": "stdlib",
                "kind": "standard library",
                "version": platform.python_version(),
                "paths": [stdlib_path],
            }
        )
    )

if purelib_path is not None:
    # No library should end up here, include it just in case
    STDLIB.append(
        Package(
            {
                "name": "<unknown>",
                "kind": "library",
                "version": "<unknown>",
                "paths": [purelib_path]
                + ([] if platlib_path is None or purelib_path == platlib_path else [platlib_path]),
            }
        )
    )


if platstdlib_path is not None and platstdlib_path != stdlib_path:
    STDLIB.append(
        Package(
            {
                "name": "platstdlib",
                "kind": "standard library",
                "version": platform.python_version(),
                "paths": [platstdlib_path],
            }
        )
    )


def _protobuf_version():
    # type: (...) -> typing.Tuple[int, int, int]
    """Check if protobuf version is post 3.12"""
    import google.protobuf

    from ddtrace.internal.utils.version import parse_version

    return parse_version(google.protobuf.__version__)


# Load the appropriate pprof_pb2 module
_pb_version = _protobuf_version()
for v in [(4, 21), (3, 19), (3, 12)]:
    if _pb_version >= v:
        import sys
        
        pprof_module = "ddtrace.profiling.exporter.pprof_%s%s_pb2" % v
        __import__(pprof_module)
        pprof_pb2 = sys.modules[pprof_module]
        break
else:
    from ddtrace.profiling.exporter import pprof_3_pb2 as pprof_pb2  # type: ignore[no-redef]


_ITEMGETTER_ZERO = operator.itemgetter(0)
_ITEMGETTER_ONE = operator.itemgetter(1)
_ATTRGETTER_ID = operator.attrgetter("id")


cdef str _none_to_str(object value):
    return "" if value is None else str(value)


def _get_thread_name(thread_id: typing.Optional[int], thread_name: typing.Optional[str]) -> str:
    if thread_name is None:
        return "Anonymous Thread %s" % ("?" if thread_id is None else str(thread_id))
    return thread_name


cdef groupby(object collection, object key):
    cdef dict groups = {}

    for item in collection:
        groups.setdefault(key(item), []).append(item)

    return groups.items()


class pprof_LocationType(object):
    # pprof_pb2.Location
    id: int


class pprof_Mapping(object):
    filename: int


class pprof_ProfileType(object):
    # Emulate pprof_pb2.Profile for typing
    id: int
    string_table: typing.Dict[int, str]
    mapping: typing.List[pprof_Mapping]

    def SerializeToString(self) -> bytes:  # type: ignore[empty-body]
        ...


class pprof_FunctionType(object):
    # pprof_pb2.Function
    id: int


_Label_T = typing.Tuple[str, str]
_Label_List_T = typing.Tuple[_Label_T, ...]
_Location_Key_T = typing.Tuple[typing.Tuple[int, ...], _Label_List_T]


HashableStackTraceType = typing.Tuple[event.FrameType, ...]


@attr.s
class _PprofConverter(object):
    """Convert stacks generated by a Profiler to pprof format."""

    # Those attributes will be serialize in a `pprof_pb2.Profile`
    _functions = attr.ib(
        init=False, factory=dict, type=typing.Dict[typing.Tuple[str, typing.Optional[str]], pprof_FunctionType]
    )
    _locations = attr.ib(init=False, factory=dict, type=typing.Dict[typing.Tuple[str, int, str], pprof_LocationType])
    _string_table = attr.ib(init=False, factory=_StringTable)

    _last_location_id = attr.ib(init=False, factory=lambda: itertools.count(1))
    _last_func_id = attr.ib(init=False, factory=lambda: itertools.count(1))

    # A dict where key is a (Location, [Labels]) and value is a a dict.
    # This dict has sample-type (e.g. "cpu-time") as key and the numeric value.
    _location_values = attr.ib(
        factory=lambda: collections.defaultdict(lambda: collections.defaultdict(lambda: 0)),
        init=False,
        repr=False,
        type=typing.DefaultDict[_Location_Key_T, typing.DefaultDict[str, int]],
    )

    def _to_Function(
        self,
        filename: str,
        funcname: str,
    ) -> pprof_FunctionType:
        try:
            return self._functions[(filename, funcname)]
        except KeyError:
            func = pprof_pb2.Function(
                id=next(self._last_func_id),
                name=self._str(funcname),
                filename=self._str(filename),
            )
            self._functions[(filename, funcname)] = func
            return func

    def _to_Location(
        self,
        filename: str,
        lineno: int,
        funcname: str,
    ) -> pprof_LocationType:
        try:
            return self._locations[(filename, lineno, funcname)]
        except KeyError:
            location = pprof_pb2.Location(
                id=next(self._last_location_id),
                line=[
                    pprof_pb2.Line(
                        function_id=self._to_Function(filename, funcname).id,
                        line=lineno,
                    ),
                ],
            )
            self._locations[(filename, lineno, funcname)] = location
            return location

    def _str(self, string: str) -> int:
        """Convert a string to an id from the string table."""
        return self._string_table.index(str(string))

    def _to_locations(
        self,
        frames,  # type: typing.Sequence[event.FrameType]
        nframes,  # type: int
    ):
        # type: (...) -> typing.Tuple[int, ...]
        locations = [
            self._to_Location(filename, lineno, funcname).id for filename, lineno, funcname, class_name in frames
        ]

        omitted = nframes - len(frames)
        if omitted:
            locations.append(
                self._to_Location("", 0, "<%d frame%s omitted>" % (omitted, ("s" if omitted > 1 else ""))).id
            )

        return tuple(locations)

    def convert_stack_event(
        self,
        thread_id,  # type: str
        thread_native_id,  # type: str
        thread_name,  # type: str
        task_id,  # type: str
        task_name,  # type: str
        local_root_span_id,  # type: str
        span_id,  # type: str
        trace_resource,  # type: str
        trace_type,  # type: str
        frames,  # type: HashableStackTraceType
        nframes,  # type: int
        samples,  # type: typing.List[stack_event.StackSampleEvent]
    ):
        # type: (...) -> None
        location_key = (
            self._to_locations(frames, nframes),
            (
                ("thread id", thread_id),
                ("thread native id", thread_native_id),
                ("thread name", thread_name),
                ("task id", task_id),
                ("task name", task_name),
                ("local root span id", local_root_span_id),
                ("span id", span_id),
                ("trace endpoint", trace_resource),
                ("trace type", trace_type),
                ("class name", frames[0][3]),
            ),
        )

        self._location_values[location_key]["cpu-samples"] = len(samples)
        self._location_values[location_key]["cpu-time"] = sum(s.cpu_time_ns for s in samples)
        self._location_values[location_key]["wall-time"] = sum(s.wall_time_ns for s in samples)

    def convert_memalloc_event(
        self,
        thread_id,  # type: str
        thread_native_id,  # type: str
        thread_name,  # type: str
        frames,  # type: HashableStackTraceType
        nframes,  # type: int
        events,  # type: typing.List[memalloc.MemoryAllocSampleEvent]
    ):
        # type: (...) -> None
        location_key = (
            self._to_locations(frames, nframes),
            (
                ("thread id", thread_id),
                ("thread native id", thread_native_id),
                ("thread name", thread_name),
            ),
        )

        self._location_values[location_key]["alloc-samples"] = round(
            sum(event.nevents * (event.capture_pct / 100.0) for event in events)
        )
        self._location_values[location_key]["alloc-space"] = round(
            sum(event.size / event.capture_pct * 100.0 for event in events)
        )

    def convert_memalloc_heap_event(self, event: memalloc.MemoryHeapSampleEvent) -> None:
        location_key = (
            self._to_locations(tuple(event.frames), event.nframes),
            (
                ("thread id", _none_to_str(event.thread_id)),
                ("thread native id", _none_to_str(event.thread_native_id)),
                ("thread name", _get_thread_name(event.thread_id, event.thread_name)),
            ),
        )

        self._location_values[location_key]["heap-space"] += event.size

    def convert_lock_acquire_event(
        self,
        lock_name,  # type: str
        thread_id,  # type: str
        thread_name,  # type: str
        task_id,  # type: str
        task_name,  # type: str
        local_root_span_id,  # type: str
        span_id,  # type: str
        trace_resource,  # type: str
        trace_type,  # type: str
        frames,  # type: HashableStackTraceType
        nframes,  # type: int
        events,  # type: typing.List[_lock.LockAcquireEvent]
        sampling_ratio,  # type: float
    ):
        # type: (...) -> None
        location_key = (
            self._to_locations(frames, nframes),
            (
                ("thread id", thread_id),
                ("thread name", thread_name),
                ("task id", task_id),
                ("task name", task_name),
                ("local root span id", local_root_span_id),
                ("span id", span_id),
                ("trace endpoint", trace_resource),
                ("trace type", trace_type),
                ("lock name", lock_name),
                ("class name", frames[0][3]),
            ),
        )

        self._location_values[location_key]["lock-acquire"] = len(events)
        self._location_values[location_key]["lock-acquire-wait"] = int(
            sum(e.wait_time_ns for e in events) / sampling_ratio
        )

    def convert_lock_release_event(
        self,
        lock_name,  # type: str
        thread_id,  # type: str
        thread_name,  # type: str
        task_id,  # type: str
        task_name,  # type: str
        local_root_span_id,  # type: str
        span_id,  # type: str
        trace_resource,  # type: str
        trace_type,  # type: str
        frames,  # type: HashableStackTraceType
        nframes,  # type: int
        events,  # type: typing.List[_lock.LockReleaseEvent]
        sampling_ratio,  # type: float
    ):
        # type: (...) -> None
        location_key = (
            self._to_locations(frames, nframes),
            (
                ("thread id", thread_id),
                ("thread name", thread_name),
                ("task id", task_id),
                ("task name", task_name),
                ("local root span id", local_root_span_id),
                ("span id", span_id),
                ("trace endpoint", trace_resource),
                ("trace type", trace_type),
                ("lock name", lock_name),
                ("class name", frames[0][3]),
            ),
        )

        self._location_values[location_key]["lock-release"] = len(events)
        self._location_values[location_key]["lock-release-hold"] = int(
            sum(e.locked_for_ns for e in events) / sampling_ratio
        )

    def convert_stack_exception_event(
        self,
        thread_id: str,
        thread_native_id: str,
        thread_name: str,
        local_root_span_id: str,
        span_id: str,
        trace_resource: str,
        trace_type: str,
        frames: HashableStackTraceType,
        nframes: int,
        exc_type_name: str,
        events: typing.List[stack_event.StackExceptionSampleEvent],
    ) -> None:
        location_key = (
            self._to_locations(frames, nframes),
            (
                ("thread id", thread_id),
                ("thread native id", thread_native_id),
                ("thread name", thread_name),
                ("local root span id", local_root_span_id),
                ("span id", span_id),
                ("trace endpoint", trace_resource),
                ("trace type", trace_type),
                ("exception type", exc_type_name),
                ("class name", frames[0][3]),
            ),
        )

        self._location_values[location_key]["exception-samples"] = len(events)

    def _build_libraries(self) -> typing.List[Package]:
        return [
            Package(
                {
                    "name": lib.name,
                    "kind": "library",
                    "version": lib.version,
                    "paths": [lib_and_filename[1] for lib_and_filename in libs_and_filenames],
                }
            )
            for lib, libs_and_filenames in groupby(
                {
                    _
                    for _ in (
                        (packages.filename_to_package(filename), filename)
                        for filename, lineno, funcname in self._locations
                    )
                    if _[0] is not None
                }, _ITEMGETTER_ZERO
            )
        ] + STDLIB

    def _build_profile(
        self,
        start_time_ns: int,
        duration_ns: int,
        period: typing.Optional[int],
        sample_types: typing.Tuple[typing.Tuple[str, str], ...],
        program_name: str,
    ) -> pprof_ProfileType:
        pprof_sample_type = [
            pprof_pb2.ValueType(type=self._str(type_), unit=self._str(unit)) for type_, unit in sample_types
        ]

        sample = [
            pprof_pb2.Sample(
                location_id=locations,
                value=[values.get(sample_type_name, 0) for sample_type_name, unit in sample_types],
                label=[pprof_pb2.Label(key=self._str(key), str=self._str(s)) for key, s in labels],
            )
            for (locations, labels), values in six.iteritems(self._location_values)
        ]

        period_type = pprof_pb2.ValueType(type=self._str("time"), unit=self._str("nanoseconds"))

        # WARNING: no code should use _str() here as once the _string_table is serialized below,
        # it won't be updated if you call _str later in the code here
        return pprof_pb2.Profile(
            sample_type=pprof_sample_type,
            sample=sample,
            mapping=[
                pprof_pb2.Mapping(
                    id=1,
                    filename=self._str(program_name),
                ),
            ],
            location=self._locations.values(),
            function=self._functions.values(),
            string_table=self._string_table,
            time_nanos=start_time_ns,
            duration_nanos=duration_ns,
            period=period,
            period_type=period_type,
        )


# Use this format because CPython does not support the class style declaration
StackEventGroupKey = typing.NamedTuple(
    "StackEventGroupKey",
    [
        ("thread_id", str),
        ("thread_native_id", str),
        ("thread_name", str),
        ("task_id", str),
        ("task_name", str),
        ("local_root_span_id", str),
        ("span_id", str),
        ("trace_resource", str),
        ("trace_type", str),
        ("frames", HashableStackTraceType),
        ("nframes", int),
    ],
)


LockEventGroupKey = typing.NamedTuple(
    "LockEventGroupKey",
    [
        ("lock_name", str),
        ("thread_id", str),
        ("thread_name", str),
        ("task_id", str),
        ("task_name", str),
        ("local_root_span_id", str),
        ("span_id", str),
        ("trace_resource", str),
        ("trace_type", str),
        ("frames", HashableStackTraceType),
        ("nframes", int),
    ],
)


StackExceptionEventGroupKey = typing.NamedTuple(
    "StackExceptionEventGroupKey",
    [
        ("thread_id", str),
        ("thread_native_id", str),
        ("thread_name", str),
        ("local_root_span_id", str),
        ("span_id", str),
        ("trace_resource", str),
        ("trace_type", str),
        ("frames", HashableStackTraceType),
        ("nframes", int),
        ("exc_type_name", str),
    ],
)


@attr.s
class PprofExporter(exporter.Exporter):
    """Export recorder events to pprof format."""

    enable_code_provenance = attr.ib(default=True, type=bool)

    def _stack_event_group_key(self, event: event.StackBasedEvent) -> StackEventGroupKey:
        return StackEventGroupKey(
            _none_to_str(event.thread_id),
            _none_to_str(event.thread_native_id),
            _get_thread_name(event.thread_id, event.thread_name),
            _none_to_str(event.task_id),
            _none_to_str(event.task_name),
            _none_to_str(event.local_root_span_id),
            _none_to_str(event.span_id),
            self._get_event_trace_resource(event),
            _none_to_str(event.trace_type),
            # TODO: store this as a tuple directly?
            tuple(event.frames),
            event.nframes,
        )

    def _group_stack_events(
        self, events: typing.Iterable[event.StackBasedEvent]
    ) -> typing.Iterator[typing.Tuple[StackEventGroupKey, typing.Iterator[event.StackBasedEvent]]]:
        return groupby(events, self._stack_event_group_key)

    def _lock_event_group_key(
        self,
        event: _lock.LockEventBase,
    ) -> LockEventGroupKey:
        return LockEventGroupKey(
            _none_to_str(event.lock_name),
            _none_to_str(event.thread_id),
            _get_thread_name(event.thread_id, event.thread_name),
            _none_to_str(event.task_id),
            _none_to_str(event.task_name),
            _none_to_str(event.local_root_span_id),
            _none_to_str(event.span_id),
            self._get_event_trace_resource(event),
            _none_to_str(event.trace_type),
            tuple(event.frames),
            event.nframes,
        )

    def _group_lock_events(
        self, events: typing.Iterable[_lock.LockEventBase]
    ) -> typing.Iterator[typing.Tuple[LockEventGroupKey, typing.Iterator[_lock.LockEventBase]]]:
        return groupby(events, self._lock_event_group_key)

    def _stack_exception_group_key(self, event: stack_event.StackExceptionSampleEvent) -> StackExceptionEventGroupKey:
        exc_type = event.exc_type
        exc_type_name = exc_type.__module__ + "." + exc_type.__name__

        return StackExceptionEventGroupKey(
            _none_to_str(event.thread_id),
            _none_to_str(event.thread_native_id),
            _get_thread_name(event.thread_id, event.thread_name),
            _none_to_str(event.local_root_span_id),
            _none_to_str(event.span_id),
            self._get_event_trace_resource(event),
            _none_to_str(event.trace_type),
            tuple(event.frames),
            event.nframes,
            exc_type_name,
        )

    def _group_stack_exception_events(
        self, events: typing.Iterable[stack_event.StackExceptionSampleEvent]
    ) -> typing.Iterator[
        typing.Tuple[StackExceptionEventGroupKey, typing.Iterator[stack_event.StackExceptionSampleEvent]]
    ]:
        return groupby(events, self._stack_exception_group_key)

    def _get_event_trace_resource(self, event: event.StackBasedEvent) -> str:
        trace_resource = ""
        # Do not export trace_resource for non Web spans for privacy concerns.
        if event.trace_resource_container and event.trace_type == ext.SpanTypes.WEB:
            (trace_resource,) = event.trace_resource_container
        return ensure_str(trace_resource, errors="backslashreplace")

    def export(
        self, events: recorder.EventsType, start_time_ns: int, end_time_ns: int
    ) -> typing.Tuple[pprof_ProfileType, typing.List[Package]]:
        """Convert events to pprof format.

        :param events: The event dictionary from a `ddtrace.profiling.recorder.Recorder`.
        :param start_time_ns: The start time of recording.
        :param end_time_ns: The end time of recording.
        :return: A protobuf Profile object.
        """
        program_name = config.get_application_name() or "<unknown program>"

        sum_period = 0
        nb_event = 0

        converter = _PprofConverter()

        # Handle StackSampleEvent
        stack_events = []
        for event in events.get(stack_event.StackSampleEvent, []):  # type: ignore[call-overload]
            stack_events.append(event)
            sum_period += event.sampling_period
            nb_event += 1

        for (
            (
                thread_id,
                thread_native_id,
                thread_name,
                task_id,
                task_name,
                local_root_span_id,
                span_id,
                trace_resource,
                trace_type,
                frames,
                nframes,
            ),
            grouped_stack_events,
        ) in self._group_stack_events(stack_events):
            converter.convert_stack_event(
                thread_id,
                thread_native_id,
                thread_name,
                task_id,
                task_name,
                local_root_span_id,
                span_id,
                trace_resource,
                trace_type,
                frames,
                nframes,
                list(typing.cast(typing.Iterator[stack_event.StackSampleEvent], grouped_stack_events)),
            )

        # Handle Lock events
        for event_class, convert_fn in (
            (_lock.LockAcquireEvent, converter.convert_lock_acquire_event),
            (_lock.LockReleaseEvent, converter.convert_lock_release_event),
            (_threading.ThreadingLockAcquireEvent, converter.convert_lock_acquire_event),
            (_threading.ThreadingLockReleaseEvent, converter.convert_lock_release_event),
        ):
            lock_events = events.get(event_class, [])  # type: ignore[call-overload]
            sampling_sum_pct = sum(event.sampling_pct for event in lock_events)

            if lock_events:
                sampling_ratio_avg = sampling_sum_pct / (len(lock_events) * 100.0)

                for (
                    lock_name,
                    thread_id,
                    thread_name,
                    task_id,
                    task_name,
                    local_root_span_id,
                    span_id,
                    trace_resource,
                    trace_type,
                    frames,
                    nframes,
                ), l_events in self._group_lock_events(lock_events):
                    convert_fn(  # type: ignore[operator]
                        lock_name,
                        thread_id,
                        thread_name,
                        task_id,
                        task_name,
                        local_root_span_id,
                        span_id,
                        trace_resource,
                        trace_type,
                        frames,
                        nframes,
                        list(l_events),
                        sampling_ratio_avg,
                    )

        for (
            (
                thread_id,
                thread_native_id,
                thread_name,
                local_root_span_id,
                span_id,
                trace_resource,
                trace_type,
                frames,
                nframes,
                exc_type_name,
            ),
            se_events,
        ) in self._group_stack_exception_events(
            events.get(stack_event.StackExceptionSampleEvent, [])  # type: ignore[call-overload]
        ):
            converter.convert_stack_exception_event(
                thread_id,
                thread_native_id,
                thread_name,
                local_root_span_id,
                span_id,
                trace_resource,
                trace_type,
                frames,
                nframes,
                exc_type_name,
                list(typing.cast(typing.Iterator[stack_event.StackExceptionSampleEvent], se_events)),
            )

        if memalloc._memalloc:
            for (
                (
                    thread_id,
                    thread_native_id,
                    thread_name,
                    task_id,
                    task_name,
                    local_root_span_id,
                    span_id,
                    trace_resource,
                    trace_type,
                    frames,
                    nframes,
                ),
                memalloc_events,
            ) in self._group_stack_events(
                events.get(memalloc.MemoryAllocSampleEvent, [])  # type: ignore[call-overload]
            ):
                converter.convert_memalloc_event(
                    thread_id,
                    thread_native_id,
                    thread_name,
                    frames,
                    nframes,
                    list(typing.cast(typing.Iterator[memalloc.MemoryAllocSampleEvent], memalloc_events)),
                )

            for event in events.get(memalloc.MemoryHeapSampleEvent, []):  # type: ignore[call-overload]
                converter.convert_memalloc_heap_event(event)

        # Compute some metadata
        period = None  # type: typing.Optional[int]
        if nb_event:
            period = int(sum_period / nb_event)

        duration_ns = end_time_ns - start_time_ns

        sample_types = (
            ("cpu-samples", "count"),
            ("cpu-time", "nanoseconds"),
            ("wall-time", "nanoseconds"),
            ("exception-samples", "count"),
            ("lock-acquire", "count"),
            ("lock-acquire-wait", "nanoseconds"),
            ("lock-release", "count"),
            ("lock-release-hold", "nanoseconds"),
            ("alloc-samples", "count"),
            ("alloc-space", "bytes"),
            ("heap-space", "bytes"),
        )

        profile = converter._build_profile(
            start_time_ns=start_time_ns,
            duration_ns=duration_ns,
            period=period,
            sample_types=sample_types,
            program_name=program_name,
        )

        # Build profile first to get location filled out
        if self.enable_code_provenance:
            libs = converter._build_libraries()
        else:
            libs = []

        return profile, libs
