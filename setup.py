import hashlib
import os
import platform
import shutil
import sys
import tarfile
import glob
import subprocess

from setuptools import setup, find_packages, Extension
from setuptools.command.build_ext import build_ext as BuildExtCommand
from setuptools.command.build_py import build_py as BuildPyCommand
from pkg_resources import get_build_platform
from distutils.command.clean import clean as CleanCommand

try:
    # ORDER MATTERS
    # Import this after setuptools or it will fail
    from Cython.Build import cythonize  # noqa: I100
    import Cython.Distutils
except ImportError:
    raise ImportError(
        "Failed to import Cython modules. This can happen under versions of pip older than 18 that don't "
        "support installing build requirements during setup. If you're using pip, make sure it's a "
        "version >=18.\nSee the quickstart documentation for more information:\n"
        "https://ddtrace.readthedocs.io/en/stable/installation_quickstart.html"
    )


if sys.version_info >= (3, 0):
    from urllib.error import HTTPError
    from urllib.request import urlretrieve
else:
    from urllib import urlretrieve

    from urllib2 import HTTPError


HERE = os.path.dirname(os.path.abspath(__file__))

DEBUG_COMPILE = "DD_COMPILE_DEBUG" in os.environ

IS_PYSTON = hasattr(sys, "pyston_version_info")

LIBDDWAF_DOWNLOAD_DIR = os.path.join(HERE, os.path.join("ddtrace", "appsec", "ddwaf", "libddwaf"))

CURRENT_OS = platform.system()

LIBDDWAF_VERSION = "1.10.0"


def verify_libddwaf_checksum(sha256_filename, filename, current_os):
    # sha256 File format is ``checksum`` followed by two whitespaces, then ``filename`` then ``\n``
    expected_checksum, expected_filename = list(filter(None, open(sha256_filename, "r").read().strip().split(" ")))
    actual_checksum = hashlib.sha256(open(filename, "rb").read()).hexdigest()
    try:
        assert expected_filename.endswith(filename)
        assert expected_checksum == actual_checksum
    except AssertionError:
        print("Checksum verification error: Checksum and/or filename don't match:")
        print("expected checksum: %s" % expected_checksum)
        print("actual checksum: %s" % actual_checksum)
        print("expected filename: %s" % expected_filename)
        print("actual filename: %s" % filename)
        sys.exit(1)


def load_module_from_project_file(mod_name, fname):
    """
    Helper used to load a module from a file in this project

    DEV: Loading this way will by-pass loading all parent modules
         e.g. importing `ddtrace.vendor.psutil.setup` will load `ddtrace/__init__.py`
         which has side effects like loading the tracer
    """
    fpath = os.path.join(HERE, fname)

    if sys.version_info >= (3, 5):
        import importlib.util

        spec = importlib.util.spec_from_file_location(mod_name, fpath)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    elif sys.version_info >= (3, 3):
        from importlib.machinery import SourceFileLoader

        return SourceFileLoader(mod_name, fpath).load_module()
    else:
        import imp

        return imp.load_source(mod_name, fpath)


def is_64_bit_python():
    return sys.maxsize > (1 << 32)


class CleanLibraries(CleanCommand):
    @staticmethod
    def remove_dynamic_library():
        shutil.rmtree(LIBDDWAF_DOWNLOAD_DIR, True)

    def run(self):
        CleanLibraries.remove_dynamic_library()
        CleanCommand.run(self)


class BuildExtWithUpx(BuildExtCommand):
    upx_addresses = {
        "x86_64": "https://github.com/upx/upx/releases/download/v4.0.2/upx-4.0.2-amd64_linux.tar.xz",
        "aarch64": "https://github.com/upx/upx/releases/download/v4.0.2/upx-4.0.2-arm64_linux.tar.xz",
    }
    upx_filename = "upx.tar.xz"
    upx_shas = {
      "x86_64": "c6274d23944608fb5db5b07b478c09fbe29b7a11dab2484f61e07f5195dddc3c",
      "aarch64": "2aae3cf0104d1494237603206a7a220a20067c5b25b43626513bfb9f5fdffe78",
    }
    upx_dir = "/tmp"
    upx_loc = upx_dir + "/upx"

    def download_upx(self):
        if os.path.isfile(self.upx_loc):
            # If the file exists, no need to get it
            return True

        # Don't even try on unsupported platforms
        if CURRENT_OS != "Linux":
            return False

        upx_address = None
        upx_sha = None
        if get_build_platform().endswith("x86_64"):
          upx_address = upx_addresses["x86_64"]
          upx_sha = upx_shas["x86_64"]
        elif get_build_platform().endswith("aarch64"):
          upx_address = upx_addresses["aarch64"]
          upx_sha = upx_shas["aarch64"]
        else:
            return False

        try:
            filename, http_response = urlretrieve(self.upx_address, self.upx_filename)
        except HTTPError:
            print("No UPX binary found at : " + self.upx_address)
            return False

        # Check the file's checksum
        actual_sha = hashlib.sha256(open(self.upx_filename, "rb").read()).hexdigest()
        try:
            assert self.upx_filename.endswith(filename)
            assert self.upx_sha == actual_sha
        except AssertionError:
            print("self.upx checksum verification error: Checksum and/or filename don't match:")
            print("expected checksum: %s" % self.upx_sha)
            print("actual checksum: %s" % actual_sha)
            print("expected filename: %s" % self.upx_filename)
            print("actual filename: %s" % filename)
            return False

        # Decompress.  Use subprocess because xz isn't well-supported through
        # tarfile on 2.7
        try:
            subprocess.check_call(["tar", "-xJf", self.upx_filename, "-C", self.upx_dir])
        except subprocess.CalledProcessError:
            print("Error extracting upx binary from tarfile")
            return False

        # upx is +x in tarball, so we can cleanup now--done
        os.remove(filename)

        if not os.path.isfile(self.upx_loc):
            print("Error getting upx")
            return False
        return True

    def compress_shared_objects(self):
        sofiles = glob.glob("**/*.so", recursive=True)
        for so in sofiles:
            try:
                # -f because some sofiles may be non-exec at this point
                subprocess.check_call([self.upx_loc, "--lzma", "-t", "-f", so])
                print("Compressed " + so + " with upx")
            except subprocess.CalledProcessError:
                print("Failed to compress " + so + " with upx")

    def run(self):
        BuildExtCommand.run(self)
        if self.download_upx():
            self.compress_shared_objects()


class LibDDWaf_Download(BuildPyCommand):
    @staticmethod
    def download_dynamic_library():
        TRANSLATE_SUFFIX = {"Windows": ".dll", "Darwin": ".dylib", "Linux": ".so"}
        AVAILABLE_RELEASES = {
            "Windows": ["win32", "x64"],
            "Darwin": ["arm64", "x86_64"],
            "Linux": ["aarch64", "x86_64"],
        }
        SUFFIX = TRANSLATE_SUFFIX[CURRENT_OS]

        # If the directory exists and it is not empty, assume the right files are there.
        # Use `python setup.py clean` to remove it.
        if os.path.isdir(LIBDDWAF_DOWNLOAD_DIR) and len(os.listdir(LIBDDWAF_DOWNLOAD_DIR)):
            return

        if not os.path.isdir(LIBDDWAF_DOWNLOAD_DIR):
            os.makedirs(LIBDDWAF_DOWNLOAD_DIR)

        for arch in AVAILABLE_RELEASES[CURRENT_OS]:
            if CURRENT_OS == "Linux" and not get_build_platform().endswith(arch):
                # We cannot include the dynamic libraries for other architectures here.
                continue
            elif CURRENT_OS == "Darwin":
                # Detect build type for macos:
                # https://github.com/pypa/cibuildwheel/blob/main/cibuildwheel/macos.py#L250
                target_platform = os.getenv("PLAT")
                # Darwin Universal2 should bundle both architectures
                if not target_platform.endswith(("universal2", arch)):
                    continue
            elif CURRENT_OS == "Windows" and (not is_64_bit_python() != arch.endswith("32")):
                # Win32 can be built on a 64-bit machine so build_platform may not be relevant
                continue

            arch_dir = os.path.join(LIBDDWAF_DOWNLOAD_DIR, arch)

            # If the directory for the architecture exists, assume the right files are there
            if os.path.isdir(arch_dir):
                continue

            ddwaf_archive_dir = "libddwaf-%s-%s-%s" % (LIBDDWAF_VERSION, CURRENT_OS.lower(), arch)
            ddwaf_archive_name = ddwaf_archive_dir + ".tar.gz"

            ddwaf_download_address = "https://github.com/DataDog/libddwaf/releases/download/%s/%s" % (
                LIBDDWAF_VERSION,
                ddwaf_archive_name,
            )
            ddwaf_sha256_address = ddwaf_download_address + ".sha256"

            try:
                filename, http_response = urlretrieve(ddwaf_download_address, ddwaf_archive_name)
                sha256_filename, http_response = urlretrieve(ddwaf_sha256_address, ddwaf_archive_name + ".sha256")
            except HTTPError as e:
                print("No archive found for dynamic library ddwaf : " + ddwaf_archive_dir)
                raise e

            # Verify checksum of downloaded file
            verify_libddwaf_checksum(sha256_filename, filename, CURRENT_OS)

            # Open the tarfile first to get the files needed.
            # This could be solved with "r:gz" mode, that allows random access
            # but that approach does not work on Windows
            with tarfile.open(filename, "r|gz", errorlevel=2) as tar:
                dynfiles = [c for c in tar.getmembers() if c.name.endswith(SUFFIX)]

            with tarfile.open(filename, "r|gz", errorlevel=2) as tar:
                print("extracting files:", [c.name for c in dynfiles])
                tar.extractall(members=dynfiles, path=HERE)
                os.rename(os.path.join(HERE, ddwaf_archive_dir), arch_dir)

            # Rename ddwaf.xxx to libddwaf.xxx so the filename is the same for every OS
            original_file = os.path.join(arch_dir, "lib", "ddwaf" + SUFFIX)
            if os.path.exists(original_file):
                renamed_file = os.path.join(arch_dir, "lib", "libddwaf" + SUFFIX)
                os.rename(original_file, renamed_file)

            os.remove(filename)

    def run(self):
        CleanLibraries.remove_dynamic_library()
        LibDDWaf_Download.download_dynamic_library()
        BuildPyCommand.run(self)


long_description = """
# dd-trace-py

`ddtrace` is Datadog's tracing library for Python.  It is used to trace requests
as they flow across web servers, databases and microservices so that developers
have great visibility into bottlenecks and troublesome requests.

## Getting Started

For a basic product overview, installation and quick start, check out our
[setup documentation][setup docs].

For more advanced usage and configuration, check out our [API
documentation][api docs].

For descriptions of terminology used in APM, take a look at the [official
documentation][visualization docs].

[setup docs]: https://docs.datadoghq.com/tracing/setup/python/
[api docs]: https://ddtrace.readthedocs.io/
[visualization docs]: https://docs.datadoghq.com/tracing/visualization/
"""


def get_exts_for(name):
    try:
        mod = load_module_from_project_file(
            "ddtrace.vendor.{}.setup".format(name), "ddtrace/vendor/{}/setup.py".format(name)
        )
        return mod.get_extensions()
    except Exception as e:
        print("WARNING: Failed to load %s extensions, skipping: %s" % (name, e))
        return []


if sys.byteorder == "big":
    encoding_macros = [("__BIG_ENDIAN__", "1")]
else:
    encoding_macros = [("__LITTLE_ENDIAN__", "1")]


if CURRENT_OS == "Windows":
    encoding_libraries = ["ws2_32"]
    extra_compile_args = []
    debug_compile_args = []
else:
    linux = CURRENT_OS == "Linux"
    encoding_libraries = []
    extra_compile_args = ["-DPy_BUILD_CORE"]
    if DEBUG_COMPILE:
        if linux:
            debug_compile_args = ["-g", "-O0", "-Wall", "-Wextra", "-Wpedantic"]
        else:
            debug_compile_args = [
                "-g",
                "-O0",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                # Cython is not deprecation-proof
                "-Wno-deprecated-declarations",
            ]
    else:
        debug_compile_args = []

if sys.version_info[:2] >= (3, 4) and not IS_PYSTON:
    ext_modules = [
        Extension(
            "ddtrace.profiling.collector._memalloc",
            sources=[
                "ddtrace/profiling/collector/_memalloc.c",
                "ddtrace/profiling/collector/_memalloc_tb.c",
                "ddtrace/profiling/collector/_memalloc_heap.c",
            ],
            extra_compile_args=debug_compile_args,
        ),
    ]
    if platform.system() not in ("Windows", ""):
        ext_modules.append(
            Extension(
                "ddtrace.appsec.iast._stacktrace",
                # Sort source files for reproducibility
                sources=[
                    "ddtrace/appsec/iast/_stacktrace.c",
                ],
                extra_compile_args=debug_compile_args,
            )
        )
        if sys.version_info >= (3, 6, 0):
            ext_modules.append(
                Extension(
                    "ddtrace.appsec.iast._taint_tracking._native",
                    # Sort source files for reproducibility
                    sources=sorted(
                        glob.glob(
                            os.path.join("ddtrace", "appsec", "iast", "_taint_tracking", "**", "*.cpp"),
                            recursive=True,
                        )
                    ),
                    extra_compile_args=debug_compile_args + ["-std=c++17"],
                )
            )
else:
    ext_modules = []


bytecode = [
    "dead-bytecode; python_version<'3.0'",  # backport of bytecode for Python 2.7
    "bytecode~=0.12.0; python_version=='3.5'",
    "bytecode~=0.13.0; python_version=='3.6'",
    "bytecode~=0.13.0; python_version=='3.7'",
    "bytecode; python_version>='3.8'",
]

setup(
    name="ddtrace",
    description="Datadog APM client library",
    url="https://github.com/DataDog/dd-trace-py",
    package_urls={
        "Changelog": "https://ddtrace.readthedocs.io/en/stable/release_notes.html",
        "Documentation": "https://ddtrace.readthedocs.io/en/stable/",
    },
    project_urls={
        "Bug Tracker": "https://github.com/DataDog/dd-trace-py/issues",
        "Source Code": "https://github.com/DataDog/dd-trace-py/",
        "Changelog": "https://ddtrace.readthedocs.io/en/stable/release_notes.html",
        "Documentation": "https://ddtrace.readthedocs.io/en/stable/",
    },
    author="Datadog, Inc.",
    author_email="dev@datadoghq.com",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="BSD",
    packages=find_packages(exclude=["tests*", "benchmarks"]),
    package_data={
        "ddtrace": ["py.typed"],
        "ddtrace.appsec": ["rules.json"],
        "ddtrace.appsec.ddwaf": [os.path.join("libddwaf", "*", "lib", "libddwaf.*")],
    },
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*",
    zip_safe=False,
    # enum34 is an enum backport for earlier versions of python
    # funcsigs backport required for vendored debtcollector
    install_requires=[
        "ddsketch>=2.0.1",
        "enum34; python_version<'3.4'",
        "funcsigs>=1.0.0; python_version=='2.7'",
        "typing; python_version<'3.5'",
        "protobuf>=3; python_version>='3.7'",
        "protobuf>=3,<4.0; python_version=='3.6'",
        "protobuf>=3,<3.18; python_version<'3.6'",
        "tenacity>=5",
        "attrs>=20; python_version>'2.7'",
        "attrs>=20,<22; python_version=='2.7'",
        "contextlib2<1.0; python_version=='2.7'",
        "cattrs<1.1; python_version<='3.6'",
        "cattrs; python_version>='3.7'",
        "six>=1.12.0",
        "typing_extensions",
        "importlib_metadata; python_version<'3.8'",
        "pathlib2; python_version<'3.5'",
        "jsonschema",
        "xmltodict>=0.12",
        "ipaddress; python_version<'3.7'",
        "envier",
        "pep562; python_version<'3.7'",
        "opentelemetry-api>=1; python_version>='3.7'",
    ]
    + bytecode,
    extras_require={
        # users can include opentracing by having:
        # install_requires=['ddtrace[opentracing]', ...]
        "opentracing": ["opentracing>=2.0.0"],
    },
    tests_require=["flake8"],
    cmdclass={
        "build_ext": BuildExtWithUpx,
        "build_py": LibDDWaf_Download,
        "clean": CleanLibraries,
    },
    entry_points={
        "console_scripts": [
            "ddtrace-run = ddtrace.commands.ddtrace_run:main",
        ],
        "pytest11": [
            "ddtrace = ddtrace.contrib.pytest.plugin",
            "ddtrace.pytest_bdd = ddtrace.contrib.pytest_bdd.plugin",
        ],
        "opentelemetry_context": [
            "ddcontextvars_context = ddtrace.opentelemetry._context:DDRuntimeContext",
        ],
    },
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    use_scm_version={"write_to": "ddtrace/_version.py"},
    setup_requires=["setuptools_scm[toml]>=4", "cython"],
    ext_modules=ext_modules
    + cythonize(
        [
            Cython.Distutils.Extension(
                "ddtrace.internal._rand",
                sources=["ddtrace/internal/_rand.pyx"],
                language="c",
            ),
            Cython.Distutils.Extension(
                "ddtrace.internal._tagset",
                sources=["ddtrace/internal/_tagset.pyx"],
                language="c",
            ),
            Extension(
                "ddtrace.internal._encoding",
                ["ddtrace/internal/_encoding.pyx"],
                include_dirs=["."],
                libraries=encoding_libraries,
                define_macros=encoding_macros,
            ),
            Cython.Distutils.Extension(
                "ddtrace.profiling.collector.stack",
                sources=["ddtrace/profiling/collector/stack.pyx"],
                language="c",
                extra_compile_args=extra_compile_args,
            ),
            Cython.Distutils.Extension(
                "ddtrace.profiling.collector._traceback",
                sources=["ddtrace/profiling/collector/_traceback.pyx"],
                language="c",
            ),
            Cython.Distutils.Extension(
                "ddtrace.profiling._threading",
                sources=["ddtrace/profiling/_threading.pyx"],
                language="c",
            ),
            Cython.Distutils.Extension(
                "ddtrace.profiling.collector._task",
                sources=["ddtrace/profiling/collector/_task.pyx"],
                language="c",
            ),
            Cython.Distutils.Extension(
                "ddtrace.profiling.exporter.pprof",
                sources=["ddtrace/profiling/exporter/pprof.pyx"],
                language="c",
            ),
            Cython.Distutils.Extension(
                "ddtrace.profiling._build",
                sources=["ddtrace/profiling/_build.pyx"],
                language="c",
            ),
        ],
        compile_time_env={
            "PY_MAJOR_VERSION": sys.version_info.major,
            "PY_MINOR_VERSION": sys.version_info.minor,
            "PY_MICRO_VERSION": sys.version_info.micro,
        },
        force=True,
        annotate=os.getenv("_DD_CYTHON_ANNOTATE") == "1",
    )
    + get_exts_for("wrapt")
    + get_exts_for("psutil"),
)
