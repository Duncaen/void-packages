import argparse
import concurrent.futures
import dataclasses
import enum
import os
import pathlib
import re
import subprocess
import sys
import typing
from collections import deque


class LogLevel(enum.IntEnum):
    NONE = enum.auto()
    ERROR = enum.auto()
    WARN = enum.auto()
    INFO = enum.auto()
    DEBUG = enum.auto()
    FOO = enum.auto()
    BAR = enum.auto()


class Log:
    __slots__ = "level"

    def __init__(self) -> None:
        self.level = LogLevel.INFO

    def error(self, *args: object, end: str | None = None) -> None:
        if self.level < LogLevel.ERROR:
            return
        print(*args, end=end, file=sys.stderr)

    def warn(self, *args: object, end: str | None = None) -> None:
        if self.level < LogLevel.WARN:
            return
        print(*args, end=end, file=sys.stderr)

    def info(self, *args: object, end: str | None = None) -> None:
        if self.level < LogLevel.INFO:
            return
        print(*args, end=end, file=sys.stderr)

    def debug(self, *args: object, end: str | None = None) -> None:
        if self.level < LogLevel.DEBUG:
            return
        print(*args, end=end, file=sys.stderr)


log = Log()


@dataclasses.dataclass(frozen=True, kw_only=True)
class SubDump:
    pkgname: str
    version: str
    revision: str
    sourcepkg: str
    short_desc: str
    depends: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass(frozen=True, kw_only=True)
class Dump:
    pkgname: str
    version: str
    revision: str
    bootstrap: bool = False
    archs: str | None = None
    broken: str | None = None
    nocross: str | None = None
    build_style: str | None = None
    short_desc: str
    maintainer: str

    build_options: list[str] = dataclasses.field(default_factory=list)
    build_options_default: list[str] = dataclasses.field(default_factory=list)
    build_options_enabled: list[str] = dataclasses.field(default_factory=list)

    hostmakedepends: list[str] = dataclasses.field(default_factory=list)
    makedepends: list[str] = dataclasses.field(default_factory=list)
    checkdepends: list[str] = dataclasses.field(default_factory=list)
    depends: list[str] = dataclasses.field(default_factory=list)
    distfiles: list[str] = dataclasses.field(default_factory=list)
    checksum: list[str] = dataclasses.field(default_factory=list)

    subpackages: list[SubDump] = dataclasses.field(default_factory=list)


if typing.TYPE_CHECKING:
    from _typeshed import DataclassInstance


T = typing.TypeVar("T", bound="DataclassInstance")


def dataclass_from_dict(cls: typing.Type[T], d: dict[str, typing.Any]) -> T:
    assert dataclasses.is_dataclass(cls)
    kwargs: dict[str, typing.Any] = {}
    types = {f.name: f.type for f in dataclasses.fields(cls)}
    for key, value in d.items():
        t = types.get(key)
        if t is None:
            continue
        elif t is str:
            kwargs[key] = value
            continue
        elif typing.get_origin(t) is list:
            t1 = typing.get_args(t)[0]
            if t1 is str:
                kwargs[key] = value.split()
                continue
            elif dataclasses.is_dataclass(t1):
                kwargs[key] = [dataclass_from_dict(t1, d) for d in value]
                continue
        raise NotImplementedError(
            f"parsing of field {key} from {type(value)} to {t} not implemented"
        )
    return cls(**kwargs)  # type: ignore[return-value]


ANSIC_UNQUOTE = {
    "\\": "\\",
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "'": "'",
    "E": "\033",
}

DOUBLE_UNQUOTE = {
    "\\": "\\",
    "`": "`",
    "$": "$",
    "'": "'",
    "\n": "\n",
}


def parse(s: str) -> Dump:
    def ansic_unquote(s: str) -> str:
        res = ""
        i = 0
        while i < len(s):
            match s[i]:
                case "\\":
                    i += 1
                    c = s[i]
                    if r := ANSIC_UNQUOTE.get(c, None):
                        res += r
                    elif c >= "0" and c <= "7":
                        n = 0
                        for c in s[i : i + 3]:
                            assert c >= "0" and c <= "7"
                            n = n * 8 + ord(c) - ord("0")
                        i += 3
                        res += chr(n)
                    else:
                        res += f"\\{c}"
                case c:
                    res += c
            i += 1
        return res

    def double_unquote(s: str) -> str:
        res = ""
        i = 0
        while i < len(s):
            match s[i]:
                case "\\":
                    i += 1
                    c = s[i]
                    if r := DOUBLE_UNQUOTE.get(c, None):
                        res += r
                    else:
                        res += f"\\{c}"
                case c:
                    res += c
            i += 1
        return res

    def parse_line(line: str) -> tuple[str, str | list[str] | None]:
        [_, flags, assignment] = line.split(" ", maxsplit=2)
        name, _, val = assignment.partition("=")
        if not val:
            return name, None
        if flags == "--":
            if val.startswith("$'"):
                return name, ansic_unquote(val[2:-1])
            elif val.startswith('"'):
                return name, double_unquote(val[1:-1])
            else:
                raise NotImplementedError(f'parsing "{val}" not implemented')
        else:
            raise NotImplementedError(f'parsing of "{flags}" not implemented')

    pkg: dict[str, typing.Any] = {}
    cur: dict[str, typing.Any] = pkg

    for line in s.splitlines():
        if not line:  # newline indicates the next sub package
            cur = {}
            pkg.setdefault("subpackages", []).append(cur)
        else:
            name, value = parse_line(line)
            if value:
                cur[name] = value

    return dataclass_from_dict(Dump, pkg)


def scan(distdir: pathlib.Path) -> dict[str, list[str]]:
    srcpkgs = set()
    subpkgs = set()
    map: dict[str, list[str]] = {}

    for f in (distdir / "srcpkgs").iterdir():
        if f.is_symlink():
            orig_target = os.readlink(f)
            target = f.readlink().name
            if target != orig_target:
                log.warn(
                    f"warn: '{pathlib.Path('srcpkgs') / f.name}' points to '{orig_target}' instead of '{target}'"
                )
            map.setdefault(target, []).append(f.name)
            subpkgs.add(f.name)
        elif f.is_dir():
            map.setdefault(f.name, [])
            srcpkgs.add(f.name)

    # move sub packages that point to other sub packages
    # to the actual source package.
    remove = []
    for sourcepkg, subs in map.items():
        if sourcepkg not in srcpkgs:
            remove.append(sourcepkg)
            for sub in subs:
                link = (distdir / "srcpkgs" / sourcepkg).readlink()
                while link.is_symlink():
                    link = link.readlink()
                target = link.name
                map.setdefault(target, []).append(sub)
                log.warn(
                    f"warn: '{pathlib.Path('srcpkgs') / sub}' points to '{sourcepkg}' instead of '{target}'"
                )
    for rm in remove:
        del map[rm]

    return map


def bwrap(
    masterdir: pathlib.Path,
    masterdir_rw: bool = False,
    hostdir: pathlib.Path | None = None,
    hostdir_rw: bool = False,
    distdir: pathlib.Path | None = None,
    distdir_rw: bool = False,
) -> list[str]:
    ro = "-" if masterdir_rw else "ro-"
    res = [
        "bwrap",
        f"--{ro}bind",
        str(masterdir),
        "/",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--proc",
        "/proc",
    ]
    if hostdir:
        ro = "" if hostdir_rw else "ro-"
        res.extend([f"--{ro}bind", str(hostdir), "/host"])
    if distdir:
        ro = "" if distdir_rw else "ro-"
        res.extend([f"--{ro}bind", str(distdir), "/void-packages"])
    return res + ["--"]


class Package:
    name: str
    arch: str
    build: typing.Optional["Build"]
    users: list["Build"]
    missing: bool

    def __init__(self, name: str, arch: str) -> None:
        self.name = name
        self.arch = arch
        self.build = None
        self.users = []
        self.missing = True

    def __str__(self) -> str:
        return f"{self.name}@{self.arch}"

    def is_missing(self) -> bool:
        return self.missing


class BuildFlag(enum.IntFlag):
    WORK = enum.auto()
    WANT = enum.auto()
    CYCLE = enum.auto()
    LOADED = enum.auto()
    BROKEN = enum.auto()
    DONE = enum.auto()


_PKGVER = re.compile(r".*_[0-9].*$")


def depname(s: str) -> str:
    """returns the name of a dependency"""
    i = s.find(">")
    if i == -1:
        i = s.find("<")
    if i != -1:
        return s[:i]
    i = s.rfind("-")
    if i != -1 and _PKGVER.match(s[i:]):
        return s[:i]
    return s


tests = {
    "foo>=1": "foo",
    "foo>1": "foo",
    "foo<1": "foo",
    "foo<=1": "foo",
    "foo-1.0_1": "foo",
    "perl-PerlIO-utf8_strict": "perl-PerlIO-utf8_strict",
    "perl-PerlIO-utf8_strict-1": "perl-PerlIO-utf8_strict-1",
    "perl-PerlIO-utf8_strict-a": "perl-PerlIO-utf8_strict-a",
    "perl-PerlIO-utf8_strict-1.0_1": "perl-PerlIO-utf8_strict",
    "python-e_dbus": "python-e_dbus",
    "perl-Digest-1.17_01_1": "perl-Digest",
    "font-adobe-100dpi-1.8_blah": "font-adobe-100dpi-1.8_blah",
    "perl-Module-CoreList-5.20170715_24_1": "perl-Module-CoreList",
    "perl-PerlIO-utf8_strict-0.007_1": "perl-PerlIO-utf8_strict",
    "cross-x86_64-linux-musl-libc-0.34_3": "cross-x86_64-linux-musl-libc",
    "hunspell-en_GB-all": "hunspell-en_GB-all",
}
for s, expect in tests.items():
    assert depname(s) == expect


def virtual_map(file: pathlib.Path) -> dict[str, str]:
    res = {}
    with open(file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            [virtual, provider] = line.split(" ", maxsplit=1)
            res[virtual] = provider
    return res


virtuals: dict[str, str]

no_remote: bool


def clean_depends(
    depends: list[str],
    ignore: frozenset[str] | None = None,
    virtuals: dict[str, str] | None = None,
) -> list[str]:
    """
    remove all version requirements from depends and map virtual packages,
    filter out packages from `ignore` (usually the package itself and its sub
    packages). And map virtual packages, starting with "virtual?" to their
    default provider.
    """
    res: set[str] = set([])
    for dep in depends:
        name = depname(dep)
        if virtuals and name.startswith("virtual?"):
            provider = virtuals.get(name.removeprefix("virtual?"))
            if not provider:
                raise Exception(f'unknown virtual package "{name}"')
            name = provider
        if ignore and name in ignore:
            continue
        res.add(name)
    return list(res)


class Build:
    sourcepkg: str
    builder: "Builder"
    flags: BuildFlag
    inputs: list[Package]
    outputs: list[Package]
    nblock: int

    def __init__(self, sourcepkg: str, builder: "Builder") -> None:
        self.sourcepkg = sourcepkg
        self.builder = builder
        self.flags = BuildFlag(0)
        self.inputs = []
        self.outputs = []
        self.nblock = 0

    def __str__(self) -> str:
        return f"{self.sourcepkg} ({self.builder})"

    def add_outputs(self, outputs: list[Package]) -> None:
        self.outputs.extend(outputs)
        for output in outputs:
            output.build = self

    def add_inputs(self, inputs: list[Package]) -> None:
        self.inputs.extend(inputs)
        for input in inputs:
            input.users.append(self)


def query_packages(
    masterdir: pathlib.Path,
    hostdir: pathlib.Path | None = None,
    cross_base: pathlib.Path | None = None,
    arch: str | None = None,
) -> dict[str, str]:
    cmd = bwrap(masterdir, hostdir=hostdir)
    env = os.environ.copy()
    if cross_base:
        root_arg = ["-r", str(pathlib.Path("/") / cross_base)]
    else:
        root_arg = []
    if arch:
        env.update({"XBPS_TARGET_ARCH": arch})
    cmd.extend(["xbps-query"] + root_arg + ["-dvRp", "pkgver", "-s", ""])
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True, check=True)
    if proc.returncode != 0:
        raise Exception(f"failed to query packages: exit status: {proc.returncode}")
    index: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        [pkgver, _, _repo] = line.split(" ", maxsplit=2)
        [pkgname, version] = pkgver[:-1].rsplit("-", maxsplit=1)
        index.setdefault(pkgname, version)
    return index


def checkvers(
    masterdir: pathlib.Path,
    hostdir: pathlib.Path | None = None,
    cross_base: pathlib.Path | None = None,
    arch: str | None = None,
) -> dict[str, str]:
    cmd = bwrap(masterdir, hostdir=hostdir)
    env = os.environ.copy()
    if cross_base:
        root_arg = ["-r", str(pathlib.Path("/") / cross_base)]
    else:
        root_arg = []
    if arch:
        env.update({"XBPS_TARGET_ARCH": arch})
    cmd.extend(["xbps-query"] + root_arg + ["-dvRp", "pkgver", "-s", ""])
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True, check=True)
    if proc.returncode != 0:
        raise Exception(f"failed to query packages: exit status: {proc.returncode}")
    index: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        [pkgver, _, _repo] = line.split(" ", maxsplit=2)
        [pkgname, version] = pkgver[:-1].rsplit("-", maxsplit=1)
        index.setdefault(pkgname, version)
    return index


class Builder:
    arch: str

    def dump(self, pkgname: str) -> Dump:
        raise NotImplementedError("dump not implemenetd")

    def get_package(self, name: str) -> Package:
        raise NotImplementedError("dump not implemenetd")

    def load_dump(self, build: Build, dump: Dump) -> None:
        raise NotImplementedError("dump not implemenetd")

    def add_build(self, sourcepkg: str, subpackages: list[str]) -> None:
        build = Build(sourcepkg, self)
        build.add_outputs(
            [self.get_package(sourcepkg)]
            + [self.get_package(subpkg) for subpkg in subpackages]
        )


class NativeBuilder(Builder):
    arch: str
    masterdir: pathlib.Path
    hostdir: pathlib.Path
    index: dict[str, str]
    builds: dict[str, Build]
    packages: dict[str, Package]

    def __init__(
        self,
        arch: str,
        host: str | None = None,
        masterdir: pathlib.Path | None = None,
        hostdir: pathlib.Path | None = None,
    ) -> None:
        self.arch = arch
        self.host = host
        self.builds = {}
        self.packages = {}

        if not masterdir:
            masterdir = pathlib.Path(self._get_var("XBPS_MASTERDIR"))
        self.masterdir = masterdir

        if not hostdir:
            hostdir = pathlib.Path(self._get_var("XBPS_HOSTDIR"))
        self.hostdir = hostdir

    def __str__(self) -> str:
        return self.arch

    def _arch_flags(self, host: bool = False) -> list[str]:
        if not host and self.host:
            return ["-A", self.host, "-a", self.arch]
        return ["-A", self.arch]

    def _get_var(self, name: str) -> str:
        env = os.environ.copy()
        env.update(
            {
                "SKIP_BUILD_REQUIREMENTS": "1",
                "SKIP_GETOPT": "1",
                "GNU_STAT": "1",
                "XBPS_USE_BUILD_MTIME": "1",
                "XBPS_USE_GIT_REVS": "",
                "XBPS_ALT_REPOSITORY": "1",
                "XBPS_DISTDIR": str(pathlib.Path.cwd()),
            }
        )
        cmd = ["./xbps-src"] + self._arch_flags() + ["show-var", name]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return proc.stdout.rstrip()

    def bootstrap_update(self) -> None:
        subprocess.run(
            ["./xbps-src", "-A", self.arch]
            + (["-N"] if no_remote else [])
            + ["bootstrap-update"]
        )

    def dump(self, pkgname: str) -> Dump:
        template = pathlib.Path("srcpkgs") / pkgname / "template"
        script = "common/scripts/dump-template"
        cmd = ([script, str(template)],)
        proc = subprocess.run(*cmd, capture_output=True, text=True, check=True)
        try:
            return parse(proc.stdout)
        except TypeError as e:
            raise Exception(f"failed to parse: {pkgname}: {e}")

    def load_dump(self, build: Build, dump: Dump) -> None:
        hostdeps: set[str] = set(dump.hostmakedepends)
        build.add_inputs([self.get_package(dep) for dep in hostdeps])

        deps: set[str] = set(dump.hostmakedepends)
        deps.update(dump.makedepends)

        ignore = frozenset(
            [dump.pkgname] + list(sub.pkgname for sub in dump.subpackages)
        )

        deps.update(clean_depends(dump.depends, ignore=ignore, virtuals=virtuals))
        for subpkg in dump.subpackages:
            deps.update(clean_depends(subpkg.depends, ignore, virtuals=virtuals))

        build.add_inputs([self.get_package(dep) for dep in deps])

    def get_package(self, name: str) -> Package:
        key = name
        if pkg := self.packages.get(key):
            return pkg
        self.packages[key] = pkg = Package(name, self.arch)
        return pkg


class CrossBuilder(Builder):
    arch: str
    host: str | NativeBuilder

    cross_base: pathlib.Path
    triplet: str | None

    index: dict[str, str]
    builds: dict[str, Build]
    packages: dict[tuple[str, str], Package]

    def __init__(
        self,
        arch: str,
        host: str | NativeBuilder,
    ) -> None:
        self.arch = arch
        self.host = host
        self.builds = {}
        self.packages = {}
        self.triplet = self._get_var("XBPS_CROSS_TRIPLET")
        self.cross_base = pathlib.Path("usr") / self.triplet

    def __str__(self) -> str:
        return f"{self.arch}@{self.host_arch}"

    @property
    def host_arch(self) -> str:
        if isinstance(self.host, str):
            return self.host
        return self.host.arch

    def _get_var(self, name: str) -> str:
        env = os.environ.copy()
        env.update(
            {
                "XBPS_USE_BUILD_MTIME": "1",
                "XBPS_USE_GIT_REVS": "",
                "XBPS_ALT_REPOSITORY": "1",
                "XBPS_DISTDIR": str(pathlib.Path.cwd()),
            }
        )
        cmd = ["./xbps-src", "-A", self.host_arch, "-a", self.arch, "show-var", name]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return proc.stdout.rstrip()

    def bootstrap_update(self) -> None:
        subprocess.run(
            ["./xbps-src", "-A", self.host_arch, "-a", self.arch]
            + (["-N"] if no_remote else [])
            + ["bootstrap-update"]
        )

    def dump(self, pkgname: str) -> Dump:
        template = pathlib.Path("srcpkgs") / pkgname / "template"
        script = "common/scripts/dump-template"
        cmd = ([script, str(template)],)
        proc = subprocess.run(*cmd, capture_output=True, text=True, check=True)
        try:
            return parse(proc.stdout)
        except TypeError as e:
            raise Exception(f"failed to parse: {pkgname}: {e}")

    def get_host_package(self, name: str) -> Package:
        if isinstance(self.host, NativeBuilder):
            return self.host.get_package(name)
        key = (name, self.host_arch)
        if pkg := self.packages.get(key):
            return pkg
        self.packages[key] = pkg = Package(name, self.host_arch)
        return pkg

    def get_package(self, name: str) -> Package:
        key = (name, self.arch)
        if pkg := self.packages.get(key):
            return pkg
        self.packages[key] = pkg = Package(name, self.arch)
        return pkg

    def load_dump(self, build: Build, dump: Dump) -> None:
        hostdeps: set[str] = set(dump.hostmakedepends)
        build.add_inputs([self.get_host_package(dep) for dep in hostdeps])

        deps: set[str] = set(dump.makedepends)

        ignore = frozenset(
            [dump.pkgname] + list(sub.pkgname for sub in dump.subpackages)
        )

        deps.update(clean_depends(dump.depends, ignore=ignore, virtuals=virtuals))
        for subpkg in dump.subpackages:
            deps.update(clean_depends(subpkg.depends, ignore, virtuals=virtuals))

        build.add_inputs([self.get_package(dep) for dep in deps])


class CycleError(Exception):
    nodes: list[Package]

    def __init__(self, pkg: Package, stack: list[Package]) -> None:
        start = next(i for i, x in enumerate(stack) if x.build is pkg.build)
        self.nodes = stack[start:] + [pkg]
        super().__init__(
            "cycle error: " + " -> ".join(node.name for node in self.nodes)
        )


class Graph:
    _load: deque[Build]
    _build: deque[Build]

    def __init__(self) -> None:
        self._load = deque()
        self._build = deque()

    def build_add(self, pkg: Package) -> None:
        # stack: collections.deque[Package] = collections.deque()
        # self._build_add(self.get_pkg(pkgname), stack)
        self._recompute_dirty(pkg)

    # def _want_pkg(self, pkg: Package, stack: deque[Package]) -> bool:
    #     build = pkg.build
    #     if not build:
    #         return True
    #     if build.flags & BuildFlag.CYCLE:
    #         raise CycleError(pkg, list(stack))
    #     self._want_build(build, stack)

    # def _want_build(self, build: Build, stack: deque[Package]) -> None:
    #     stack.append(pkg)
    #     for input in build.inputs:
    #         self.want_pkg(input)
    #     last = stack.pop()
    #     assert pkg == last

    def _recompute_node_dirty(
        self,
        pkg: Package,
        builder: Builder,
        stack: deque[Package],
        dependent: Package | None = None,
    ) -> bool:
        # print("recompute dirty:", pkg.name)
        build = pkg.build
        if build is None:
            ref = ""
            if dependent:
                ref = f", needed for {dependent}"
            log.error(f"{pkg}{ref} is missing and can not be build")
            return False
        if build.flags & BuildFlag.BROKEN:
            return False
        if build.flags & BuildFlag.CYCLE:
            raise CycleError(pkg, list(stack))
        if build.flags & BuildFlag.WORK:
            return True
        if build.flags & BuildFlag.DONE:
            return True

        build.flags |= BuildFlag.WANT | BuildFlag.WORK | BuildFlag.CYCLE
        stack.append(pkg)

        for outout in build.outputs:
            pass

        if build.flags & BuildFlag.LOADED == 0:
            self._load.append(build)
        else:
            build.nblock = 0
            for input in build.inputs:
                if not self._recompute_node_dirty(input, stack, dependent=pkg):
                    pass
                if input.is_missing():
                    build.nblock += 1
            if build.nblock == 0 and build.flags & BuildFlag.DONE == 0:
                self._build.append(build)

        popped = stack.pop()
        assert popped is pkg
        build.flags &= ~BuildFlag.CYCLE
        return True

    def _recompute_dirty(self, pkg: Package) -> None:
        stack: deque[Package] = deque()
        self._recompute_node_dirty(pkg, stack)

    def _unmark_dependents(self, pkg: Package) -> None:
        # print("_unmark_dependents", pkg.name)
        for user in pkg.users:
            if user.flags & BuildFlag.WORK == 0:
                continue
            user.flags &= ~BuildFlag.WORK
            for output in user.outputs:
                self._unmark_dependents(output)

    def unmark(self, build: Build) -> None:
        build.flags &= ~BuildFlag.WORK
        for output in build.outputs:
            self._unmark_dependents(output)

    def refresh_dependencies(self, build: Build) -> None:
        # dependents: set[Build] = set([])
        # for output in build.outputs:
        #     self._unmark_dependents(output, dependents)
        # for dependent in dependents:
        #     self._recompute_dirty(dependent)
        build.flags |= BuildFlag.LOADED
        build.flags &= ~BuildFlag.WORK
        self._recompute_dirty(build.outputs[0])

    def pkg_done(self, pkg: Package) -> None:
        for user in pkg.users:
            if (
                user.flags & BuildFlag.WANT == 0
                or user.flags & BuildFlag.DONE
                or user.nblock == 0
            ):
                continue
            user.nblock -= 1
            if user.nblock == 0:
                self._build.append(user)

    def build_done(self, build: Build) -> None:
        build.flags |= BuildFlag.DONE
        for output in build.outputs:
            # if not output.exists():  # build might not generate outputs
            #     pass
            self.pkg_done(output)


def default_arch() -> str:
    proc = subprocess.run(
        ["xbps-uhelper", "arch"], capture_output=True, text=True, check=True
    )
    return proc.stdout.strip()


def setup_builders(args: argparse.Namespace) -> list[Builder]:
    if not args.builder:
        return [NativeBuilder(default_arch())]

    res: list[Builder] = []
    for x in args.builder:
        match x.split("@", maxsplit=1):
            case [target, host]:
                host_builder = next(
                    (x for x in res if isinstance(x, NativeBuilder) and x.arch == host),
                    None,
                )
                res.append(CrossBuilder(target, host_builder or host))
            case [target]:
                res.append(NativeBuilder(target))

    return res


def run(graph: Graph) -> None:
    done = 0
    failed = 0
    total = 0

    with (
        concurrent.futures.ThreadPoolExecutor(max_workers=8) as load_pool,
        concurrent.futures.ThreadPoolExecutor(max_workers=1) as build_pool,
    ):
        futures: dict[concurrent.futures.Future[Dump], Build] = {}
        loaded: deque[Build] = deque()
        while True:
            if len(futures) == 0 and len(graph._load) == 0 and len(graph._build) == 0:
                break
            while len(graph._load) > 0:
                build = graph._load.pop()
                future = load_pool.submit(build.builder.dump, build.sourcepkg)
                futures[future] = build
                total += 1
            while len(graph._build) > 0:
                build = graph._build.pop()
                print(f"build {build}")
                graph.build_done(build)
            for future in concurrent.futures.as_completed(futures):
                build = futures.pop(future)
                done += 1
                try:
                    dump = future.result()
                except subprocess.CalledProcessError as e:
                    failed += 1
                    log.error(
                        f"[{done}/{total}] failed to load {build} with exit "
                        f"status: {e.returncode}"
                    )
                    log.error(e.stderr.rstrip())
                except Exception as e:
                    failed += 1
                    log.error(f"[{done}/{total}] failed to load {build} with exception")
                    log.error(e)
                    # raise e
                else:
                    if isinstance(dump, Dump):
                        log.info(f"[{done}/{total}] loaded {build}")
                        build.builder.load_dump(build, dump)
                        graph.unmark(build)
                        loaded.append(build)
            for build in loaded:
                graph.refresh_dependencies(build)
            loaded.clear()


def cmd_build(args: argparse.Namespace) -> None:
    distdir = pathlib.Path.cwd()

    global virtuals
    virtuals = virtual_map(distdir / "etc/defaults.virtual")

    graph = Graph()
    builders = setup_builders(args)

    log.debug("scanning packages")
    pkgs = scan(distdir)

    for sourcepkg, subpkgs in pkgs.items():
        for builder in builders:
            builder.add_build(sourcepkg, subpkgs)

    # for sourcepkg, subpkgs in pkgs.items():
    #     for builder in builders:
    #         build = graph.add_build(sourcepkg, builder)
    #         build.add_outputs(
    #             list(
    #                 graph.get_pkg(name, builder.arch) for name in [sourcepkg] + subpkgs
    #             )
    #         )

    if len(args.targets) > 0:
        for target in args.targets:
            match target.split("@", maxsplit=1):
                case [pkgname, arch]:
                    builder = next((x for x in builders if x.arch == arch), None)
                    if not builder:
                        log.error(
                            f"can't build {pkgname} for {arch}, no matching builder not found."
                        )
                        continue
                    graph.build_add(builder.get_package(pkgname))
                case [pkgname]:
                    for builder in builders:
                        graph.build_add(builder.get_package(pkgname))
    else:
        raise Exception
        # for pkg in graph._pkgs.values():
        #     if len(pkg.users) > 0:
        #         continue
        #     graph.build_add(pkg.name, pkg.arch)

    run(graph)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("targets", nargs="*")
    parser.add_argument(
        "--no-remote",
        "-N",
        action="store_true",
        help="Disable use of remote repositories to resolve dependencies",
    )
    parser.add_argument("--explain", "-e", help="explain")
    parser.add_argument(
        "--log-level",
        default="info",
        choices=["debug", "info", "warn", "error", "none"],
    )

    parser.add_argument(
        "--builder",
        "-B",
        action="append",
        help="",
    )
    parser.add_argument(
        "--distdir",
        "-D",
        type=pathlib.Path,
        help="path to void-packages",
    )
    parser.add_argument(
        "--host",
        "-A",
        help="host architecture for cross builds",
    )

    # subparsers = parser.add_subparsers(title='builder', help='builder', required=True)

    # subparser = subparsers.add_parser('build')
    # subparser.add_argument('arch')
    # subparser.set_defaults(func=cmd_bootstrap)

    args = parser.parse_args()
    log.level = LogLevel[args.log_level.upper()]
    log.debug(f"arguments: {args}")

    global no_remote
    no_remote = args.no_remote

    cmd_build(args)


if __name__ == "__main__":
    main()
