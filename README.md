# ProcfsRoot

[![PkgGoDev](https://pkg.go.dev/badge/github.com/thediveo/procfsroot)](https://pkg.go.dev/github.com/thediveo/procfsroot)
[![GitHub](https://img.shields.io/github/license/thediveo/procfsroot)](https://img.shields.io/github/license/thediveo/procfsroot)
![build and test](https://github.com/thediveo/procfsroot/actions/workflows/buildandtest.yaml/badge.svg?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/thediveo/procfsroot)](https://goreportcard.com/report/github.com/thediveo/procfsroot)
![Coverage](https://img.shields.io/badge/Coverage-96.9%25-brightgreen)

`procfsroot` is a small Go module that helps with accessing file system paths
containing absolute symbolic links that are to be taken relative (sic!) to a
particular root path. A good example is accessing paths inside
`/proc/[PID]/root` "wormholes" in the [proc file
system](https://man7.org/linux/man-pages/man5/proc.5.html). Symbolic links are
properly resolved and kept inside a given root path, prohibiting rogue relative
symbolic links from breaking out of a procfs root wormhole.

For devcontainer instructions, please see the [section "DevContainer"
below](#devcontainer).

## Usage

`procfsroot.EvalSymlinks()` mirrors Golang's
[`filepath.EvalSymlinks`](https://golang.org/pkg/path/filepath/#EvalSymlinks),
but works only on paths using "`/`" forward slashes and enforces symbolic link
chasing relative to an enforced root path.

In the following example, the "absolute" path `/var/run/docker.sock` (which
might be in a different mount namespace) is correctly resolved in the root
context of `/proc/1/root` – even in case of absolute symbolic links, such as
`/var/run` usually being an absolute symlink pointing to `/run`. Trying to
directly use `/proc/1/root/var/run/docker.sock` will fail in case of different
mount namespaces between the accessing process and the initial mount namespace
of the init process PID 1, as this would be resolved by the Linux kernel into
`/run/docker.sock` in the current mount namespace(*).

```go
import (
    "os"
    "github.com/thediveo/procfsroot"
)

const root := "/proc/1/root"

func main() {
    p, err := procfsroot.EvalSymlinks("/var/run/docker.sock", root, procfsroot.EvalFullPath)
    if err != nil {
        panic(err)
    }
    f, err := os.Open(root + p)
    defer f.Close()
}
```

For illustrational purposes, simply run this as an "incontinentainer" to show
that absolute symbolic path access will fail when done through a wormhole:

```bash
$ docker run -it --rm --pid=host --privileged busybox ls -l /proc/1/root/var/run/docker.socket
ls: /proc/1/root/var/run/docker.socket: No such file or directory
```

## Mount Namespace Wormholes

In case you have either never noticed the special `/proc/[PID]/root` links or
have ever wondered what they're good for: they're kind of "wormholes" into
arbitrary [mount
namespaces](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html) given
a suitable process ID (PID). They simplify accessing directories and files in
other mount namespaces because they do not require switching the accessing
process first into the target mount namespace (which can only be done while
single threaded).

| Access Method | Required Capabilites |
| :--- | :--- |
| `setns()` | `CAP_SYS_ADMIN`, `CAP_SYS_CHROOT`, as well as typically also `CAP_SYS_PTRACE` in order to access a mount namespace reference in `/proc/[PID]/ns/mnt`</li></ul> |
| `/proc/[PID]/root` | `CAP_SYS_PTRACE` (so convenient 😀) |

Of course, the usual file system DAC (discretionary access control) still
applies as usual – including UID 0 access rules.

Also, for access to `/proc/[PID]` the current process needs to be in a suitable
[PID namespace](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
that includes the PID of a "target" process of interest. Of course, the initial
PID namespace is "gold standard".

## DevContainer

> [!CAUTION]
>
> Do **not** use VSCode's "~~Dev Containers: Clone Repository in Container
> Volume~~" command, as it is utterly broken by design, ignoring
> `.devcontainer/devcontainer.json`.

1. `git clone https://github.com/thediveo/procfsroot`
2. in VSCode: Ctrl+Shift+P, "Dev Containers: Open Workspace in Container..."
3. select `procfsroot.code-workspace` and off you go...

## Supported Go Versions

`procfsroot` supports versions of Go that are noted by the [Go release
policy](https://golang.org/doc/devel/release.html#policy), that is, major
versions _N_ and _N_-1 (where _N_ is the current major version).

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md).

## Copyright and License

Copyright 2021, 2026 Harald Albrecht, licensed under the Apache License, Version 2.0.
