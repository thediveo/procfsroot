package wormholes

import (
	"io/fs"
	"os"
	"path"
	"strconv"

	"github.com/thediveo/procfsroot"
)

// FS provides a wormhole fs.FS that leverages the Linux procfs (process
// filesystem) to carry out VFS operations from the perspective of a
// (potentially different) process.
//
// This wormhole FS confines all access to within the view of the process with a
// particular PID. This includes malicious relative symlinks that are blocked.
// Absolute symlinks are also resolved within that process's view.
//
// Nevertheless, this is FS is not designed to be a bullet-proof FS, but instead
// to support diagnosis tools as best as possible while preventing shooting
// one's own feet.
type FS struct {
	procfsRoot string
	pid        int // just for convenience
}

var (
	_ fs.FS         = (*FS)(nil)
	_ fs.StatFS     = (*FS)(nil)
	_ fs.ReadLinkFS = (*FS)(nil)
	_ fs.ReadFileFS = (*FS)(nil)
	_ fs.ReadDirFS  = (*FS)(nil)
	_ fs.SubFS      = (*FS)(nil)
)

// New returns a new Wormholer filesystem that provides the VFS view as seen by
// the process with the specified PID.
//
// Please note that New does not check if the process with the specified PID
// exists or that the caller has sufficient capabilities to carry out filesystem
// operations through a /proc/[PID]/root wormhole.
func New(pid int) *FS {
	return &FS{
		procfsRoot: "/proc/" + strconv.Itoa(pid) + "/root",
		pid:        pid,
	}
}

// PID returns the PID of the process into which this wormhole FS opens a VFS
// window.
func (w *FS) PID() int { return w.pid }

// Sub returns an FS corresponding to the subtree rooted at dir.
func (w *FS) Sub(dir string) (fs.FS, error) {
	if !fs.ValidPath(dir) {
		return nil, &fs.PathError{Op: "sub", Path: dir, Err: fs.ErrInvalid}
	}
	if dir == "." {
		return w, nil
	}
	return &FS{
		procfsRoot: path.Join(w.procfsRoot, dir),
		pid:        w.pid,
	}, nil
}

// Open opens the named file. [fs.File.Close] must be called to release any
// associated resources.
//
// Names that do not satisfy [fs.ValidPath] return a *[fs.PathError] with Err
// set to [fs.ErrInvalid] or [fs.ErrNotExist].
//
// On error, Open returns a *[fs.PathError] with its Op field set to "open", the
// Path field set to name, and the Err field describing the problem.
func (w *FS) Open(name string) (fs.File, error) {
	name, err := w.evilSymlinks(name, procfsroot.EvalFullPath, "open")
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path.Join(w.procfsRoot, name))
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	return f, nil
}

// Stat returns a fs.FileInfo describing the file. Otherwise, it returns a
// *[fs.PathError] with its Op field set to "stat", the Path field set to name,
// and the Err field describing the problem.
func (w *FS) Stat(name string) (fs.FileInfo, error) {
	name, err := w.evilSymlinks(name, procfsroot.EvalFullPath, "stat")
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path.Join(w.procfsRoot, name))
	if err != nil {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: err}
	}
	return info, nil
}

// ReadLink returns the destination of the named symbolic link. Otherwise, it
// returns a *[fs.PathError] with its Op field set to "readlink", the Path field
// set to name, and the Err field describing the problem.
func (w *FS) ReadLink(name string) (string, error) {
	name, err := w.evilSymlinks(name, procfsroot.EvalExceptLast, "readlink")
	if err != nil {
		return "", err
	}
	dest, err := os.Readlink(path.Join(w.procfsRoot, name))
	if err != nil {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: err}
	}
	return dest, nil
}

// Lstat returns a [fs.FileInfo] describing the named file. If the file is a
// symbolic link, the returned [fs.FileInfo] describes the symbolic link. Lstat
// makes no attempt to follow the link. Otherwise, it returns a *[fs.PathError]
// with its Op field set to "lstat", the Path field set to name, and the Err
// field describing the problem.
func (w *FS) Lstat(name string) (fs.FileInfo, error) {
	name, err := w.evilSymlinks(name, procfsroot.EvalExceptLast, "lstat")
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path.Join(w.procfsRoot, name))
	if err != nil {
		return nil, &fs.PathError{Op: "lstat", Path: name, Err: err}
	}
	return info, nil
}

// ReadFile reads the named file and returns its contents. A successful call
// returns a nil error, not io.EOF. (Because ReadFile reads the whole file, the
// expected EOF from the final Read is not treated as an error to be reported.)
//
// The caller is permitted to modify the returned byte slice. This method should
// return a copy of the underlying data.
func (w *FS) ReadFile(name string) ([]byte, error) {
	name, err := w.evilSymlinks(name, procfsroot.EvalExceptLast, "readfile")
	if err != nil {
		return nil, err
	}
	contents, err := os.ReadFile(path.Join(w.procfsRoot, name))
	if err != nil {
		return nil, &fs.PathError{Op: "readfile", Path: name, Err: err}
	}
	return contents, nil
}

// ReadDir reads the named directory and returns a list of directory entries
// sorted by filename.
func (w *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	name, err := w.evilSymlinks(name, procfsroot.EvalExceptLast, "readdir")
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(path.Join(w.procfsRoot, name))
	if err != nil {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
	}
	return entries, nil
}

// evilSymlinks returns the absolute path (still relative to the FS's
// procfsRoot) after evaluating any symbolic links in the specified name, where
// these are always confined and taken relative to the FS's procfsRoot.
func (w *FS) evilSymlinks(name string, pathhandling procfsroot.EvalSymlinkPathHandling, operation string) (string, error) {
	if !fs.ValidPath(name) {
		return "", &fs.PathError{Op: operation, Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		name = "/"
	} else {
		name = "/" + name
	}
	path, err := procfsroot.EvalSymlinks(name, w.procfsRoot, pathhandling)
	if err != nil {
		return "", &fs.PathError{Op: operation, Path: name, Err: err}
	}
	return path, nil
}
