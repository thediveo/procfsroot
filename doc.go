/*
Package procfsroot helps with accessing file system paths containing absolute
symbolic links that are to be taken relative (sic!) to a particular root path.

A typical use case is accessing paths inside /proc/[PID]/root "wormholes" in the
proc file system. Using [EvalSymlinks], symbolic links are properly resolved and
kept inside a given root path, prohibiting rogue relative symbolic links from
breaking out of, for example, a procfs /proc/[PID]/root "wormhole".

Less DIY-afine developers might be interested in
[github.com/thediveo/procfsroot/wormholes.FS] which is a [fs.FS] implementation
that leverages [EvalSymlinks].
*/
package procfsroot
