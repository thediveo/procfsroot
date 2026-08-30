/*
Package wormholes provides a fs.FS that is bound to a specific process PID and
operates on the VFS as seen by that process. It correctly handles absolute and
relative symlinks within its view. It blocks malicious or accidentally broken
symlink escapes. Yet it isn't completely bullet-proof.

Differing from [io.Root] this FS implementation supports absolute symlinks,
which is a must in some (especially near-system) scenarios.
*/
package wormholes
