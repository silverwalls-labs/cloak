//go:build cloak_ffi_system

// System linkage (build tag `cloak_ffi_system`): link -lcloak_ffi from
// the system/toolchain search path instead of the repo-relative static
// archive. Point the build at your install:
//
//	CGO_LDFLAGS="-L/path/to/lib" go build -tags cloak_ffi_system ./...
//
// If the resolved library is the shared one (libcloak_ffi.so/.dylib),
// the usual runtime path rules apply (LD_LIBRARY_PATH / rpath /
// install_name) — prefer the static archive unless you have a reason
// not to.

package cloak

/*
#cgo LDFLAGS: -lcloak_ffi
#cgo linux LDFLAGS: -lm -ldl -lpthread
*/
import "C"
