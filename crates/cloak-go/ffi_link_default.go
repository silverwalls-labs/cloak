//go:build !cloak_ffi_system

// Default linkage: the cloak-ffi static archive from a repo checkout,
// by explicit path (never `-L dir -lcloak_ffi` — the linker would
// prefer the .dylib/.so that cargo emits next to the .a, reintroducing
// runtime library-path pain). Build it first:
//
//	cargo build -p cloak-ffi --release
//
// Out-of-tree consumers either `replace` this module to a checkout, or
// build with `-tags cloak_ffi_system` and point CGO_LDFLAGS at an
// installed library (see ffi_link_system.go).
//
// The Linux-only trailing libs are what the Rust standard library
// inside the archive needs; macOS gets them from libSystem implicitly.

package cloak

/*
#cgo LDFLAGS: ${SRCDIR}/../../target/release/libcloak_ffi.a
#cgo linux LDFLAGS: -lm -ldl -lpthread
*/
import "C"
