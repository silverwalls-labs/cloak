// Low-level cgo bridge to the cloak-ffi C ABI.
//
// Mirrors the role of bridge.go in the WASM adapter — all cgo and
// unsafe pointer juggling is confined to this file (plus the two
// build-tag-gated link-flag files); the rest of the package works with
// []byte values and the ffiEngine/ffiSession wrappers.
//
// Not part of the public API — use CreateEngine instead.

package cloak

/*
#cgo CFLAGS: -I${SRCDIR}/include
#include <cloak.h>
*/
import "C"

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unsafe"
)

// ── Error type ─────────────────────────────────────────────────────

// CloakError is the error type for every failure surfaced by this
// package (invalid config, consumed sessions, FFI-side errors).
type CloakError struct {
	msg string
}

func (e *CloakError) Error() string { return e.msg }

func cloakErrorf(format string, args ...any) *CloakError {
	return &CloakError{msg: fmt.Sprintf(format, args...)}
}

// ── ABI version guard ──────────────────────────────────────────────

// abiVersionError returns nil when the linked library matches the
// vendored header, and a descriptive error otherwise (a stale
// target/release archive is the usual culprit).
func abiVersionError() error {
	if v := C.cloak_abi_version(); v != C.CLOAK_ABI_VERSION {
		return cloakErrorf(
			"cloak-ffi ABI mismatch: library reports version %d, header expects %d — "+
				"rebuild the library: cargo build -p cloak-ffi --release",
			uint32(v), uint32(C.CLOAK_ABI_VERSION))
	}
	return nil
}

// ── Byte crossing helpers ───────────────────────────────────────────

// cPtr returns a C pointer to b's first byte, or nil for empty/nil
// slices (the ABI documents (NULL, 0) as the valid empty pair). cgo
// pins the Go allocation for the duration of the call, and cloak-ffi
// only borrows inputs — no copy in.
func cPtr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

// goBytes copies a CloakBuf into Go memory and frees it. Empty buffers
// return nil (matching the WASM adapter's nil-for-empty convention).
// bytes.Clone — not C.GoBytes — because GoBytes takes a C.int and
// would truncate >2 GiB buffers.
func goBytes(buf C.CloakBuf) []byte {
	if buf.len == 0 {
		return nil
	}
	data := bytes.Clone(unsafe.Slice((*byte)(unsafe.Pointer(buf.ptr)), buf.len))
	C.cloak_buf_free(buf)
	return data
}

// takeErr reads an error CloakBuf as a string and frees it.
func takeErr(buf C.CloakBuf) string {
	if buf.len == 0 {
		return "(no error message)"
	}
	msg := string(unsafe.Slice((*byte)(unsafe.Pointer(buf.ptr)), buf.len))
	C.cloak_buf_free(buf)
	return msg
}

// parseStats decodes the stats JSON the ABI returns (same shape as
// cloak-wasm: bytes_processed, matches, near_misses omitted when
// empty — the omission is what keeps Stats.NearMisses nil).
func parseStats(jsonBytes []byte) (Stats, error) {
	stats := Stats{Matches: map[string]int{}}
	if len(jsonBytes) == 0 {
		// Unreachable: every finish/redact below requests stats.
		return stats, nil
	}
	if err := json.Unmarshal(jsonBytes, &stats); err != nil {
		return Stats{}, cloakErrorf("stats: invalid JSON from cloak-ffi: %v", err)
	}
	if stats.Matches == nil {
		stats.Matches = map[string]int{}
	}
	return stats, nil
}

// ── Engine ops ──────────────────────────────────────────────────────

// ffiEngine wraps the opaque C engine pointer so every other file in
// the package stays cgo-free.
type ffiEngine struct {
	ptr *C.CloakEngine
}

func ffiEngineNew(configTOML string) (*ffiEngine, error) {
	cfg := []byte(configTOML)
	var errBuf C.CloakBuf
	ptr := C.cloak_engine_new(cPtr(cfg), C.size_t(len(cfg)), &errBuf)
	if ptr == nil {
		return nil, cloakErrorf("engine_new: %s", takeErr(errBuf))
	}
	return &ffiEngine{ptr: ptr}, nil
}

// free releases the engine. The ABI refuses — engine still valid,
// retryable — while sessions are live or scans are in flight.
func (e *ffiEngine) free() error {
	var errBuf C.CloakBuf
	if C.cloak_engine_free(e.ptr, &errBuf) != C.CLOAK_OK {
		return cloakErrorf("engine_free: %s", takeErr(errBuf))
	}
	e.ptr = nil
	return nil
}

// redact is the one-shot scan: output bytes + stats in one C call.
func (e *ffiEngine) redact(input []byte) ([]byte, Stats, error) {
	var out, statsBuf, errBuf C.CloakBuf
	rc := C.cloak_redact(e.ptr, cPtr(input), C.size_t(len(input)), &out, &statsBuf, &errBuf)
	if rc != C.CLOAK_OK {
		return nil, Stats{}, cloakErrorf("redact: %s", takeErr(errBuf))
	}
	output := goBytes(out)
	stats, err := parseStats(goBytes(statsBuf))
	if err != nil {
		return nil, Stats{}, err
	}
	return output, stats, nil
}

func (e *ffiEngine) sessionNew() (*ffiSession, error) {
	var errBuf C.CloakBuf
	ptr := C.cloak_session_new(e.ptr, &errBuf)
	if ptr == nil {
		return nil, cloakErrorf("session_new: %s", takeErr(errBuf))
	}
	return &ffiSession{ptr: ptr}, nil
}

// ── Session ops ─────────────────────────────────────────────────────

// ffiSession wraps the opaque C session pointer. The session holds a
// strong reference to its engine on the Rust side, so the engine's
// memory outlives it even if Close is misused.
type ffiSession struct {
	ptr *C.CloakSession
}

func (s *ffiSession) push(input []byte) ([]byte, error) {
	var out, errBuf C.CloakBuf
	rc := C.cloak_session_push(s.ptr, cPtr(input), C.size_t(len(input)), &out, &errBuf)
	if rc != C.CLOAK_OK {
		return nil, cloakErrorf("push: %s", takeErr(errBuf))
	}
	return goBytes(out), nil
}

// finish flushes the carry-over and collects stats. The ABI consumes
// the scanning state either way; the pointer itself is released
// separately by free.
func (s *ffiSession) finish() ([]byte, Stats, error) {
	var out, statsBuf, errBuf C.CloakBuf
	rc := C.cloak_session_finish(s.ptr, &out, &statsBuf, &errBuf)
	if rc != C.CLOAK_OK {
		return nil, Stats{}, cloakErrorf("finish: %s", takeErr(errBuf))
	}
	output := goBytes(out)
	stats, err := parseStats(goBytes(statsBuf))
	if err != nil {
		return nil, Stats{}, err
	}
	return output, stats, nil
}

// free releases the C session object (the abort path, and the required
// final release after finish), lifting the engine pin it holds.
// Idempotent at this layer via the nil reset.
func (s *ffiSession) free() {
	if s.ptr == nil {
		return
	}
	C.cloak_session_free(s.ptr)
	s.ptr = nil
}
