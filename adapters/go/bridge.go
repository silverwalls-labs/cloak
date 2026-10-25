// Low-level bridge to the `cloak-wasm` linear-memory ABI.
//
// Mirrors the `WasmCloak` helper in `crates/wasm-parity/tests/parity.rs`
// and the Node/Python bridges — same protocol, Go idioms. All
// pointer/handle juggling is confined here; the rest of the adapter
// works with []byte values.
//
// Not part of the public API — use CreateEngine instead.

package cloak

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// ── Error type ─────────────────────────────────────────────────────

// CloakError is the error type for every failure surfaced by this
// adapter (invalid config, consumed sessions, WASM-side errors).
type CloakError struct {
	msg string
}

func (e *CloakError) Error() string { return e.msg }

func cloakErrorf(format string, args ...any) *CloakError {
	return &CloakError{msg: fmt.Sprintf(format, args...)}
}

// ── Artifact resolution ────────────────────────────────────────────

// wasmPath resolves the `.wasm` artifact path.
//
// Priority: `CLOAK_WASM_PATH` env var, then the standard cargo release
// output relative to this source file's location in the repo. The
// fallback works for `go test` / `go run` from the source tree — a
// consumer binary built elsewhere supplies the artifact via
// `CLOAK_WASM_PATH` or WithWASM.
func wasmPath() string {
	if p := os.Getenv("CLOAK_WASM_PATH"); p != "" {
		return p
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..",
		"target", "wasm32-wasip1", "release", "cloak_wasm.wasm")
}

func loadWasmBytes() ([]byte, error) {
	path := wasmPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, cloakErrorf(
			"cloak_wasm.wasm not found at %q — build it with:\n"+
				"  RUSTFLAGS=\"-Ctarget-feature=+simd128\" cargo build -p cloak-wasm --target wasm32-wasip1 --release\n"+
				"or point CLOAK_WASM_PATH at the artifact", path)
	}
	return data, nil
}

// hostEnv snapshots the process environment as a map — the default
// WASM env, mirroring the Node/Python bridges.
func hostEnv() map[string]string {
	environ := os.Environ()
	env := make(map[string]string, len(environ))
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	return env
}

// ── Bridge ─────────────────────────────────────────────────────────

// bridge drives the cloak-wasm C ABI over a wazero runtime.
//
// Not safe for concurrent use: the WASM module keeps take-once
// error/stats slots, so callers must serialize access — the public
// Engine wraps every operation (its sessions' included) in one mutex.
type bridge struct {
	ctx context.Context
	rt  wazero.Runtime
	mem api.Memory

	fnAlloc       api.Function
	fnDealloc     api.Function
	fnEngineNew   api.Function
	fnEngineFree  api.Function
	fnSessionNew  api.Function
	fnSessionFree api.Function
	fnPush        api.Function
	fnFinish      api.Function
	fnFinishStats api.Function
	fnRedact      api.Function
	fnBufFree     api.Function
	fnLastError   api.Function
}

// newBridge compiles and instantiates the WASM module as a WASI p1
// reactor (no `_start`; `_initialize` is called iff exported).
//
// env is the environment visible to the WASM module — the digest key
// is resolved from here via `digest_key = "env:CLOAK_DIGEST_KEY"` in
// the config. nil inherits the host process environment.
func newBridge(ctx context.Context, wasmBytes []byte, env map[string]string) (b *bridge, err error) {
	rt := wazero.NewRuntime(ctx)
	defer func() {
		if err != nil {
			_ = rt.Close(ctx)
		}
	}()

	if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
		return nil, cloakErrorf("WASI instantiation failed: %v", err)
	}

	compiled, err := rt.CompileModule(ctx, wasmBytes)
	if err != nil {
		return nil, cloakErrorf("WASM compile failed: %v", err)
	}

	// Reactor module: never run `_start`. Route the module's stderr to
	// the host's (panic messages land somewhere visible, matching the
	// Python bridge's inherit_stderr), and give `random_get` a real
	// CSPRNG — wazero's default source is deterministic, and the module
	// draws its ephemeral digest key from it when none is configured.
	cfg := wazero.NewModuleConfig().
		WithStartFunctions().
		WithStderr(os.Stderr).
		WithRandSource(rand.Reader)

	if env == nil {
		env = hostEnv()
	}
	for _, k := range slices.Sorted(maps.Keys(env)) {
		cfg = cfg.WithEnv(k, env[k])
	}

	mod, err := rt.InstantiateModule(ctx, compiled, cfg)
	if err != nil {
		return nil, cloakErrorf("WASM instantiation failed: %v", err)
	}

	// WASI reactor init — the current artifact does not export
	// `_initialize`, but call it when present (same forward-compat
	// probe as the Python bridge).
	if initFn := mod.ExportedFunction("_initialize"); initFn != nil {
		if _, err := initFn.Call(ctx); err != nil {
			return nil, cloakErrorf("_initialize failed: %v", err)
		}
	}

	b = &bridge{ctx: ctx, rt: rt, mem: mod.Memory()}
	var missing []string
	lookup := func(name string) api.Function {
		fn := mod.ExportedFunction(name)
		if fn == nil {
			missing = append(missing, name)
		}
		return fn
	}
	b.fnAlloc = lookup("cloakwasm_alloc")
	b.fnDealloc = lookup("cloakwasm_dealloc")
	b.fnEngineNew = lookup("cloakwasm_engine_new")
	b.fnEngineFree = lookup("cloakwasm_engine_free")
	b.fnSessionNew = lookup("cloakwasm_session_new")
	b.fnSessionFree = lookup("cloakwasm_session_free")
	b.fnPush = lookup("cloakwasm_push")
	b.fnFinish = lookup("cloakwasm_finish")
	b.fnFinishStats = lookup("cloakwasm_finish_stats")
	b.fnRedact = lookup("cloakwasm_redact")
	b.fnBufFree = lookup("cloakwasm_buf_free")
	b.fnLastError = lookup("cloakwasm_last_error")
	if b.mem == nil {
		missing = append(missing, "memory")
	}
	if len(missing) > 0 {
		return nil, cloakErrorf("artifact is missing exports: %s", strings.Join(missing, ", "))
	}
	return b, nil
}

func (b *bridge) close() error {
	if err := b.rt.Close(b.ctx); err != nil {
		return cloakErrorf("wasm runtime close failed: %v", err)
	}
	return nil
}

// ── Linear memory helpers ──────────────────────────────────────────

// call invokes a cached export and narrows the result to the ABI's
// u32. Traps (module panic/abort) and closed-runtime failures surface
// as errors — no panic crosses the boundary.
func (b *bridge) call(fn api.Function, op string, params ...uint64) (uint32, error) {
	results, err := fn.Call(b.ctx, params...)
	if err != nil {
		return 0, cloakErrorf("%s: wasm call failed: %v", op, err)
	}
	if len(results) == 0 {
		return 0, nil
	}
	return uint32(results[0]), nil
}

// writeBytes allocates + copies bytes into WASM linear memory.
// Returns (ptr, allocSize) — always allocates at least 1 byte so the
// paired dealloc size is never 0 (alloc(0) returns null). ABI calls
// take the *actual* data length, not allocSize.
func (b *bridge) writeBytes(data []byte) (ptr, allocSize uint32, err error) {
	if uint64(len(data)) > math.MaxUint32 {
		return 0, 0, cloakErrorf("input too large for the WASM ABI: %d bytes", len(data))
	}
	allocSize = uint32(len(data))
	if allocSize == 0 {
		allocSize = 1
	}
	ptr, err = b.call(b.fnAlloc, "alloc", uint64(allocSize))
	if err != nil {
		return 0, 0, err
	}
	if ptr == 0 {
		return 0, 0, cloakErrorf("WASM alloc failed for %d bytes", allocSize)
	}
	if len(data) > 0 && !b.mem.Write(ptr, data) {
		b.dealloc(ptr, allocSize)
		return 0, 0, cloakErrorf("WASM memory write out of range (ptr=%d len=%d)", ptr, len(data))
	}
	return ptr, allocSize, nil
}

// readBufResult copies a `BufResult { ptr: u32, len: u32 }` payload
// out of linear memory. The copy happens before any further WASM call
// — wazero's Memory.Read returns a view into live memory, which the
// next call may grow (and therefore move).
func (b *bridge) readBufResult(resultPtr uint32) ([]byte, error) {
	dataPtr, okPtr := b.mem.ReadUint32Le(resultPtr)
	dataLen, okLen := b.mem.ReadUint32Le(resultPtr + 4)
	if !okPtr || !okLen {
		return nil, cloakErrorf("BufResult read out of range (ptr=%d)", resultPtr)
	}
	if dataLen == 0 {
		return nil, nil
	}
	view, ok := b.mem.Read(dataPtr, dataLen)
	if !ok {
		return nil, cloakErrorf("BufResult data read out of range (ptr=%d len=%d)", dataPtr, dataLen)
	}
	out := make([]byte, dataLen)
	copy(out, view)
	return out, nil
}

// bufFree frees a BufResult and its data buffer. Null-safe.
func (b *bridge) bufFree(resultPtr uint32) {
	if resultPtr == 0 {
		return
	}
	_, _ = b.call(b.fnBufFree, "buf_free", uint64(resultPtr))
}

// dealloc frees a region previously returned by writeBytes.
func (b *bridge) dealloc(ptr, size uint32) {
	_, _ = b.call(b.fnDealloc, "dealloc", uint64(ptr), uint64(size))
}

// ── Error retrieval ────────────────────────────────────────────────

// lastErrorMsg reads and consumes the module's take-once error slot.
func (b *bridge) lastErrorMsg() string {
	ptr, err := b.call(b.fnLastError, "last_error")
	if err != nil || ptr == 0 {
		return ""
	}
	data, err := b.readBufResult(ptr)
	b.bufFree(ptr)
	if err != nil {
		return ""
	}
	return string(data)
}

// wasmError builds the error for a WASM function that signaled
// failure via a null/zero return.
func (b *bridge) wasmError(op string) error {
	if msg := b.lastErrorMsg(); msg != "" {
		return cloakErrorf("%s: %s", op, msg)
	}
	return cloakErrorf("%s (no error message)", op)
}

// ── Engine lifecycle ───────────────────────────────────────────────

func (b *bridge) engineNew(configTOML string) (uint32, error) {
	data := []byte(configTOML)
	ptr, allocSize, err := b.writeBytes(data)
	if err != nil {
		return 0, err
	}
	handle, err := b.call(b.fnEngineNew, "engine_new", uint64(ptr), uint64(len(data)))
	b.dealloc(ptr, allocSize)
	if err != nil {
		return 0, err
	}
	if handle == 0 {
		return 0, b.wasmError("engine_new")
	}
	return handle, nil
}

func (b *bridge) engineFree(handle uint32) error {
	rc, err := b.call(b.fnEngineFree, "engine_free", uint64(handle))
	if err != nil {
		return err
	}
	if rc == 0 {
		return b.wasmError("engine_free")
	}
	return nil
}

// ── Session lifecycle ──────────────────────────────────────────────

func (b *bridge) sessionNew(engineHandle uint32) (uint32, error) {
	handle, err := b.call(b.fnSessionNew, "session_new", uint64(engineHandle))
	if err != nil {
		return 0, err
	}
	if handle == 0 {
		return 0, b.wasmError("session_new")
	}
	return handle, nil
}

func (b *bridge) sessionFree(handle uint32) error {
	rc, err := b.call(b.fnSessionFree, "session_free", uint64(handle))
	if err != nil {
		return err
	}
	if rc == 0 {
		return b.wasmError("session_free")
	}
	return nil
}

// bufCall runs an ABI function returning a *BufResult and copies the
// payload out.
func (b *bridge) bufCall(fn api.Function, op string, params ...uint64) ([]byte, error) {
	resultPtr, err := b.call(fn, op, params...)
	if err != nil {
		return nil, err
	}
	if resultPtr == 0 {
		return nil, b.wasmError(op)
	}
	data, err := b.readBufResult(resultPtr)
	b.bufFree(resultPtr)
	return data, err
}

func (b *bridge) push(sessionHandle uint32, input []byte) ([]byte, error) {
	ptr, allocSize, err := b.writeBytes(input)
	if err != nil {
		return nil, err
	}
	data, err := b.bufCall(b.fnPush, "push",
		uint64(sessionHandle), uint64(ptr), uint64(len(input)))
	b.dealloc(ptr, allocSize)
	return data, err
}

func (b *bridge) finish(sessionHandle uint32) ([]byte, error) {
	return b.bufCall(b.fnFinish, "finish", uint64(sessionHandle))
}

func (b *bridge) redact(engineHandle uint32, input []byte) ([]byte, error) {
	ptr, allocSize, err := b.writeBytes(input)
	if err != nil {
		return nil, err
	}
	data, err := b.bufCall(b.fnRedact, "redact",
		uint64(engineHandle), uint64(ptr), uint64(len(input)))
	b.dealloc(ptr, allocSize)
	return data, err
}

// finishStats reads and consumes the take-once stats slot stashed by
// the previous finish/redact. Returns zero stats when none are
// available (mirrors the Node/Python fallback).
func (b *bridge) finishStats() (Stats, error) {
	resultPtr, err := b.call(b.fnFinishStats, "finish_stats")
	if err != nil {
		return Stats{}, err
	}
	stats := Stats{Matches: map[string]int{}}
	if resultPtr == 0 {
		return stats, nil
	}
	data, err := b.readBufResult(resultPtr)
	b.bufFree(resultPtr)
	if err != nil {
		return Stats{}, err
	}
	if err := json.Unmarshal(data, &stats); err != nil {
		return Stats{}, cloakErrorf("finish_stats: invalid stats JSON: %v", err)
	}
	if stats.Matches == nil {
		stats.Matches = map[string]int{}
	}
	return stats, nil
}
