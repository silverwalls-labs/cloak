// Test-only exports: compiled into the cloak package for test builds
// so the external cloak_test package can reach internals without
// widening the public API.

package cloak

// WasmPathForTest exposes the bridge's artifact resolution so tests
// reuse it instead of duplicating the CLOAK_WASM_PATH + repo-relative
// fallback (which would drift).
func WasmPathForTest() string { return wasmPath() }
