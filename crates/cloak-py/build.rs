fn main() {
    // On macOS, extension modules must link with `-undefined
    // dynamic_lookup` (Python symbols are provided by the interpreter at
    // import time). maturin passes this itself; this keeps plain
    // workspace builds (clippy, `cargo build --workspace` in CI) linking
    // without a libpython.
    pyo3_build_config::add_extension_module_link_args();
}
