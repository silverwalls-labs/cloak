//! `fuzz_config` (docs/03 §4): arbitrary TOML → parser never panics,
//! errors are typed.
//!
//! Drives the full build pipeline: `Config::from_toml` → `validate` →
//! `Engine::new`. Every failure must be a typed `BuildError` with a
//! non-empty `Display`; a valid config must never panic engine
//! construction. Run with `-close_fd_mask=3`: configs that resolve to an
//! ephemeral digest key print a stderr warning on every iteration.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // TOML is text by definition; non-UTF-8 input can't reach the parser
    // through any real entry point (the CLI reads config via fs::read_to_string).
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    match cloak_core::Config::from_toml(s) {
        Err(e) => assert!(!e.to_string().is_empty(), "untyped parse error"),
        Ok(config) => match config.validate() {
            Err(e) => assert!(!e.to_string().is_empty(), "untyped validation error"),
            Ok(()) => match cloak_core::Engine::new(&config) {
                Ok(_engine) => {}
                Err(e) => assert!(!e.to_string().is_empty(), "untyped build error"),
            },
        },
    }
});
