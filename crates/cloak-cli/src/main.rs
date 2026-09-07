use std::io::{self, BufWriter, Read, Write};

use anyhow::Context;
use clap::Parser;

/// Redact secrets and PII from streams.
#[derive(Parser)]
#[command(name = "cloak", version, about)]
struct Cli {
    // S1: no flags. S5 adds --config, --stats-format, file args.
}

fn run() -> anyhow::Result<()> {
    let _cli = Cli::parse();

    let config = cloak_core::Config::default();
    let engine = cloak_core::Engine::new(&config).context("failed to build engine")?;
    let mut session = engine.session();

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut out = BufWriter::new(stdout.lock());

    // S2: slurp the whole stream and scan it as one buffer — Session::push
    // treats each chunk as self-contained until S3 lands bounded carry-over.
    // S3 restores 64 KiB streaming reads (docs/04-performance.md).
    let mut input = Vec::new();
    reader
        .read_to_end(&mut input)
        .context("failed to read stdin")?;
    session.push(&input, &mut out)?;

    let _stats = session.finish(&mut out)?;
    out.flush()?;

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        // Walk the full error chain — a .context() wrapper must not break
        // SIGPIPE handling.
        let is_broken_pipe = e.chain().any(|cause| {
            cause
                .downcast_ref::<io::Error>()
                .is_some_and(|io_err| io_err.kind() == io::ErrorKind::BrokenPipe)
        });
        if is_broken_pipe {
            std::process::exit(0);
        }
        eprintln!("cloak: {e:#}");
        std::process::exit(1);
    }
}
