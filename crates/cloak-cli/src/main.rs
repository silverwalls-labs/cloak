use std::io::{self, BufWriter, Read, Write};

use anyhow::Context;
use clap::Parser;

/// Default read buffer size (64 KiB), per docs/04-performance.md.
const READ_BUF_SIZE: usize = 64 * 1024;

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

    let mut buf = vec![0u8; READ_BUF_SIZE];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        session.push(&buf[..n], &mut out)?;
    }

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
