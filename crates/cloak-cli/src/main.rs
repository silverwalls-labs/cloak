use std::io::{self, BufWriter, Read, Write};
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;

/// Redact secrets and PII from streams.
#[derive(Parser)]
#[command(name = "cloak", version, about)]
struct Cli {
    /// Path to a TOML configuration file.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Emit per-rule match statistics to stderr.
    #[arg(long, value_name = "FORMAT")]
    stats_format: Option<StatsFormat>,

    /// Input files. If omitted, reads stdin.
    files: Vec<PathBuf>,
}

/// Output format for end-of-stream statistics.
#[derive(Clone, Debug, clap::ValueEnum)]
enum StatsFormat {
    Text,
    Json,
}

fn load_config(cli: &Cli) -> anyhow::Result<cloak_core::Config> {
    match &cli.config {
        Some(path) => {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read config file: {}", path.display()))?;
            cloak_core::Config::from_toml(&content)
                .with_context(|| format!("failed to parse config file: {}", path.display()))
        }
        None => Ok(cloak_core::Config::default()),
    }
}

fn emit_stats(stats: &cloak_core::Stats, format: &StatsFormat) -> anyhow::Result<()> {
    let stderr = io::stderr();
    let mut err = stderr.lock();
    match format {
        StatsFormat::Json => {
            serde_json::to_writer(&mut err, stats).context("failed to write stats")?;
            writeln!(err)?;
        }
        StatsFormat::Text => {
            writeln!(err, "bytes_processed: {}", stats.bytes_processed)?;
            writeln!(err, "total_matches: {}", stats.total_matches())?;
            if !stats.matches.is_empty() {
                writeln!(err, "per_rule:")?;
                for (rule, count) in &stats.matches {
                    writeln!(err, "  {rule}: {count}")?;
                }
            }
        }
    }
    Ok(())
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = load_config(&cli)?;
    let engine = cloak_core::Engine::new(&config).context("failed to build engine")?;
    let mut session = engine.session();

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    // S3: 64 KiB streaming reads — bounded carry-over makes chunk
    // boundaries invisible (docs/03-guarantee-and-testing.md).
    let mut buf = [0u8; 64 * 1024];

    if cli.files.is_empty() {
        // Stdin mode.
        let stdin = io::stdin();
        let mut reader = stdin.lock();
        loop {
            let n = reader.read(&mut buf).context("failed to read stdin")?;
            if n == 0 {
                break;
            }
            session.push(&buf[..n], &mut out)?;
        }
    } else {
        // File args mode: concatenate through one session.
        for path in &cli.files {
            let file = std::fs::File::open(path)
                .with_context(|| format!("failed to open: {}", path.display()))?;
            let mut reader = io::BufReader::new(file);
            loop {
                let n = reader
                    .read(&mut buf)
                    .with_context(|| format!("failed to read: {}", path.display()))?;
                if n == 0 {
                    break;
                }
                session.push(&buf[..n], &mut out)?;
            }
        }
    }

    let stats = session.finish(&mut out)?;
    out.flush()?;

    // Stats to stderr — after stdout is flushed so the redacted payload
    // is complete even if the process is killed between flush and stats.
    if let Some(format) = &cli.stats_format {
        emit_stats(&stats, format)?;
    }

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
