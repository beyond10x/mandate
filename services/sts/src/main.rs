use clap::Parser;

/// Mandate foundation scaffold; runtime capabilities are not implemented.
#[derive(Parser)]
#[command(name = "mandate-sts", version, arg_required_else_help = true)]
struct Args {}

fn main() {
    let _ = Args::parse();
}
