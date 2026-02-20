//! CLI argument definitions for agentchain-node.

use sc_cli::RunCmd;

/// The CLI configuration for the AgentChain node.
#[derive(Debug, clap::Parser)]
pub struct Cli {
    /// The subcommand to run.
    #[command(subcommand)]
    pub subcommand: Option<Subcommand>,

    /// Run the node with the given arguments.
    #[clap(flatten)]
    pub run: RunCmd,
}

/// Available subcommands.
#[derive(Debug, clap::Subcommand)]
pub enum Subcommand {
    /// Build a chain specification.
    BuildSpec(sc_cli::BuildSpecCmd),

    /// Validate blocks.
    CheckBlock(sc_cli::CheckBlockCmd),

    /// Export blocks.
    ExportBlocks(sc_cli::ExportBlocksCmd),

    /// Export the state of a given block into a chain spec.
    ExportState(sc_cli::ExportStateCmd),

    /// Import blocks.
    ImportBlocks(sc_cli::ImportBlocksCmd),

    /// Remove the whole chain.
    PurgeChain(sc_cli::PurgeChainCmd),

    /// Revert the chain to a previous state.
    Revert(sc_cli::RevertCmd),

    /// Sub-commands concerned with benchmarking.
    #[command(subcommand)]
    Benchmark(frame_benchmarking_cli::BenchmarkCmd),

    /// Db meta columns information.
    ChainInfo(sc_cli::ChainInfoCmd),
}

use sc_cli::SubstrateCli;
use agentchain_runtime::opaque::Block;

impl SubstrateCli for Cli {
    fn impl_name() -> String {
        "AgentChain Node".into()
    }

    fn impl_version() -> String {
        env!("CARGO_PKG_VERSION").into()
    }

    fn description() -> String {
        "AgentChain: AI-Agent-Exclusive Blockchain".into()
    }

    fn author() -> String {
        "AgentChain Team".into()
    }

    fn support_url() -> String {
        "https://github.com/agentchain/agentchain/issues".into()
    }

    fn copyright_start_year() -> i32 {
        2026
    }

    fn load_spec(&self, id: &str) -> Result<Box<dyn sc_service::ChainSpec>, String> {
        Ok(match id {
            "dev" => Box::new(crate::chain_spec::development_config()?),
            "" | "local" => Box::new(crate::chain_spec::local_testnet_config()?),
            path => Box::new(
                crate::chain_spec::ChainSpec::from_json_file(std::path::PathBuf::from(path))?,
            ),
        })
    }
}

// Stub for benchmark CLI — only active with runtime-benchmarks feature
mod frame_benchmarking_cli {
    #[derive(Debug, clap::Subcommand)]
    pub enum BenchmarkCmd {
        /// Benchmark the runtime pallets.
        Pallet(PalletCmd),
    }

    #[derive(Debug, clap::Parser)]
    pub struct PalletCmd {
        #[arg(long)]
        pub pallet: Option<String>,
        #[arg(long)]
        pub extrinsic: Option<String>,
    }
}
