//! Build script for the AgentChain runtime.
//! Compiles the runtime to a Wasm blob for on-chain storage.

fn main() {
    #[cfg(feature = "std")]
    {
        substrate_wasm_builder::WasmBuilder::build_using_defaults();
    }
}
