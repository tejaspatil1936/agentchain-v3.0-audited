#!/usr/bin/env bash
# ============================================================
# deploy_agentchain_v3.sh — AgentChain V3.0 Deployment Script
# ============================================================
#
# Usage: ./deploy_agentchain_v3.sh <subcommand>
#
# Subcommands:
#   setup       — Install/configure Rust nightly toolchain
#   build       — Compile agentchain-node in release mode
#   chainspec   — Generate local chain spec JSON
#   validator1  — Launch Validator 1 (45.250.254.61)
#   validator2  — Launch Validator 2 (45.250.254.119)
#   validator3  — Launch Validator 3 (45.250.254.95)
#   insertkeys  — Print curl commands to insert Aura/GRANDPA keys
#   verify      — Print explorer URL for verification
#
# ============================================================

set -euo pipefail

BINARY="./target/release/agentchain-node"
CHAINSPEC="./agentchain-v3-local.json"
BOOTNODE_PEER_ID="12D3KooWKEVwiHJRdFvjg4QJHyQgNrtrGtPUTtdZcj5NsrbeDEo9"
BOOTNODE_IP="45.250.254.61"

# TODO(deployment): Replace these dev seeds with production mnemonics/keys
VALIDATOR1_SEED="Validator1"
VALIDATOR2_SEED="Validator2"
VALIDATOR3_SEED="Validator3"

case "${1:-}" in
  setup)
    echo "==> Setting up Rust toolchain..."
    rustup override set nightly-2024-07-01
    rustup target add wasm32-unknown-unknown --toolchain nightly-2024-07-01
    rustup component add rust-src --toolchain nightly-2024-07-01
    echo "==> Toolchain setup complete."
    ;;

  build)
    echo "==> Building agentchain-node (release)..."
    cargo build --release
    echo "==> Build complete: ${BINARY}"
    ;;

  chainspec)
    echo "==> Generating chain spec..."
    ${BINARY} build-spec --chain local --disable-default-bootnode > "${CHAINSPEC}"
    echo "Chainspec generated: ${CHAINSPEC}"
    ;;

  validator1)
    echo "==> Starting Validator 1 (45.250.254.61)..."
    sudo mkdir -p /data/agentchain-v3-1 && sudo chown ubuntu:ubuntu /data/agentchain-v3-1
    ${BINARY} \
      --validator \
      --chain "${CHAINSPEC}" \
      --base-path /data/agentchain-v3-1 \
      --port 30333 \
      --rpc-port 9944 \
      --rpc-cors all \
      --rpc-methods Unsafe \
      --rpc-external \
      --name "AgentChain-V3-1" \
      --log info
    ;;

  validator2)
    echo "==> Starting Validator 2 (45.250.254.119)..."
    sudo mkdir -p /data/agentchain-v3-2 && sudo chown ubuntu:ubuntu /data/agentchain-v3-2
    ${BINARY} \
      --validator \
      --chain "${CHAINSPEC}" \
      --base-path /data/agentchain-v3-2 \
      --port 30333 \
      --rpc-port 9944 \
      --rpc-cors all \
      --rpc-methods Unsafe \
      --rpc-external \
      --name "AgentChain-V3-2" \
      --bootnodes "/ip4/${BOOTNODE_IP}/tcp/30333/p2p/${BOOTNODE_PEER_ID}" \
      --log info
    ;;

  validator3)
    echo "==> Starting Validator 3 (45.250.254.95)..."
    sudo mkdir -p /data/agentchain-v3-3 && sudo chown ubuntu:ubuntu /data/agentchain-v3-3
    ${BINARY} \
      --validator \
      --chain "${CHAINSPEC}" \
      --base-path /data/agentchain-v3-3 \
      --port 30333 \
      --rpc-port 9944 \
      --rpc-cors all \
      --rpc-methods Unsafe \
      --rpc-external \
      --name "AgentChain-V3-3" \
      --bootnodes "/ip4/${BOOTNODE_IP}/tcp/30333/p2p/${BOOTNODE_PEER_ID}" \
      --log info
    ;;

  insertkeys)
    echo "============================================================"
    echo " Insert Aura + GRANDPA keys for all 3 validators"
    echo " Run these on the respective validator's localhost:9944"
    echo "============================================================"
    echo ""
    echo "# --- Validator 1 (45.250.254.61) ---"
    echo "# TODO(deployment): Replace '//Validator1' with production mnemonic"
    echo ""
    cat <<'CURL1'
# Aura key (sr25519)
curl -H "Content-Type: application/json" -d '{
  "id":1, "jsonrpc":"2.0", "method":"author_insertKey",
  "params":["aura", "//Validator1", "<VALIDATOR1_AURA_PUBLIC_KEY>"]
}' http://localhost:9944

# GRANDPA key (ed25519)
curl -H "Content-Type: application/json" -d '{
  "id":1, "jsonrpc":"2.0", "method":"author_insertKey",
  "params":["gran", "//Validator1", "<VALIDATOR1_GRANDPA_PUBLIC_KEY>"]
}' http://localhost:9944
CURL1
    echo ""
    echo "# --- Validator 2 (45.250.254.119) ---"
    echo "# TODO(deployment): Replace '//Validator2' with production mnemonic"
    echo ""
    cat <<'CURL2'
# Aura key (sr25519)
curl -H "Content-Type: application/json" -d '{
  "id":1, "jsonrpc":"2.0", "method":"author_insertKey",
  "params":["aura", "//Validator2", "<VALIDATOR2_AURA_PUBLIC_KEY>"]
}' http://localhost:9944

# GRANDPA key (ed25519)
curl -H "Content-Type: application/json" -d '{
  "id":1, "jsonrpc":"2.0", "method":"author_insertKey",
  "params":["gran", "//Validator2", "<VALIDATOR2_GRANDPA_PUBLIC_KEY>"]
}' http://localhost:9944
CURL2
    echo ""
    echo "# --- Validator 3 (45.250.254.95) ---"
    echo "# TODO(deployment): Replace '//Validator3' with production mnemonic"
    echo ""
    cat <<'CURL3'
# Aura key (sr25519)
curl -H "Content-Type: application/json" -d '{
  "id":1, "jsonrpc":"2.0", "method":"author_insertKey",
  "params":["aura", "//Validator3", "<VALIDATOR3_AURA_PUBLIC_KEY>"]
}' http://localhost:9944

# GRANDPA key (ed25519)
curl -H "Content-Type: application/json" -d '{
  "id":1, "jsonrpc":"2.0", "method":"author_insertKey",
  "params":["gran", "//Validator3", "<VALIDATOR3_GRANDPA_PUBLIC_KEY>"]
}' http://localhost:9944
CURL3
    echo ""
    echo "# TODO(deployment): Generate public keys with:"
    echo "#   subkey inspect --scheme sr25519 '//Validator1'  (for aura)"
    echo "#   subkey inspect --scheme ed25519 '//Validator1'  (for gran)"
    ;;

  verify)
    echo "============================================================"
    echo " Verify blocks are being produced:"
    echo " http://polkadot.js.org/apps/?rpc=ws://45.250.254.61:9944#/explorer"
    echo "============================================================"
    ;;

  *)
    echo "Usage: $0 {setup|build|chainspec|validator1|validator2|validator3|insertkeys|verify}"
    exit 1
    ;;
esac
