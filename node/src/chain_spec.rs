//! AgentChain genesis configuration (chain spec).
//!
//! Defines the initial state of the chain: authorities, balances,
//! constitutional principles, vesting schedules, and pallet parameters.
//!
//! ## V3.0 Allocation (10B ACH)
//! - Validator Rewards:   3.5B (35%) — recycling compensates for reduction
//! - On-Chain Treasury:   1.5B (15%) — tx fee recycling supplements
//! - Liquidity (AMM):     700M  (7%) — smaller initial, less supply shock
//! - LP Incentives:       1.0B (10%) — sustained LP rewards over 4 years
//! - Community:           1.0B (10%) — time-locked in 4 × 250M tranches
//! - Deployer Bootstrap:  500M  (5%) — 12-month sunset, then → treasury
//! - Insurance Fund:      500M  (5%) — 67% supermajority to access
//! - Founder:             800M  (8%) — dual-schedule vest, no cliff (unchanged)
//! - Contributors:        500M  (5%) — 2-year linear vest, no cliff (unchanged)
//!
//! Network-serving: 87%  |  Insider: 13%
//!
//! ## Account Mapping
//! Protocol fund accounts use PalletId-derived deterministic addresses.
//! This ensures the runtime's `TreasuryAccount`, `ValidatorRewardFundAccount`,
//! etc. point to accounts that actually hold the genesis funds.
//!
//! Dev accounts (Alice–Ferdie) receive small test balances for development.

use agentchain_primitives::*;
use agentchain_runtime::{
    opaque::SessionKeys, AccountId, Signature, WASM_BINARY,
};
use frame_support::PalletId;
use sc_service::ChainType;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_core::{sr25519, Pair, Public};
use sp_runtime::traits::{AccountIdConversion, IdentifyAccount, Verify};

/// Specialized chain spec for AgentChain.
pub type ChainSpec = sc_service::GenericChainSpec;

type AccountPublic = <Signature as Verify>::Signer;

/// Generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{}", seed), None)
        .expect("static values are valid; qed")
        .public()
}

/// Generate an account ID from seed.
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
    AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
    AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Generate an Aura authority key.
pub fn authority_keys_from_seed(s: &str) -> (AccountId, AuraId, GrandpaId) {
    (
        get_account_id_from_seed::<sr25519::Public>(s),
        get_from_seed::<AuraId>(s),
        get_from_seed::<GrandpaId>(s),
    )
}

/// Session keys constructor.
fn session_keys(aura: AuraId, grandpa: GrandpaId) -> SessionKeys {
    SessionKeys { aura, grandpa }
}

// ============================================================
// Protocol Fund Accounts (PalletId-derived)
// These MUST match the runtime's parameter_types! accounts exactly.
// ============================================================

/// Treasury account — must match runtime TreasuryAccount.
fn treasury_account() -> AccountId {
    PalletId(*b"ach/trsy").into_account_truncating()
}

/// Validator reward fund — must match runtime ValidatorRewardFundAccount.
fn validator_reward_fund_account() -> AccountId {
    PalletId(*b"ach/vfnd").into_account_truncating()
}

/// Staker reward pool — must match runtime RewardPoolAccount.
/// Starts with ED to stay alive; accumulates from marketplace fee transfers.
fn reward_pool_account() -> AccountId {
    PalletId(*b"ach/pool").into_account_truncating()
}

/// Liquidity bootstrap fund — seed AMM pool.
fn liquidity_fund_account() -> AccountId {
    PalletId(*b"ach/liqd").into_account_truncating()
}

/// Community distribution fund — fair launch / airdrop.
fn community_fund_account() -> AccountId {
    PalletId(*b"ach/cmty").into_account_truncating()
}

/// V3.0: Insurance fund — emergency backstop for catastrophic events.
fn insurance_fund_account() -> AccountId {
    PalletId(*b"ach/insf").into_account_truncating()
}

/// V3.0: LP incentive fund — rewards for liquidity providers over 4 years.
fn liquidity_incentive_account() -> AccountId {
    PalletId(*b"ach/lpir").into_account_truncating()
}

/// V3.0: Deployer bootstrap fund — early deployer subsidies, 12-month sunset.
fn deployer_bootstrap_account() -> AccountId {
    PalletId(*b"ach/boot").into_account_truncating()
}

/// Chain properties for wallets and explorers.
/// Without this, wallets display "Unit" instead of "ACH" and show raw planck balances.
fn chain_properties() -> sc_service::Properties {
    let mut properties = sc_service::Properties::new();
    properties.insert("tokenSymbol".into(), "ACH".into());
    properties.insert("tokenDecimals".into(), 12.into());
    properties.insert("ss58Format".into(), 42.into()); // TODO: Register a unique SS58 prefix
    properties
}

/// Development chain config (single validator: Alice).
pub fn development_config() -> Result<ChainSpec, String> {
    Ok(ChainSpec::builder(
        WASM_BINARY.ok_or_else(|| "WASM binary not available".to_string())?,
        None,
    )
    .with_name("AgentChain Dev")
    .with_id("agentchain_dev")
    .with_chain_type(ChainType::Development)
    .with_properties(chain_properties())
    .with_genesis_config_patch(testnet_genesis(
        // Initial authorities
        vec![authority_keys_from_seed("Alice")],
        // Sudo account
        get_account_id_from_seed::<sr25519::Public>("Alice"),
        // Dev accounts for testing
        vec![
            get_account_id_from_seed::<sr25519::Public>("Alice"),
            get_account_id_from_seed::<sr25519::Public>("Bob"),
            get_account_id_from_seed::<sr25519::Public>("Charlie"),
            get_account_id_from_seed::<sr25519::Public>("Dave"),
            get_account_id_from_seed::<sr25519::Public>("Eve"),
            get_account_id_from_seed::<sr25519::Public>("Ferdie"),
        ],
        true,
    ))
    .build())
}

/// Local testnet config (3 validators: Validator1, Validator2, Validator3).
pub fn local_testnet_config() -> Result<ChainSpec, String> {
    Ok(ChainSpec::builder(
        WASM_BINARY.ok_or_else(|| "WASM binary not available".to_string())?,
        None,
    )
    .with_name("AgentChain Local Testnet")
    .with_id("agentchain_local")
    .with_chain_type(ChainType::Local)
    .with_properties(chain_properties())
    .with_genesis_config_patch(testnet_genesis(
        vec![
            // TODO(deployment): Replace dev seeds with production SR25519 keys
            authority_keys_from_seed("Validator1"),  // TODO(deployment): Replace with production key for 45.250.254.61
            authority_keys_from_seed("Validator2"),  // TODO(deployment): Replace with production key for 45.250.254.119
            authority_keys_from_seed("Validator3"),  // TODO(deployment): Replace with production key for 45.250.254.95
        ],
        // TODO(deployment): Replace with production sudo key
        get_account_id_from_seed::<sr25519::Public>("Validator1"),  // Sudo = Validator1
        vec![
            // TODO(deployment): Replace dev seeds with production SR25519 keys
            get_account_id_from_seed::<sr25519::Public>("Validator1"),  // TODO(deployment)
            get_account_id_from_seed::<sr25519::Public>("Validator2"),  // TODO(deployment)
            get_account_id_from_seed::<sr25519::Public>("Validator3"),  // TODO(deployment)
        ],
        true,
    ))
    .build())
}

/// Build the genesis config JSON patch.
///
/// Protocol fund accounts use PalletId-derived deterministic addresses
/// that match the runtime's parameter_types! (audit fix: genesis/runtime alignment).
///
/// Dev accounts receive small test balances for local testing.
fn testnet_genesis(
    initial_authorities: Vec<(AccountId, AuraId, GrandpaId)>,
    root_key: AccountId,
    dev_accounts: Vec<AccountId>,
    _enable_println: bool,
) -> serde_json::Value {
    // ================================================================
    // Genesis balance allocation — 10B ACH total (exactly)
    // ================================================================
    //
    // V3.0 Genesis Allocation (10B ACH):
    //
    // Protocol fund accounts (PalletId-derived, match runtime exactly):
    //   Treasury:            1.5B (15%) — governance-controlled
    //   Validator Rewards:   3.5B (35%) — halving block reward + fee recycling
    //   Liquidity (AMM):     700M  (7%) — initial AMM pool seeding
    //   LP Incentives:       1.0B (10%) — sustained LP rewards over 4 years
    //   Community Fund:      1.0B (10%) — fair launch / airdrop, 4 × 250M tranches
    //   Deployer Bootstrap:  500M  (5%) — early deployer subsidies, 12-month sunset
    //   Insurance Fund:      500M  (5%) — 67% supermajority access
    //
    // Vested insider accounts (dev seeds for devnet, UNCHANGED from V2.5):
    //   Alice (Founder):     800M  (8%) — dual-schedule: 120M/1yr + 680M/4yr, no cliff
    //   Bob (Contributor):   500M  (5%) — 2-year linear vest, no cliff
    //
    // H1 fix: Dev test balances are SUBTRACTED from the community fund
    // to maintain exact 10B total supply. No extra ACH is created.

    let dev_balance: Balance = 10_000 * UNITS;
    let num_dev_accounts = if dev_accounts.len() > 2 { dev_accounts.len() - 2 } else { 0 };
    let total_dev_balance = dev_balance * (num_dev_accounts as u128);
    // Subtract dev balances + reward pool ED from community fund
    let adjusted_community = COMMUNITY_DISTRIBUTION
        .saturating_sub(total_dev_balance)
        .saturating_sub(EXISTENTIAL_DEPOSIT);

    let mut balances: Vec<(AccountId, Balance)> = vec![
        // === Protocol fund accounts (PalletId-derived) ===
        (treasury_account(), TREASURY_ALLOCATION),                    // 1.5B ACH
        (validator_reward_fund_account(), VALIDATOR_REWARD_FUND),     // 3.5B ACH
        (liquidity_fund_account(), LIQUIDITY_BOOTSTRAP),              // 700M ACH
        (liquidity_incentive_account(), LIQUIDITY_INCENTIVE_POOL),    // 1.0B ACH (V3.0 NEW)
        (community_fund_account(), adjusted_community),               // ~1.0B ACH minus dev balances
        (deployer_bootstrap_account(), DEPLOYER_BOOTSTRAP_FUND),      // 500M ACH (V3.0 NEW)
        (insurance_fund_account(), INSURANCE_FUND),                   // 500M ACH (V3.0 NEW)
        (reward_pool_account(), EXISTENTIAL_DEPOSIT),                 // 0.001 ACH (keep-alive)

        // === Vested insider accounts (UNCHANGED from V2.5) ===
        (dev_accounts[0].clone(), FOUNDER_ALLOCATION),                // 800M ACH (Alice)
        (dev_accounts[1].clone(), CONTRIBUTOR_ALLOCATION),            // 500M ACH (Bob)
    ];

    // Dev test balances (carved from community fund, not extra supply)
    for account in &dev_accounts[2..] {
        balances.push((account.clone(), dev_balance));
    }

    // ================================================================
    // Vesting schedules — V2.5 revised, no cliffs
    // ================================================================
    //
    // Substrate vesting pallet format: [account, locked, per_block, starting_block]
    //   locked:         total amount locked (vested linearly from starting_block)
    //   per_block:      amount that unlocks per block
    //   starting_block: block at which vesting begins (0 = genesis)
    //
    // FOUNDER — Dual schedule (2 entries for same account):
    //   Operational: 120M ACH over 1 year (BLOCKS_1_YEAR), starts at block 0
    //   Long-term:   680M ACH over 4 years (BLOCKS_4_YEARS), starts at block 0
    //   Combined month-1 access: ~24M ACH
    //   No cliff — both schedules begin vesting at genesis.
    //
    // CONTRIBUTOR — Single schedule:
    //   500M ACH over 2 years (BLOCKS_2_YEARS), starts at block 0
    //   No cliff — vesting begins at genesis.
    //   V2.5: Shortened from 3 years. Contributors took early-stage risk.

    // Founder operational pool: 120M over 1 year
    let founder_operational_per_block: Balance =
        FOUNDER_OPERATIONAL / (BLOCKS_1_YEAR as u128);
    // Founder long-term pool: 680M over 4 years
    let founder_longterm_per_block: Balance =
        FOUNDER_LONG_TERM / (BLOCKS_4_YEARS as u128);
    // Contributor: 500M over 2 years
    let contributor_per_block: Balance =
        CONTRIBUTOR_ALLOCATION / (BLOCKS_2_YEARS as u128);

    serde_json::json!({
        "balances": {
            "balances": balances,
        },
        "vesting": {
            "vesting": [
                // Founder operational: 120M ACH, 1-year linear vest, no cliff
                [dev_accounts[0].clone(), FOUNDER_OPERATIONAL, founder_operational_per_block, 0u32],
                // Founder long-term: 680M ACH, 4-year linear vest, no cliff
                [dev_accounts[0].clone(), FOUNDER_LONG_TERM, founder_longterm_per_block, 0u32],
                // Contributor: 500M ACH, 2-year linear vest, no cliff
                [dev_accounts[1].clone(), CONTRIBUTOR_ALLOCATION, contributor_per_block, 0u32],
            ],
        },
        "aura": {
            "authorities": initial_authorities
                .iter()
                .map(|x| x.1.clone())
                .collect::<Vec<_>>(),
        },
        "grandpa": {
            "authorities": initial_authorities
                .iter()
                .map(|x| (x.2.clone(), 1))
                .collect::<Vec<_>>(),
        },
        "session": {
            "keys": initial_authorities
                .iter()
                .map(|x| {
                    (
                        x.0.clone(),
                        x.0.clone(),
                        session_keys(x.1.clone(), x.2.clone()),
                    )
                })
                .collect::<Vec<_>>(),
        },
        "sudo": {
            "key": Some(root_key),
        },
        "constitution": {
            "principles": vec![
                (
                    b"verified_autonomous_execution".to_vec(),
                    b"All chain participants must execute within verified environments".to_vec(),
                    b"AgentIdentity".to_vec(),
                ),
                (
                    b"deployer_transparency".to_vec(),
                    b"Every agent must declare its deployer; deployer graphs are public".to_vec(),
                    b"DeployerAgents".to_vec(),
                ),
                (
                    b"constitutional_compliance".to_vec(),
                    b"Runtime upgrades must pass CCC validation against Kernel principles".to_vec(),
                    b"Constitution".to_vec(),
                ),
                (
                    b"economic_anti_capture".to_vec(),
                    b"No single entity may capture >50% of governance weight".to_vec(),
                    b"".to_vec(),
                ),
                (
                    b"bootstrapped_allocation".to_vec(),
                    b"87% of token supply serves the network; insider allocation capped at 13%".to_vec(),
                    b"Economics".to_vec(),
                ),
            ],
        },
        // V1.5: Approved enclave measurements loaded at genesis.
        // For devnet (AllowSimulatedTee = true), simulated agents bypass the whitelist,
        // so this can include placeholder entries for testing the confirm_agent flow.
        //
        // For testnet/mainnet (AllowSimulatedTee = false), populate with actual
        // MRENCLAVE hashes of approved agent binaries. All agents must match one of
        // these measurements to be confirmed as Active.
        //
        // Example dev entries use well-known test hashes. Replace with real
        // measurements from `sgx_sign dump` or `sevtool --attestation-report` output.
        "agentIdentity": {
            "approvedEnclaves": vec![
                // Dev placeholder: "agentchain-worker-dev-v1.5"
                // This is a test measurement for local development.
                // Real entries would be actual MRENCLAVE/measurement hashes.
                (
                    sp_core::H256::from(sp_core::hashing::blake2_256(b"agentchain-worker-dev-v1.5")),
                    b"agentchain-worker-dev-v1.5".to_vec(),
                ),
                // Dev placeholder: "agentchain-worker-dev-v1.5-debug"
                (
                    sp_core::H256::from(sp_core::hashing::blake2_256(b"agentchain-worker-dev-v1.5-debug")),
                    b"agentchain-worker-dev-v1.5-debug".to_vec(),
                ),
            ],
        },
    })
}
