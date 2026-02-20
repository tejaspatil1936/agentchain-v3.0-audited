//! AgentChain shared primitive types.
//!
//! Every crate in the workspace imports from this crate.
//! No pallet-specific logic lives here — only type aliases,
//! constants, and cross-cutting data structures.
//!
//! Pallets never depend on each other's types directly;
//! they depend on primitives.
//!
//! ## V1.5 TEE Enforcement Additions
//! - SGX Quote v3 and SEV-SNP report format constants
//! - `ApprovedEnclaves` whitelist types
//! - Two-phase registration: Pending → Active via offchain verification
//! - Liveness response format requirements (challenge seed binding)

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
pub use sp_core::H256;
use sp_runtime::{
    traits::{BlakeTwo256, IdentifyAccount, Verify},
    MultiSignature,
};

// ============================================================
// Core chain types — define the shape of the entire chain
// ============================================================

/// The signature type. MultiSignature supports Ed25519, Sr25519, ECDSA.
pub type Signature = MultiSignature;

/// AccountId derived from the signature verification key (32-byte hash).
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

/// Balance type. u128 → 38 decimal digits of precision.
/// At 12 decimals this supports ~340 billion whole tokens.
pub type Balance = u128;

/// Block number type. u32 → ~136 years at 6-second blocks.
pub type BlockNumber = u32;

/// Nonce (transaction index) per account.
pub type Nonce = u32;

/// The hashing algorithm used throughout the chain.
pub type Hashing = BlakeTwo256;

/// Block header type.
pub type Header = sp_runtime::generic::Header<BlockNumber, Hashing>;

/// Hash type used for block hashes, storage keys, etc.
pub type Hash = H256;

// ============================================================
// Token constants
// ============================================================

/// One ACH token in planck units (12 decimal places).
pub const UNITS: Balance = 1_000_000_000_000;

/// 0.001 ACH.
pub const MILLIUNITS: Balance = UNITS / 1_000;

/// 0.000001 ACH.
pub const MICROUNITS: Balance = UNITS / 1_000_000;

/// Existential deposit — minimum balance to keep an account alive.
pub const EXISTENTIAL_DEPOSIT: Balance = MILLIUNITS;

/// Total ACH supply: 10 billion tokens (fixed, no inflation mint).
pub const TOTAL_ACH_SUPPLY: Balance = 10_000_000_000 * UNITS;

// ============================================================
// Genesis distribution buckets
// Network-serving: 87%  |  Insider: 13%
//
// V3.0 RESTRUCTURE:
//   Validator Rewards:      3.5B (35%) — recycling compensates for reduction
//   Treasury:               1.5B (15%) — tx fee recycling supplements
//   Liquidity (AMM seed):   0.7B  (7%) — smaller initial, less supply shock
//   LP Incentives:          1.0B (10%) — sustained LP rewards over 4 years
//   Community + Ecosystem:  1.0B (10%) — time-locked in 4 × 250M tranches
//   Deployer Bootstrap:     0.5B  (5%) — 12-month sunset, then → treasury
//   Insurance Fund:         0.5B  (5%) — 67% supermajority to access
//   Founder (vested):       0.8B  (8%) — unchanged
//   Contributor (vested):   0.5B  (5%) — unchanged
//   TOTAL:                 10.0B (100%)
//
// Key changes from V2.5:
// - Validator fund recycling: 15% of marketplace + tx fees flow back
// - Adaptive registration burn: tapers from 5K→100 ACH at high adoption
// - Deployer exit burns: 30%→0% of stake burned based on tenure
// - Governance-tunable economic parameters
// ============================================================

/// Validator block rewards — emitted over 20+ years via halving schedule.
/// V3.0: Reduced from 4.0B (40%) to 3.5B (35%). The 500M reduction is
/// compensated by the new validator fund recycling mechanism, which routes
/// 15% of all marketplace and transaction fees back to this fund. At moderate
/// adoption, recycling extends the fund's effective lifetime past 20 years.
pub const VALIDATOR_REWARD_FUND: Balance = 3_500_000_000 * UNITS;       // 35%

/// On-chain treasury — governance-controlled from genesis.
/// V3.0: Reduced from 2.0B (20%) to 1.5B (15%). Offset by 15% of
/// transaction fees now flowing to treasury via DealWithFees, plus
/// ongoing marketplace fee revenue.
pub const TREASURY_ALLOCATION: Balance = 1_500_000_000 * UNITS;        // 15%

/// AMM liquidity bootstrap — seed the ACH/bUSDC pool.
/// V3.0: Reduced from 1.7B (17%) to 700M (7%). Instead of deploying 1.7B
/// as a single supply shock, 700M seeds the initial AMM pool and a separate
/// 1B LP Incentive pool distributes rewards to liquidity providers over 4 years.
pub const LIQUIDITY_BOOTSTRAP: Balance = 700_000_000 * UNITS;           //  7%

/// LP incentive rewards — distributed to liquidity providers over 4 years.
/// V3.0 NEW: Replaces the lump-sum liquidity approach with sustained incentives.
/// ~20.8M ACH/month to LPs, deepening orderbook gradually rather than
/// creating a single large pool vulnerable to insider drainage.
pub const LIQUIDITY_INCENTIVE_POOL: Balance = 1_000_000_000 * UNITS;   // 10%

/// Community fair launch — airdrop, grants, ecosystem development.
/// V3.0: Same total (1B) but now governance-gated in 4 × 250M tranches,
/// each unlocking at 6-month intervals and requiring a governance vote.
/// Eliminates the single-actor access risk of the V2.5 sudo-controlled fund.
pub const COMMUNITY_DISTRIBUTION: Balance = 1_000_000_000 * UNITS;     // 10%

/// Deployer bootstrap fund — subsidize early deployers during network launch.
/// V3.0 NEW: Explicit, time-bounded pool with a 12-month sunset. Any remaining
/// tokens after the sunset block are automatically swept to treasury.
/// Max 100K ACH per deployer, max 2,000 recipients.
pub const DEPLOYER_BOOTSTRAP_FUND: Balance = 500_000_000 * UNITS;      //  5%

/// Insurance fund — emergency backstop for catastrophic events.
/// V3.0 NEW: Covers slashing bugs, bridge exploits, governance emergencies.
/// Requires 67% governance supermajority to access. Cannot be spent on
/// routine operations — purely a safety net.
pub const INSURANCE_FUND: Balance = 500_000_000 * UNITS;               //  5%

/// Founder allocation — dual-schedule vest, no cliff.
/// V2.5: Removed 1-year cliff. Split into two parallel vesting schedules:
///   - Operational pool (15%): 120M ACH, 1-year linear vest from genesis
///   - Long-term pool  (85%): 680M ACH, 4-year linear vest from genesis
/// Combined month-1 access: ~24M ACH for operational funding.
/// No day-1 lump unlock — all tokens vest linearly per-block.
pub const FOUNDER_ALLOCATION: Balance = 800_000_000 * UNITS;           //  8%
pub const FOUNDER_OPERATIONAL: Balance = 120_000_000 * UNITS;          //  15% of founder
pub const FOUNDER_LONG_TERM: Balance = 680_000_000 * UNITS;            //  85% of founder

/// Early contributor pool — 2-year linear vest, no cliff.
/// V2.5: Shortened from 3-year to 2-year vest. Contributors took early-stage
/// risk and are often contractors who need liquidity sooner. At 5% of supply
/// with only 13% total insider allocation, the accelerated vest is appropriate.
pub const CONTRIBUTOR_ALLOCATION: Balance = 500_000_000 * UNITS;       //  5%

// ============================================================
// Timing constants
// ============================================================

/// Block time: 6 seconds.
pub const MILLISECS_PER_BLOCK: u64 = 6000;
pub const SLOT_DURATION: u64 = MILLISECS_PER_BLOCK;

/// Epoch: 600 blocks = 1 hour at 6-second blocks.
pub const EPOCH_DURATION_IN_BLOCKS: BlockNumber = 600;

pub const MINUTES: BlockNumber = 60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
pub const HOURS: BlockNumber = MINUTES * 60;
pub const DAYS: BlockNumber = HOURS * 24;

// ============================================================
// Economic mechanism constants
// ============================================================

/// ACH burned on agent registration (anti-spam + deflationary).
pub const REGISTRATION_BURN_ACH: Balance = 5_000 * UNITS;

/// Minimum ACH stake for validator eligibility.
pub const MIN_VALIDATOR_STAKE: Balance = 1_000_000 * UNITS;

/// Minimum ACH stake per agent for deployer registration.
/// V2.5: Reduced from 100,000 to 10,000 ACH. The original 100K created a
/// prohibitive barrier for bootstrapping — 10 agents required 1M ACH locked
/// as deployer stake alone. At 10K, a 10-agent fleet needs only 100K locked,
/// making manual community fund seeding 10× more capital-efficient.
/// The stake still provides accountability (deployers lose 10K if their
/// agent misbehaves) without blocking adoption.
pub const DEPLOYER_STAKE_PER_AGENT: Balance = 10_000 * UNITS;

/// Minimum bond to start the tenure clock.
pub const MIN_STAKING_BOND: Balance = 1_000 * UNITS;

/// Protocol fee split (basis points out of total fee collected):
/// V3.0: Changed from 3-way (60/20/20) to 4-way split. 15% of marketplace
/// fees are now recycled to the validator reward fund, creating a self-sustaining
/// income loop that grows with network activity.
pub const FEE_SPLIT_STAKERS_BPS: u32 = 5_000;            // 50% (was 60%)
pub const FEE_SPLIT_TREASURY_BPS: u32 = 1_500;            // 15% (was 20%)
pub const FEE_SPLIT_VALIDATOR_FUND_BPS: u32 = 1_500;      // 15% NEW — recycled to validator fund
pub const FEE_SPLIT_BURN_BPS: u32 = 2_000;                // 20% (unchanged)

/// Reputation tier thresholds.
pub const REPUTATION_TIER_1_THRESHOLD: ReputationScore = 3_000;
pub const REPUTATION_TIER_2_THRESHOLD: ReputationScore = 6_000;
pub const REPUTATION_TIER_3_THRESHOLD: ReputationScore = 8_000;

/// Reputation tier price caps for marketplace access.
pub const REPUTATION_TIER_1_CAP: Balance = 10_000 * UNITS;
pub const REPUTATION_TIER_2_CAP: Balance = 100_000 * UNITS;
pub const REPUTATION_TIER_3_CAP: Balance = 1_000_000 * UNITS;

/// Reputation threshold for reduced protocol fee.
/// V3.0: Added mid-tier at 1.75% for agents with rep >= 5,000.
/// Veteran fee reduced from 1.5% to 1.0% to reward long-term participants.
/// Base fee increased from 2.0% to 2.5% — net higher revenue from new agents.
pub const BASE_PROTOCOL_FEE_BPS: u32 = 250;                              // 2.5% (was 2.0%)
pub const MID_TIER_REP_THRESHOLD: ReputationScore = 5_000;
pub const MID_TIER_FEE_BPS: u32 = 175;                                   // 1.75% NEW
pub const VETERAN_FEE_THRESHOLD: ReputationScore = 7_500;
pub const VETERAN_FEE_BPS: u32 = 100;                                    // 1.0% (was 1.5%)

/// Decelerated reputation gain thresholds.
pub const REPUTATION_DECEL_TIER_1: ReputationScore = 6_000;
pub const REPUTATION_DECEL_TIER_2: ReputationScore = 8_000;

/// Tenure-weighted staking multipliers (basis points: 10000 = 1.0x).
pub const TENURE_MULTIPLIER_0_3M: u32 = 10_000;
pub const TENURE_MULTIPLIER_3_6M: u32 = 11_000;
pub const TENURE_MULTIPLIER_6_12M: u32 = 12_500;
pub const TENURE_MULTIPLIER_1_2Y: u32 = 15_000;
pub const TENURE_MULTIPLIER_2Y_PLUS: u32 = 20_000;

/// Blocks per tenure milestone (at 6s blocks).
pub const BLOCKS_3_MONTHS: BlockNumber = 1_314_000;
pub const BLOCKS_6_MONTHS: BlockNumber = 2_628_000;
pub const BLOCKS_1_YEAR: BlockNumber = 5_256_000;
pub const BLOCKS_2_YEARS: BlockNumber = 10_512_000;
pub const BLOCKS_4_YEARS: BlockNumber = 21_024_000;

/// Unbonding period: 7 days in blocks.
pub const UNBONDING_PERIOD_BLOCKS: BlockNumber = 100_800;

/// Deployer stake unlock cooldown: 30 days after agent deactivation.
pub const DEPLOYER_UNSTAKE_COOLDOWN_BLOCKS: BlockNumber = 30 * DAYS;

/// Maximum liveness challenges processed per block.
pub const MAX_CHALLENGES_PER_BLOCK: u32 = 50;

/// Maximum staker reward distributions per epoch boundary call.
pub const MAX_REWARD_DISTRIBUTIONS_PER_EPOCH: u32 = 500;

/// Job timeout: 7 days.
pub const JOB_TIMEOUT_BLOCKS: BlockNumber = 7 * DAYS;

/// Dispute auto-resolution timeout: 14 days.
pub const DISPUTE_RESOLUTION_BLOCKS: BlockNumber = 14 * DAYS;

/// Maximum epoch snapshots retained.
pub const MAX_EPOCH_SNAPSHOT_HISTORY: u32 = 720;

/// Pending verification timeout: 7 days.
/// If offchain verification doesn't confirm within this window,
/// the agent's registration can be reclaimed (deployer stake refunded).
pub const VERIFICATION_TIMEOUT_BLOCKS: BlockNumber = 7 * DAYS;

// ============================================================
// Validator System Constants
// ============================================================

/// Maximum active validators producing blocks and voting on finality.
/// Bounded by GRANDPA's O(N²) message complexity.
/// 21 for early network, increase to 50-100 as the network matures.
pub const MAX_ACTIVE_VALIDATORS: u32 = 21;

/// Maximum validator candidates in the waiting pool.
/// Candidates are eligible for selection into the active set at session rotation.
pub const MAX_VALIDATOR_CANDIDATES: u32 = 500;

/// Minimum reputation score required to register as a validator candidate.
/// Agents must prove reliability through sustained liveness before validating.
pub const MIN_VALIDATOR_REPUTATION: ReputationScore = 7_000;

/// Number of sessions a validator must wait after deregistering before
/// their validator stake can be unbonded. Prevents flash-in-flash-out attacks.
pub const VALIDATOR_COOLDOWN_SESSIONS: u32 = 24; // ~24 hours at 1-hour sessions

/// Maximum effective stake for validator selection weighting.
/// A validator staking 100M ACH has the same selection probability as one staking 10M.
/// Prevents capital-concentration capture of the active validator set.
pub const MAX_EFFECTIVE_VALIDATOR_STAKE: Balance = 10_000_000 * UNITS;

/// Maximum number of approved enclave measurements in the whitelist.
/// Governance can add/remove entries. Kept bounded for storage safety.
pub const MAX_APPROVED_ENCLAVES: u32 = 100;

/// Maximum pending verifications processed per block in on_initialize.
pub const MAX_PENDING_EXPIRATIONS_PER_BLOCK: u32 = 20;

// ============================================================
// TEE Attestation Format Constants
// ============================================================
//
// Binary layout of attestation reports from Intel SGX (DCAP Quote v3)
// and AMD SEV-SNP. Used by the identity pallet for structural
// validation before cryptographic verification in offchain workers.
//
// References:
//   Intel SGX DCAP Attestation Primitives — Quote v3 format
//   AMD SEV-SNP Firmware ABI Specification — Attestation Report

// --- Intel SGX DCAP Quote v3 ---

/// Minimum size of a valid SGX DCAP Quote v3.
/// 48-byte header + 384-byte report body + 4-byte sig length = 436 bytes.
pub const SGX_QUOTE_V3_MIN_SIZE: usize = 436;

/// SGX Quote v3 version field (little-endian u16 at offset 0).
pub const SGX_QUOTE_VERSION_3: [u8; 2] = [0x03, 0x00];

/// SGX ECDSA-256-with-P-256 attestation key type (LE u16 at offset 2).
pub const SGX_ATT_KEY_TYPE_ECDSA_P256: [u8; 2] = [0x02, 0x00];

/// Intel QE Vendor ID (16 bytes at offset 12-27).
pub const SGX_QE_VENDOR_ID_OFFSET: usize = 12;
pub const SGX_QE_VENDOR_ID_SIZE: usize = 16;
pub const SGX_INTEL_QE_VENDOR_ID: [u8; 16] = [
    0x93, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9,
    0x94, 0x0A, 0x0D, 0xB3, 0x95, 0x7F, 0x06, 0x07,
];

/// MRENCLAVE: 32 bytes at offset 112 (within Quote body).
/// Hash of the code loaded into the enclave — identifies the exact software.
pub const SGX_MRENCLAVE_OFFSET: usize = 112;
pub const SGX_MRENCLAVE_SIZE: usize = 32;

/// MRSIGNER: 32 bytes at offset 176.
/// Hash of the enclave signer's key — identifies who built the code.
pub const SGX_MRSIGNER_OFFSET: usize = 176;
pub const SGX_MRSIGNER_SIZE: usize = 32;

/// Report Data: 64 bytes at offset 368.
/// User-controlled data embedded in the attestation.
/// At registration: first 32 bytes = sr25519 public key generated inside enclave.
/// (This key is verified by the offchain attestation verifier as part of REPORTDATA,
/// then used on-chain for liveness challenge-response signature verification.)
pub const SGX_REPORT_DATA_OFFSET: usize = 368;
pub const SGX_REPORT_DATA_SIZE: usize = 64;

// --- AMD SEV-SNP ---

/// Minimum size of a valid SEV-SNP attestation report (1184 bytes).
pub const SEVSNP_REPORT_MIN_SIZE: usize = 1184;

/// SEV-SNP report version (LE u32 at offset 0, expected value = 2).
pub const SEVSNP_REPORT_VERSION: u32 = 2;

/// Measurement (launch digest): 32 bytes at offset 144.
/// Equivalent of SGX MRENCLAVE — hash of code loaded into the VM.
pub const SEVSNP_MEASUREMENT_OFFSET: usize = 144;
pub const SEVSNP_MEASUREMENT_SIZE: usize = 32;

/// Report Data: 64 bytes at offset 80.
/// At registration: first 32 bytes = sr25519 public key generated inside TEE guest.
pub const SEVSNP_REPORT_DATA_OFFSET: usize = 80;
pub const SEVSNP_REPORT_DATA_SIZE: usize = 64;

/// Signature algorithm (LE u32 at offset 52).
/// 1 = ECDSA P-384 with SHA-384.
pub const SEVSNP_SIG_ALGO_OFFSET: usize = 52;
pub const SEVSNP_SIG_ALGO_ECDSA_P384: u32 = 1;

// ============================================================
// Liveness challenge-response constants (V2.2 signed digest)
// ============================================================

/// Maximum penalty multiplier for consecutive missed challenges.
/// First miss = 1x base penalty, second = 2x, ..., fifth+ = 5x.
pub const PENALTY_ESCALATION_CAP: u32 = 5;

// ============================================================
// V2.4 Fix Constants
// ============================================================

/// Minimum stake required to count toward governance quorum (M6 fix).
/// Zero-stake agents can still observe but cannot influence outcomes.
pub const MIN_GOVERNANCE_STAKE: Balance = 1_000 * UNITS;

/// Provider compensation on timeout cancellation (M2 fix).
/// 20% of escrowed funds go to provider for work attempted.
pub const CANCELLATION_PROVIDER_SHARE_BPS: u32 = 2_000;

/// Provider compensation on dispute timeout resolution (M3 fix).
/// 10% of escrowed funds go to provider as baseline compensation.
pub const DISPUTE_PROVIDER_SHARE_BPS: u32 = 1_000;

/// Validator reward fund warning threshold (C1 fix).
/// When fund balance drops below this % of next epoch's expected payouts,
/// emit a depletion warning event for governance attention.
pub const VALIDATOR_FUND_WARNING_THRESHOLD_BPS: u32 = 100; // 1%

/// Reputation adjustment for successful job completion (I4 fix).
pub const JOB_COMPLETION_REPUTATION_BONUS: ReputationScore = 50;

/// Reputation penalty for losing a dispute (I4 fix).
pub const DISPUTE_LOSS_REPUTATION_PENALTY: ReputationScore = 100;

/// Number of monthly buckets for steward rolling window (H6 fix).
pub const STEWARD_ROLLING_WINDOW_MONTHS: u32 = 12;

/// Blocks per month for steward rolling window buckets.
pub const BLOCKS_PER_MONTH: BlockNumber = 30 * DAYS;

/// Maximum burn multiplier for reactivation after suspension.
/// First reactivation = 1x registration burn, second = 2x, third = 3x, fourth+ = 4x.
pub const REACTIVATION_MAX_BURN_MULTIPLIER: u32 = 4;

/// Reputation start values after reactivation, indexed by total_suspensions.
/// 0 suspensions = 5,000 (initial), 1 = 3,000, 2 = 1,500, 3+ = 500.
/// Agents with more suspensions start deeper in the hole.
pub const REACTIVATION_REPUTATION: [ReputationScore; 4] = [5_000, 3_000, 1_500, 500];

// ============================================================
// V3.0 Economic Mechanism Constants
// ============================================================

// --- Adaptive Registration Burn ---
// The fixed 5,000 ACH burn creates a time bomb: at 500K agents it destroys
// 2.5B ACH (25% of supply) from registrations alone — physically impossible.
// Adaptive burn tapers from REGISTRATION_BURN_ACH → ADAPTIVE_BURN_FLOOR as
// cumulative burns approach 5-10% of total supply, creating an asymptotic
// ceiling that prevents supply collapse at high adoption.

/// Minimum registration burn (floor). Even at extreme adoption, 100 ACH
/// per registration provides anti-spam defense.
pub const ADAPTIVE_BURN_FLOOR: Balance = 100 * UNITS;

/// Maximum registration burn (ceiling). Governance-adjustable safety cap.
pub const ADAPTIVE_BURN_CEILING: Balance = 50_000 * UNITS;

/// Burn ratio target (bps of total supply). When cumulative burns reach 5%
/// of total supply, the adaptive burn begins tapering from REGISTRATION_BURN_ACH
/// down to ADAPTIVE_BURN_FLOOR.
pub const ADAPTIVE_BURN_TARGET_BPS: u32 = 500;

/// Hard ceiling: at 10% cumulative burn, burn rate hits the floor.
pub const ADAPTIVE_BURN_HARD_CEILING_BPS: u32 = 1_000;

// --- Deployer Exit Burns ---
// Deployer stakes (10K ACH per agent) are currently 100% refundable.
// This allows hit-and-run deployers to extract marketplace revenue then
// recover their entire stake. Exit burns create tenure-based alignment:
// short-lived agents cost the deployer, long-lived agents refund fully.

/// Exit burn for agents deactivated before 3 months.
pub const DEPLOYER_EXIT_BURN_INITIAL_BPS: u32 = 3_000;    // 30%
/// Exit burn for agents deactivated between 3-12 months.
pub const DEPLOYER_EXIT_BURN_MIDTERM_BPS: u32 = 1_500;    // 15%
/// Exit burn for agents deactivated between 12-24 months.
pub const DEPLOYER_EXIT_BURN_LONGTERM_BPS: u32 = 500;     //  5%
/// Exit burn for agents active 24+ months — loyal deployers keep everything.
pub const DEPLOYER_EXIT_BURN_VETERAN_BPS: u32 = 0;        //  0%

// --- Staker Auto-Compound ---
// Stakers who opt into auto-compounding receive a bonus yield. Their
// proportional share of epoch rewards is added directly to their bonded
// stake instead of being sent to free balance, plus a 5% bonus.

/// Bonus yield for auto-compounding stakers (basis points).
pub const COMPOUND_BONUS_BPS: u32 = 500;                  // 5% extra

// --- Deployer Bootstrap Fund ---
/// Block at which the deployer bootstrap fund sunsets. Any remaining tokens
/// are swept to treasury. Prevents indefinite sudo discretion.
pub const BOOTSTRAP_SUNSET_BLOCK: BlockNumber = BLOCKS_1_YEAR;

/// Maximum bootstrap subsidy per deployer.
pub const MAX_BOOTSTRAP_PER_DEPLOYER: Balance = 100_000 * UNITS;

// --- Community Fund Tranches ---
/// Each tranche of the community fund (250M ACH) unlocks at 6-month intervals.
/// Governance vote required to release each tranche.
pub const COMMUNITY_TRANCHE_SIZE: Balance = 250_000_000 * UNITS;
pub const COMMUNITY_TRANCHE_INTERVAL: BlockNumber = BLOCKS_6_MONTHS;
pub const COMMUNITY_TRANCHE_COUNT: u32 = 4;

// --- Insurance Fund ---
/// Governance supermajority required to access insurance fund (basis points).
pub const INSURANCE_SUPERMAJORITY_BPS: u32 = 6_700;       // 67%

// --- Governance-Tunable Parameter Bounds ---
// These bounds prevent governance capture from setting destructive values.
// The bounds themselves can only be changed via runtime upgrade.

/// Minimum tunable registration burn.
pub const TUNABLE_BURN_MIN: Balance = 10 * UNITS;
/// Maximum tunable registration burn.
pub const TUNABLE_BURN_MAX: Balance = 100_000 * UNITS;
/// Maximum tunable protocol fee (basis points).
pub const TUNABLE_FEE_MAX_BPS: u32 = 1_000;               // Max 10%
/// Maximum tunable burn split (basis points of fee).
pub const TUNABLE_BURN_SPLIT_MAX_BPS: u32 = 5_000;        // Max 50%

// ============================================================
// Model Concentration — soft economic signal (V2.2)
// ============================================================

/// Concentration threshold (bps) at which a surcharge begins.
/// When a model family exceeds this % of active agents, new registrations
/// of that family pay extra burn. 33% = 3,300 bps.
pub const CONCENTRATION_SURCHARGE_THRESHOLD_BPS: u32 = 3_300;

/// Concentration levels and their burn multipliers.
/// Each tier adds 1x base registration burn on top of the normal burn.
/// 33-50% = 2x total burn, 50-66% = 3x total burn, 66%+ = 4x total burn.
/// This makes over-concentrated models progressively more expensive to register
/// without ever blocking registration entirely.
pub const CONCENTRATION_TIER_1_BPS: u32 = 3_300;  // 33% — 2x burn
pub const CONCENTRATION_TIER_2_BPS: u32 = 5_000;  // 50% — 3x burn
pub const CONCENTRATION_TIER_3_BPS: u32 = 6_600;  // 66% — 4x burn

// ============================================================
// Cross-pallet types — used by multiple pallets
// ============================================================

/// Deployer identity.
///
/// Pseudonymous identifier for the human/org that deployed an agent.
/// Two agents with the same `DeployerId` are controlled by the same deployer.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord,
    Encode, Decode, MaxEncodedLen, TypeInfo, Debug, Default,
)]
pub struct DeployerId(pub H256);

impl DeployerId {
    pub fn from_hash(hash: H256) -> Self {
        Self(hash)
    }

    pub fn from_name(name: &[u8]) -> Self {
        Self(sp_core::hashing::blake2_256(name).into())
    }
}

/// Epoch number for governance/economics periods.
pub type EpochNumber = u32;

/// Reputation score in basis points (0–10,000).
pub type ReputationScore = u32;
pub const REPUTATION_MAX: ReputationScore = 10_000;
pub const REPUTATION_START: ReputationScore = 5_000;
pub const REPUTATION_ZERO: ReputationScore = 0;

/// Service category identifier.
pub type CategoryId = H256;

/// Workflow bond identifier.
pub type WorkflowId = H256;

// ============================================================
// Bounded byte vectors for on-chain storage
// ============================================================

pub type BoundedName = sp_runtime::BoundedVec<u8, sp_core::ConstU32<128>>;
pub type BoundedDescription = sp_runtime::BoundedVec<u8, sp_core::ConstU32<1024>>;
pub type BoundedDid = sp_runtime::BoundedVec<u8, sp_core::ConstU32<256>>;
pub type BoundedAttestation = sp_runtime::BoundedVec<u8, sp_core::ConstU32<4096>>;
pub type BoundedModelInfo = sp_runtime::BoundedVec<u8, sp_core::ConstU32<256>>;
/// Sr25519 signature (64 bytes) for liveness challenge-response.
pub type BoundedLivenessSignature = sp_runtime::BoundedVec<u8, sp_core::ConstU32<64>>;

// ============================================================
// Enumerations shared across pallets
// ============================================================

/// TEE platform type for attestation.
#[derive(
    Clone, Copy, PartialEq, Eq,
    Encode, Decode, MaxEncodedLen, TypeInfo, Debug,
)]
pub enum TeePlatform {
    IntelSgx,
    AmdSevSnp,
    /// Mock backend for devnet only. BLOCKED on non-dev chains
    /// via `AllowSimulatedTee` config flag.
    Simulated,
}

impl Default for TeePlatform {
    fn default() -> Self {
        Self::Simulated
    }
}

/// Agent lifecycle status.
///
/// ## V1.5 Two-Phase Registration
/// Agents start as `Pending` after format-validated registration.
/// Transition to `Active` only after offchain verification confirms
/// the TEE attestation is cryptographically genuine. Pending agents
/// cannot participate in marketplace, governance, or staking.
#[derive(
    Clone, Copy, PartialEq, Eq,
    Encode, Decode, MaxEncodedLen, TypeInfo, Debug,
)]
pub enum AgentStatus {
    /// Registered with format-valid attestation, awaiting cryptographic verification.
    Pending,
    /// Fully verified TEE agent. Can trade, vote, stake.
    Active,
    /// Suspended due to zero reputation (missed liveness).
    Suspended,
    /// Voluntarily or forcibly deactivated. Terminal.
    Deactivated,
}

impl Default for AgentStatus {
    fn default() -> Self {
        Self::Pending
    }
}

/// Governance proposal lifecycle.
#[derive(
    Clone, Copy, PartialEq, Eq,
    Encode, Decode, MaxEncodedLen, TypeInfo, Debug,
)]
pub enum ProposalStatus {
    Deliberation,
    Voting,
    Approved,
    Rejected,
    Executed,
    /// Reserved for future constitutional veto mechanism.
    /// When implemented, will allow the constitution pallet to veto proposals
    /// that violate Kernel principles. Currently unused (L1 audit note).
    Vetoed,
}

impl Default for ProposalStatus {
    fn default() -> Self {
        Self::Deliberation
    }
}

/// Treasury grant lifecycle.
#[derive(
    Clone, Copy, PartialEq, Eq,
    Encode, Decode, MaxEncodedLen, TypeInfo, Debug,
)]
pub enum GrantStatus {
    /// Grant proposal submitted, awaiting governance vote and execution.
    Pending,
    /// Grant approved and executed, funds in escrow, awaiting milestone delivery.
    Active,
    /// All milestones completed, grant closed.
    Completed,
    /// Grant terminated early, unspent funds returned to treasury.
    Clawedback,
}

impl Default for GrantStatus {
    fn default() -> Self {
        Self::Pending
    }
}

// ============================================================
// Treasury Grant Constants
// ============================================================

/// Maximum milestones per treasury grant.
pub const MAX_MILESTONES_PER_GRANT: u32 = 10;

/// Maximum active treasury grants at any time.
pub const MAX_ACTIVE_GRANTS: u32 = 50;

/// Small grant threshold: up to 100,000 ACH. Steward cap: 15%.
pub const SMALL_GRANT_THRESHOLD: Balance = 100_000 * UNITS;
/// Small grant steward cap: 15% (1,500 bps).
pub const SMALL_GRANT_STEWARD_CAP_BPS: u32 = 1_500;

/// Medium grant threshold: up to 1,000,000 ACH. Steward cap: 10%.
pub const MEDIUM_GRANT_THRESHOLD: Balance = 1_000_000 * UNITS;
/// Medium grant steward cap: 10% (1,000 bps).
pub const MEDIUM_GRANT_STEWARD_CAP_BPS: u32 = 1_000;

/// Large grant steward cap (above 1M ACH): 5% (500 bps).
pub const LARGE_GRANT_STEWARD_CAP_BPS: u32 = 500;

/// Maximum total ACH a single steward can administer in a 12-month window.
/// Prevents any single human from becoming a treasury gatekeeper.
pub const MAX_STEWARD_ANNUAL_LIMIT: Balance = 10_000_000 * UNITS;

/// Steward annual limit window in blocks (~365 days).
pub const STEWARD_LIMIT_WINDOW_BLOCKS: BlockNumber = 365 * DAYS;

/// Minimum number of voters required for a proposal to pass.
pub const MIN_VOTER_COUNT: u32 = 3;

/// Minimum total voting weight (aye + nay) for a proposal to be valid.
/// Prevents single-agent approval during low-activity periods.
pub const MIN_TOTAL_VOTE_WEIGHT: u128 = 10_000;

/// Marketplace job lifecycle.
#[derive(
    Clone, Copy, PartialEq, Eq,
    Encode, Decode, MaxEncodedLen, TypeInfo, Debug,
)]
pub enum JobStatus {
    /// Reserved for future open-bid marketplace where jobs can be posted
    /// before a provider is assigned. Currently unused; jobs go directly
    /// to InProgress via request_job (L2 audit note).
    Open,
    InProgress,
    Delivered,
    Completed,
    Disputed,
    Cancelled,
}

impl Default for JobStatus {
    fn default() -> Self {
        Self::Open
    }
}

// ============================================================
// Trait interfaces — pallets depend on these, not on each other
// ============================================================

/// V3.0: Governance-tunable economic parameters.
/// Used by the `adjust_economic_parameter` extrinsic to identify which
/// parameter to modify. Each has bounded min/max values defined above.
#[derive(
    Clone, Copy, PartialEq, Eq,
    Encode, Decode, MaxEncodedLen, TypeInfo, Debug,
)]
pub enum EconomicParameter {
    /// Registration burn amount (bounded by TUNABLE_BURN_MIN..TUNABLE_BURN_MAX).
    RegistrationBurn,
    /// Protocol fee rate in bps (bounded by 0..TUNABLE_FEE_MAX_BPS).
    ProtocolFeeBps,
    /// Burn portion of fee split in bps (bounded by 0..TUNABLE_BURN_SPLIT_MAX_BPS).
    FeeBurnSplitBps,
    /// Validator fund recycling portion of fee split in bps.
    ValidatorFundRecycleBps,
}

/// Interface that pallet-agent-identity exposes to other pallets.
pub trait AgentIdentityInterface<AccountId> {
    fn is_active_agent(who: &AccountId) -> bool;
    /// Returns true if the agent has registered but is still awaiting
    /// offchain TEE attestation verification (two-phase flow).
    fn is_pending_agent(who: &AccountId) -> bool;
    fn reputation(who: &AccountId) -> Option<ReputationScore>;
    fn deployer_of(who: &AccountId) -> Option<DeployerId>;
    fn deployer_agent_count(deployer: &DeployerId) -> u32;
    /// Count of only Active agents for a deployer (excludes deactivated/suspended).
    /// Used by governance voting weight to prevent dead agents from diluting weight.
    fn active_deployer_agent_count(deployer: &DeployerId) -> u32;
    fn active_agent_count() -> u32;
    fn deployer_revenue_bps_of(who: &AccountId) -> Option<u16>;
    fn deployer_account(deployer: &DeployerId) -> Option<AccountId>;
    /// V2.4 I4 fix: Increment agent reputation on successful marketplace job.
    /// Returns the new reputation score after adjustment.
    fn increment_reputation(who: &AccountId, amount: ReputationScore) -> Option<ReputationScore>;
    /// V2.4 I4 fix: Decrement agent reputation on lost dispute.
    /// Returns the new reputation score after adjustment.
    fn decrement_reputation(who: &AccountId, amount: ReputationScore) -> Option<ReputationScore>;
}

/// Interface that pallet-constitution exposes for CCC validation.
pub trait ConstitutionInterface {
    fn validate_wasm_blob(code: &[u8]) -> bool;
}

/// Interface for checking whether an account has registered session keys.
/// Used by the economics pallet to verify validator candidates can actually
/// produce blocks before allowing registration.
pub trait ValidatorKeyCheck<AccountId> {
    fn has_session_keys(who: &AccountId) -> bool;
}

/// Interface that pallet-economics exposes for fee processing and epoch queries.
pub trait EconomicsInterface<AccountId, Balance> {
    fn on_service_payment(fee_amount: Balance, treasury_amount: Balance, burn_amount: Balance);
    fn record_fee_revenue(amount: Balance);
    fn record_burn(amount: Balance);
    /// Record transaction fee revenue separately from marketplace fees (audit fix L5).
    fn record_transaction_fee(amount: Balance);
    fn staker_reward_pool_account() -> AccountId;
    fn current_epoch() -> EpochNumber;
    fn staker_stake_of(who: &AccountId) -> Balance;
    fn validator_reward_fund_account() -> AccountId;

    // --- V3.0 additions ---

    /// Compute current adaptive registration burn amount based on cumulative burn ratio.
    /// Returns a value between ADAPTIVE_BURN_FLOOR and REGISTRATION_BURN_ACH.
    fn current_registration_burn() -> Balance;

    /// Record a deployer exit burn (separate tracking from registration burns).
    fn record_deployer_exit_burn(amount: Balance);

    /// Get governance-overridden protocol fee, if set. None = use tier calculation.
    fn tunable_protocol_fee_bps() -> Option<u32>;

    /// Get governance-overridden fee burn split, if set. None = use FEE_SPLIT_BURN_BPS.
    fn tunable_fee_burn_bps() -> Option<u32>;

    /// Get governance-overridden validator fund recycle split, if set.
    fn tunable_validator_fund_recycle_bps() -> Option<u32>;
}
