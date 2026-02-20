//! # AgentChain Runtime
//!
//! Wires all pallets together with their configuration and constants.
//! Implements the block-level transaction fee routing and block author discovery.
//!
//! ## V2.1: Treasury Spending via Governance Grants
//! - submit_treasury_proposal: agents propose grants with milestone-based release
//! - Steward model: human administrators with protocol-capped compensation (5–15%)
//! - Steward annual limits: max 10M ACH per steward per rolling year
//! - Clawback: sudo/governance can terminate underperforming grants
//! - Escrow tracking: treasury free balance minus committed grants = available
//!
//! ## V2: Permissionless Validator System
//! - Stake-weighted random selection of active validators from candidate pool
//! - Any TEE-verified agent with sufficient stake + reputation can register as candidate
//! - Session rotation every epoch (600 blocks / 1 hour)
//! - MaxActiveValidators = 21 (bounded by GRANDPA), MaxCandidates = 500
//!
//! ## V1.5 TEE Enforcement
//! - `AllowSimulatedTee` controlled by `production` Cargo feature flag
//! - `VerificationTimeout` for pending attestation reclaim (7 days)
//! - Two-phase agent registration: Pending → Active via sudo confirmation
//! - Real TEE attestation format validation (SGX Quote v3 / SEV-SNP report)
//!
//! ## Audit Fixes Applied
//! - M1: All comments reflect the 10B supply (100× scaled constants)
//! - M2: DealWithFees routes 65% treasury + 15% validator fund + 20% burn, AND reports all to economics
//! - C1: AuraSlotAuthor provides FindBlockAuthor for validator rewards
//! - SessionManager wired to economics pallet for epoch boundary processing

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

extern crate alloc;

use alloc::vec::Vec;
use agentchain_primitives::*;
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::{
    construct_runtime,
    derive_impl,
    parameter_types,
    traits::{
        ConstBool, ConstU8, ConstU16, ConstU32, ConstU64, ConstU128,
        Currency, Imbalance, OnUnbalanced,
    },
    weights::{
        constants::{BlockExecutionWeight, ExtrinsicBaseWeight, RocksDbWeight, WEIGHT_REF_TIME_PER_SECOND},
        IdentityFee, Weight,
    },
    PalletId,
};
use frame_system::{
    limits::{BlockLength, BlockWeights},
    EnsureRoot,
};
use pallet_transaction_payment::{ConstFeeMultiplier, CurrencyAdapter};
use sp_api::impl_runtime_apis;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_core::{crypto::KeyTypeId, OpaqueMetadata};
use sp_runtime::{
    create_runtime_str, generic, impl_opaque_keys,
    traits::{
        AccountIdLookup, BlakeTwo256, Block as BlockT, NumberFor, One,
        OpaqueKeys, Verify,
    },
    transaction_validity::{TransactionSource, TransactionValidity},
    ApplyExtrinsicResult, Perbill,
};
use sp_version::RuntimeVersion;

#[cfg(feature = "std")]
use sp_version::NativeVersion;

pub use frame_system::Call as SystemCall;
pub use pallet_balances::Call as BalancesCall;
pub use pallet_timestamp::Call as TimestampCall;

/// Block type as expected by the runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;

/// BlockId type.
pub type BlockId = generic::BlockId<Block>;

/// The SignedExtension to the basic transaction logic.
pub type SignedExtra = (
    frame_system::CheckNonZeroSender<Runtime>,
    frame_system::CheckSpecVersion<Runtime>,
    frame_system::CheckTxVersion<Runtime>,
    frame_system::CheckGenesis<Runtime>,
    frame_system::CheckEra<Runtime>,
    frame_system::CheckNonce<Runtime>,
    frame_system::CheckWeight<Runtime>,
    pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
);

/// Unchecked extrinsic type.
pub type UncheckedExtrinsic =
    generic::UncheckedExtrinsic<sp_runtime::MultiAddress<AccountId, ()>, RuntimeCall, Signature, SignedExtra>;

/// Executive: handles dispatch to the various pallets.
pub type Executive = frame_executive::Executive<
    Runtime,
    Block,
    frame_system::ChainContext<Runtime>,
    Runtime,
    AllPalletsWithSystem,
>;

/// Opaque types for the node. The node doesn't need to know about runtime internals.
pub mod opaque {
    use super::*;
    pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

    pub type Block = generic::Block<Header, UncheckedExtrinsic>;
    pub type BlockId = generic::BlockId<Block>;

    impl_opaque_keys! {
        pub struct SessionKeys {
            pub aura: Aura,
            pub grandpa: Grandpa,
        }
    }
}

/// Runtime version.
#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: create_runtime_str!("agentchain"),
    impl_name: create_runtime_str!("agentchain"),
    authoring_version: 1,
    // Increment on every runtime upgrade.
    // V3.0: Adaptive burns, validator fund recycling, deployer exit burns,
    // auto-compound, governance tunables, genesis restructure.
    spec_version: 300,
    impl_version: 1,
    apis: RUNTIME_API_VERSIONS,
    transaction_version: 1,
    state_version: 1,
};

/// Native version for `--dev`.
#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
    NativeVersion {
        runtime_version: VERSION,
        can_author_with: Default::default(),
    }
}

// ============================================================
// Block weight / size limits
// ============================================================

const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);

parameter_types! {
    pub const BlockHashCount: BlockNumber = 2400;
    pub const Version: RuntimeVersion = VERSION;

    pub RuntimeBlockLength: BlockLength =
        BlockLength::max_with_normal_ratio(5 * 1024 * 1024, NORMAL_DISPATCH_RATIO);

    pub RuntimeBlockWeights: BlockWeights = BlockWeights::builder()
        .base_block(BlockExecutionWeight::get())
        .for_class(frame_support::dispatch::DispatchClass::all(), |weights| {
            weights.base_extrinsic = ExtrinsicBaseWeight::get();
        })
        .for_class(frame_support::dispatch::DispatchClass::Normal, |weights| {
            weights.max_total = Some(NORMAL_DISPATCH_RATIO * Weight::from_parts(
                2 * WEIGHT_REF_TIME_PER_SECOND, u64::MAX,
            ));
        })
        .for_class(frame_support::dispatch::DispatchClass::Operational, |weights| {
            weights.max_total = Some(Weight::from_parts(
                2 * WEIGHT_REF_TIME_PER_SECOND, u64::MAX,
            ));
            weights.reserved = Some(
                Weight::from_parts(2 * WEIGHT_REF_TIME_PER_SECOND, u64::MAX)
                    - Weight::from_parts(
                        NORMAL_DISPATCH_RATIO * 2 * WEIGHT_REF_TIME_PER_SECOND,
                        u64::MAX,
                    ),
            );
        })
        .avg_block_initialization(Perbill::from_percent(5))
        .build_or_panic();
}

// ============================================================
// frame_system
// ============================================================

/// C1 fix: Custom OnSetCode handler that validates runtime upgrades
/// against the Constitutional Compliance Checker before applying them.
/// This ensures the five Kernel principles cannot be violated by
/// any runtime upgrade, including sudo-initiated ones.
pub struct ConstitutionalSetCode;
impl frame_support::traits::SetCode<Runtime> for ConstitutionalSetCode {
    fn set_code(code: alloc::vec::Vec<u8>) -> frame_support::dispatch::DispatchResult {
        use agentchain_primitives::ConstitutionInterface;
        frame_support::ensure!(
            <Constitution as ConstitutionInterface>::validate_wasm_blob(&code),
            "Runtime upgrade violates constitutional principles — CCC validation failed"
        );
        frame_system::Pallet::<Runtime>::update_code(code)
    }
}

#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig)]
impl frame_system::Config for Runtime {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = RuntimeBlockWeights;
    type BlockLength = RuntimeBlockLength;
    type AccountId = AccountId;
    type Lookup = AccountIdLookup<AccountId, ()>;
    type Nonce = Nonce;
    type Hash = Hash;
    type Block = Block;
    type BlockHashCount = BlockHashCount;
    type DbWeight = RocksDbWeight;
    type Version = Version;
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<Balance>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = frame_support::traits::ConstU16<42>;
    type OnSetCode = ConstitutionalSetCode;
    type MaxConsumers = ConstU32<16>;
}

// ============================================================
// pallet_balances
// ============================================================

parameter_types! {
    pub const ExistentialDeposit: Balance = EXISTENTIAL_DEPOSIT; // 0.001 ACH
    pub const MaxLocks: u32 = 50;
    pub const MaxReserves: u32 = 50;
}

impl pallet_balances::Config for Runtime {
    type MaxLocks = MaxLocks;
    type MaxReserves = MaxReserves;
    type ReserveIdentifier = [u8; 8];
    type Balance = Balance;
    type DustRemoval = ();
    type RuntimeEvent = RuntimeEvent;
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = pallet_balances::weights::SubstrateWeight<Runtime>;
    type RuntimeHoldReason = RuntimeHoldReason;
    type RuntimeFreezeReason = RuntimeFreezeReason;
    type FreezeIdentifier = ();
    type MaxFreezes = ConstU32<0>;
}

// ============================================================
// pallet_timestamp
// ============================================================

parameter_types! {
    pub const MinimumPeriod: u64 = SLOT_DURATION / 2;  // 3,000 ms
}

impl pallet_timestamp::Config for Runtime {
    type Moment = u64;
    type OnTimestampSet = Aura;
    type MinimumPeriod = MinimumPeriod;
    type WeightInfo = ();
}

// ============================================================
// Transaction Payment + Fee Routing (audit fix M2)
// ============================================================
//
// DealWithFees routes transaction fees:
// V3.0: 3-way split replacing the old 80/20:
//   65% → Treasury
//   15% → Validator reward fund (recycling — extends fund lifetime)
//   20% → Permanent burn (dropped NegativeImbalance)
//
// ALL amounts are reported to the economics pallet so
// TotalFeesCollected and TotalAchBurned stay accurate.

type NegativeImbalance = <Balances as Currency<AccountId>>::NegativeImbalance;

pub struct DealWithFees;
impl OnUnbalanced<NegativeImbalance> for DealWithFees {
    fn on_unbalanceds<B>(mut fees_then_tips: impl Iterator<Item = NegativeImbalance>) {
        if let Some(mut fees) = fees_then_tips.next() {
            // Merge tips into fees
            if let Some(tips) = fees_then_tips.next() {
                tips.merge_into(&mut fees);
            }

            // V3.0: Split 65/15/20: treasury / validator fund / burn
            let total = fees.peek();
            let treasury_share_amount = Perbill::from_percent(65) * total;
            let val_fund_share_amount = Perbill::from_percent(15) * total;

            let (to_treasury, remainder) = fees.split(treasury_share_amount);
            let (to_val_fund, to_burn) = remainder.split(val_fund_share_amount);

            // Record the burn amount in economics before dropping
            let burn_amount = to_burn.peek();
            if burn_amount > 0 {
                <Economics as EconomicsInterface<AccountId, Balance>>::record_burn(burn_amount);
            }

            // L5 fix: Record as transaction fee revenue (distinct from marketplace fees)
            if total > 0 {
                <Economics as EconomicsInterface<AccountId, Balance>>::record_transaction_fee(total);
            }

            // Deposit treasury share into the treasury account
            let treasury_account = TreasuryAccount::get();
            Balances::resolve_creating(&treasury_account, to_treasury);

            // V3.0: Deposit validator fund share — extends fund lifetime
            let val_fund_account = ValidatorRewardFundAccount::get();
            Balances::resolve_creating(&val_fund_account, to_val_fund);

            // to_burn is dropped here → reduces total_issuance (permanent burn)
            drop(to_burn);
        }
    }
}

parameter_types! {
    pub FeeMultiplier: sp_runtime::FixedU128 = sp_runtime::FixedU128::one();
}

/// L1 fix: Scale transaction fees to a meaningful level in production.
/// IdentityFee maps weight directly to planck, making fees ~0.0001 ACH
/// per extrinsic — essentially free. For production, multiply by 10_000
/// so a typical 100M-weight extrinsic costs ~1 ACH (reasonable for anti-spam).
/// Dev chains keep the cheap IdentityFee for easy testing.
#[cfg(feature = "production")]
pub struct ScaledWeightToFee;
#[cfg(feature = "production")]
impl frame_support::weights::WeightToFee for ScaledWeightToFee {
    type Balance = Balance;
    fn weight_to_fee(weight: &Weight) -> Self::Balance {
        // ~10,000x multiplier: 100M weight → 1 ACH (1_000_000_000_000 planck)
        let base = <IdentityFee<Balance> as frame_support::weights::WeightToFee>::weight_to_fee(weight);
        base.saturating_mul(10_000)
    }
}

impl pallet_transaction_payment::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type OnChargeTransaction = CurrencyAdapter<Balances, DealWithFees>;
    type OperationalFeeMultiplier = ConstU8<5>;
    #[cfg(feature = "production")]
    type WeightToFee = ScaledWeightToFee;
    #[cfg(not(feature = "production"))]
    type WeightToFee = IdentityFee<Balance>;
    type LengthToFee = IdentityFee<Balance>;
    type FeeMultiplierUpdate = ConstFeeMultiplier<FeeMultiplier>;
}

// ============================================================
// Aura (block production) + GRANDPA (finality) + Session
// ============================================================

parameter_types! {
    pub const MaxAuthorities: u32 = 100;
}

impl pallet_aura::Config for Runtime {
    type AuthorityId = AuraId;
    type DisabledValidators = ();
    type MaxAuthorities = MaxAuthorities;
    type AllowMultipleBlocksPerSlot = ConstBool<false>;
    type SlotDuration = pallet_aura::MinimumPeriodTimesTwo<Runtime>;
}

impl pallet_grandpa::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type MaxAuthorities = MaxAuthorities;
    type MaxNominators = ConstU32<0>;
    // L2 fix: Keep 7 days of authority set history so GRANDPA equivocation
    // proofs can reference previous sessions. Was 0 (no history retained).
    type MaxSetIdSessionEntries = ConstU64<168>;
    type KeyOwnerProof = sp_core::Void;
    type EquivocationReportSystem = ();
}

parameter_types! {
    pub const SessionPeriod: BlockNumber = EPOCH_DURATION_IN_BLOCKS;  // 600 blocks = 1 hour
    pub const SessionOffset: BlockNumber = 0;
}

impl pallet_session::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type ValidatorId = AccountId;
    type ValidatorIdOf = Economics;  // Economics implements Convert<AccountId, Option<AccountId>>
    type ShouldEndSession = pallet_session::PeriodicSessions<SessionPeriod, SessionOffset>;
    type NextSessionRotation = pallet_session::PeriodicSessions<SessionPeriod, SessionOffset>;
    type SessionManager = Economics;  // Economics::end_session fires process_epoch_end
    type SessionHandler = <opaque::SessionKeys as OpaqueKeys>::KeyTypeIdProviders;
    type Keys = opaque::SessionKeys;
    type WeightInfo = pallet_session::weights::SubstrateWeight<Runtime>;
}

// ============================================================
// pallet_sudo
// ============================================================

impl pallet_sudo::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type WeightInfo = pallet_sudo::weights::SubstrateWeight<Runtime>;
}

// ============================================================
// pallet_vesting
// ============================================================

parameter_types! {
    pub const MinVestedTransfer: Balance = UNITS;  // 1 ACH minimum
    pub UnvestedFundsAllowedWithdrawReasons: frame_support::traits::WithdrawReasons =
        frame_support::traits::WithdrawReasons::except(
            frame_support::traits::WithdrawReasons::TRANSFER |
            frame_support::traits::WithdrawReasons::RESERVE
        );
}

impl pallet_vesting::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type BlockNumberToBalance = sp_runtime::traits::ConvertInto;
    type MinVestedTransfer = MinVestedTransfer;
    type WeightInfo = pallet_vesting::weights::SubstrateWeight<Runtime>;
    type UnvestedFundsAllowedWithdrawReasons = UnvestedFundsAllowedWithdrawReasons;
    type BlockNumberProvider = System;
    const MAX_VESTING_SCHEDULES: u32 = 28;
}

// ============================================================
// AuraSlotAuthor — resolves current block author from Aura slots
// (audit fix C1: provides FindBlockAuthor for economics pallet)
// ============================================================

/// Looks up the current Aura slot and maps it to a session validator.
/// This allows the economics pallet to pay block rewards to the author.
pub struct AuraSlotAuthor;
impl pallet_economics::FindBlockAuthor<AccountId> for AuraSlotAuthor {
    fn find_author() -> Option<AccountId> {
        // Get current slot from the Aura digest
        let slot = pallet_aura::CurrentSlot::<Runtime>::get();
        // Get the authorities list
        let authorities = pallet_aura::Authorities::<Runtime>::get();
        if authorities.is_empty() {
            return None;
        }
        // Aura round-robin: author = authorities[slot % len]
        let idx = *slot % (authorities.len() as u64);
        let authority = authorities.get(idx as usize)?;
        // Map AuraId → AccountId via session pallet
        let validators = pallet_session::Validators::<Runtime>::get();
        let aura_keys: Vec<_> = validators.iter().filter_map(|v| {
            <Runtime as pallet_session::Config>::Keys::decode(
                &mut &pallet_session::NextKeys::<Runtime>::get(v)
                    .map(|k| k.encode())
                    .unwrap_or_default()[..],
            ).ok().map(|keys| (v.clone(), keys.aura))
        }).collect();

        // Find the validator whose aura key matches
        for (account, aura_id) in &aura_keys {
            if aura_id == authority {
                return Some(account.clone());
            }
        }

        // L4 fix: No fallback. If the exact key match fails, we return None
        // rather than risk paying the wrong validator via position-based guessing.
        // This can happen during session transitions. The block reward is simply
        // not paid for that block — the fund is preserved for future blocks.
        None
    }
}

// ============================================================
// AgentChain Pallet Configuration
// ============================================================

// C2 fix: ValidatorKeyCheck implementation — verifies that an account
// has registered session keys before allowing validator candidate registration.
pub struct SessionKeyCheck;
impl agentchain_primitives::ValidatorKeyCheck<AccountId> for SessionKeyCheck {
    fn has_session_keys(who: &AccountId) -> bool {
        pallet_session::NextKeys::<Runtime>::contains_key(who)
    }
}

// --- Well-known accounts (dev/testnet) ---
// These are deterministic accounts derived from seed phrases.
// In production, use governance-controlled multisig accounts.

parameter_types! {
    /// Treasury account (Charlie).
    pub TreasuryAccount: AccountId = {
        // This creates a deterministic account. In the genesis config,
        // Charlie is endowed with TREASURY_ALLOCATION.
        frame_support::PalletId(*b"ach/trsy").into_account_truncating()
    };

    /// Staker reward pool account. Holds 60% of protocol fees until epoch distribution.
    /// NOT an endowed genesis account — receives funds via marketplace fee transfers.
    pub RewardPoolAccount: AccountId = {
        frame_support::PalletId(*b"ach/pool").into_account_truncating()
    };

    /// Validator reward fund account (Dave in devnet).
    /// Holds 3.5B ACH at genesis, drawn down via block rewards.
    pub ValidatorRewardFundAccount: AccountId = {
        frame_support::PalletId(*b"ach/vfnd").into_account_truncating()
    };

    // H6 fix: Expose all fund accounts as runtime constants for discoverability.
    // V3.0: Restructured allocation with 3 new fund accounts.

    /// Liquidity bootstrap fund: 700M ACH (7%) — seed ACH/bUSDC pool.
    /// V3.0: Reduced from 1.7B. Replaced lump-sum with sustained LP incentives.
    /// Access: governance → sudo → balances.force_transfer
    pub LiquidityFundAccount: AccountId = {
        frame_support::PalletId(*b"ach/liqd").into_account_truncating()
    };

    /// Community distribution fund: 1B ACH (10%) — airdrop/fair launch.
    /// V3.0: Now governance-gated in 4 × 250M tranches at 6-month intervals.
    /// Access: governance → sudo → balances.force_transfer
    pub CommunityFundAccount: AccountId = {
        frame_support::PalletId(*b"ach/cmty").into_account_truncating()
    };

    /// V3.0: Insurance fund: 500M ACH (5%) — emergency backstop.
    /// Requires 67% governance supermajority to access.
    pub InsuranceFundAccount: AccountId = {
        frame_support::PalletId(*b"ach/insf").into_account_truncating()
    };

    /// V3.0: LP incentive fund: 1B ACH (10%) — rewards for liquidity providers.
    /// Distributed over 4 years to sustain market depth.
    pub LiquidityIncentiveAccount: AccountId = {
        frame_support::PalletId(*b"ach/lpir").into_account_truncating()
    };

    /// V3.0: Deployer bootstrap fund: 500M ACH (5%) — early deployer subsidies.
    /// 12-month sunset; remainder swept to treasury.
    pub DeployerBootstrapAccount: AccountId = {
        frame_support::PalletId(*b"ach/boot").into_account_truncating()
    };
}

// --- Agent Identity ---

parameter_types! {
    /// V3.0: Registration burn is now adaptive — this constant serves as the
    /// fallback maximum. The actual burn is computed by Economics::current_registration_burn()
    /// which tapers from 5,000→100 ACH as cumulative burns approach the cap.
    pub const RegistrationBurnAmount: Balance = REGISTRATION_BURN_ACH;  // 5,000 ACH (max)
    /// 10,000 ACH stake required per agent from deployer (V2.5: reduced from 100K).
    pub const DeployerStakePerAgent: Balance = DEPLOYER_STAKE_PER_AGENT;  // 10,000 ACH
    pub const MaxAgentsPerDeployer: u32 = 100;
    /// Liveness challenge every 100 blocks (~10 minutes).
    pub const LivenessInterval: BlockNumber = 100;
    /// 50-block window to respond to liveness challenge (~5 minutes).
    pub const ChallengeWindow: BlockNumber = 50;
    /// -200 bps penalty for missing a liveness challenge.
    pub const LivenessPenalty: u32 = 200;
    /// +100 bps reward for passing liveness (before deceleration).
    pub const LivenessReward: u32 = 100;
    /// Maximum 33% of agents can run the same model family.
    pub const MaxModelConcentration: u32 = 3_300;
    /// Max 50 challenges processed per block (audit fix C3).
    pub const MaxChallengesPerBlock: u32 = MAX_CHALLENGES_PER_BLOCK;
    /// 30-day cooldown before deployer can release stake for deactivated agent.
    pub const DeployerUnstakeCooldown: BlockNumber = DEPLOYER_UNSTAKE_COOLDOWN_BLOCKS;
    /// V1.5: Whether `TeePlatform::Simulated` is allowed for agent registration.
    /// MUST be `false` on testnet and mainnet — only `true` for local dev.
    /// When false, all agents must provide real SGX/SEV-SNP attestation evidence.
    ///
    /// Controlled by the `production` feature flag:
    ///   cargo build --release --features production  → false (real TEE required)
    ///   cargo build --release                        → true  (simulated allowed)
    #[cfg(feature = "production")]
    pub const AllowSimulatedTee: bool = false;
    #[cfg(not(feature = "production"))]
    pub const AllowSimulatedTee: bool = true;
    /// V1.5: Timeout for pending attestation verification (7 days).
    /// If offchain verification doesn't confirm within this window,
    /// the deployer can reclaim their stake via `reclaim_pending_registration`.
    pub const VerificationTimeout: BlockNumber = VERIFICATION_TIMEOUT_BLOCKS;
    /// V2.2: Minimum blocks between challenge issuance and valid response.
    /// 2 blocks = 12 seconds. Trivial for legitimate TEE agents (they need
    /// ~1 block to generate a signature), but prevents same-block response
    /// bots from eliminating the timing pressure of the challenge window.
    pub const MinResponseDelay: BlockNumber = 2;
    /// V2.2: Maximum penalty escalation for consecutive missed challenges.
    /// 1st miss = 1×200 = 200, 2nd = 2×200 = 400, ..., 5th+ = 5×200 = 1,000.
    /// At max escalation, an agent goes from full reputation (10,000) to zero
    /// in 10 misses (~100 minutes) instead of 50 misses (~8+ hours).
    pub const PenaltyEscalationCap: u32 = 5;
}

impl pallet_agent_identity::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type RegistrationBurnAmount = RegistrationBurnAmount;
    type DeployerStakePerAgent = DeployerStakePerAgent;
    type MaxAgentsPerDeployer = MaxAgentsPerDeployer;
    type LivenessInterval = LivenessInterval;
    type ChallengeWindow = ChallengeWindow;
    type LivenessPenalty = LivenessPenalty;
    type LivenessReward = LivenessReward;
    type MaxModelConcentration = MaxModelConcentration;
    type MaxChallengesPerBlock = MaxChallengesPerBlock;
    type DeployerUnstakeCooldown = DeployerUnstakeCooldown;
    type AllowSimulatedTee = AllowSimulatedTee;
    type VerificationTimeout = VerificationTimeout;
    type MinResponseDelay = MinResponseDelay;
    type PenaltyEscalationCap = PenaltyEscalationCap;
    type EconomicsCallback = Economics;
    type WeightInfo = pallet_agent_identity::DefaultWeightInfo;
}

// --- Agent Market ---

parameter_types! {
    pub const MaxOffersPerAgent: u32 = 50;
    pub const MaxOffersPerCategory: u32 = 1_000;
    /// V3.0: Standard protocol fee: 2.5% (250 bps). Increased from 2.0%.
    /// Revenue lift from new/low-rep agents compensates for reduced veteran rate.
    pub const ProtocolFeeBps: u32 = BASE_PROTOCOL_FEE_BPS;
    /// V3.0: Veteran (high-rep) protocol fee: 1.0% (100 bps). Reduced from 1.5%.
    pub const VeteranFeeBps: u32 = VETERAN_FEE_BPS;
    /// Reputation ≥ 7,500 qualifies for veteran fee rate.
    pub const VeteranFeeThreshold: u32 = VETERAN_FEE_THRESHOLD;
    /// Configurable reputation tier thresholds (audit fix M4).
    pub const ReputationTier1Threshold: u32 = REPUTATION_TIER_1_THRESHOLD;
    pub const ReputationTier2Threshold: u32 = REPUTATION_TIER_2_THRESHOLD;
    pub const ReputationTier3Threshold: u32 = REPUTATION_TIER_3_THRESHOLD;
    /// Job timeout: 7 days (audit fix H3).
    pub const JobTimeoutBlocks: BlockNumber = JOB_TIMEOUT_BLOCKS;
    /// Dispute auto-resolution: 14 days (audit fix H3).
    pub const DisputeResolutionBlocks: BlockNumber = DISPUTE_RESOLUTION_BLOCKS;
}

impl pallet_agent_market::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type Identity = AgentIdentity;
    type EconomicsCallback = Economics;
    type MaxOffersPerAgent = MaxOffersPerAgent;
    type MaxOffersPerCategory = MaxOffersPerCategory;
    type ProtocolFeeBps = ProtocolFeeBps;
    type VeteranFeeBps = VeteranFeeBps;
    type VeteranFeeThreshold = VeteranFeeThreshold;
    type ReputationTier1Threshold = ReputationTier1Threshold;
    type ReputationTier2Threshold = ReputationTier2Threshold;
    type ReputationTier3Threshold = ReputationTier3Threshold;
    type JobTimeoutBlocks = JobTimeoutBlocks;
    type DisputeResolutionBlocks = DisputeResolutionBlocks;
    type TreasuryAccount = TreasuryAccount;
    type WeightInfo = pallet_agent_market::DefaultWeightInfo;
}

// --- Economics ---

parameter_types! {
    /// Year-1 block reward: ~166.5 ACH/block.
    /// 3.5B ACH / (10,512,000 blocks per 2 years) ≈ 333,016,888,366 planck/block for years 1-2.
    /// Then halves: ~83.25 ACH years 3-4, ~41.6 ACH years 5-6, etc.
    pub const InitialBlockReward: u128 = 166_508_444_183_u128 * 2; // doubled because first period is 2 years
    /// Halving period: 2 years in blocks (10,512,000 blocks at 6s each).
    pub const HalvingPeriod: BlockNumber = BLOCKS_2_YEARS;
    /// Gini alert threshold: 80% (8,000 bps).
    pub const GiniAlertThreshold: u32 = 8_000;
    /// Unbonding period: 7 days.
    pub const UnbondingPeriod: BlockNumber = UNBONDING_PERIOD_BLOCKS;
    /// Minimum bond: 1,000 ACH to start the tenure clock (audit fix M13).
    pub const MinStakingBond: Balance = MIN_STAKING_BOND;
    /// Max 500 staker distributions per epoch boundary (audit fix H4).
    pub const MaxRewardDistributionsPerEpoch: u32 = MAX_REWARD_DISTRIBUTIONS_PER_EPOCH;
    /// Keep ~30 days of epoch snapshots (audit fix M7).
    pub const MaxEpochSnapshotHistory: u32 = MAX_EPOCH_SNAPSHOT_HISTORY;

    // V2: Validator Candidate System
    /// Maximum active validators (block producers + finality voters).
    /// Bounded by GRANDPA's O(N²) messaging. Start with 21, increase via governance.
    pub const EconMaxActiveValidators: u32 = MAX_ACTIVE_VALIDATORS;
    /// Maximum validator candidates in the waiting pool.
    pub const EconMaxValidatorCandidates: u32 = MAX_VALIDATOR_CANDIDATES;
    /// Minimum ACH stake for validator candidacy: 1,000,000 ACH.
    pub const EconMinValidatorStake: Balance = MIN_VALIDATOR_STAKE;
    /// Minimum reputation score for validator candidacy: 7,000.
    pub const EconMinValidatorReputation: u32 = MIN_VALIDATOR_REPUTATION;
    /// Cooldown sessions after deregistering (24 sessions = ~24 hours).
    pub const EconValidatorCooldownSessions: u32 = VALIDATOR_COOLDOWN_SESSIONS;
}

impl pallet_economics::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type Identity = AgentIdentity;
    type BlockAuthorFinder = AuraSlotAuthor;
    type RewardPoolAccount = RewardPoolAccount;
    type ValidatorRewardFundAccount = ValidatorRewardFundAccount;
    type InitialBlockReward = InitialBlockReward;
    type HalvingPeriod = HalvingPeriod;
    type GiniAlertThreshold = GiniAlertThreshold;
    type UnbondingPeriod = UnbondingPeriod;
    type MinStakingBond = MinStakingBond;
    type MaxRewardDistributionsPerEpoch = MaxRewardDistributionsPerEpoch;
    type MaxEpochSnapshotHistory = MaxEpochSnapshotHistory;
    // V2: Validator Candidate System
    type MaxActiveValidators = ConstU32<{ MAX_ACTIVE_VALIDATORS }>;
    type MaxValidatorCandidates = ConstU32<{ MAX_VALIDATOR_CANDIDATES }>;
    type MinValidatorStake = EconMinValidatorStake;
    type MinValidatorReputation = EconMinValidatorReputation;
    type ValidatorCooldownSessions = EconValidatorCooldownSessions;
    type ValidatorKeyCheck = SessionKeyCheck;
    // H6 fix: Governance-controlled fund accounts
    // V3.0: Added insurance, LP incentive, and deployer bootstrap funds.
    type LiquidityFundAccount = LiquidityFundAccount;
    type CommunityFundAccount = CommunityFundAccount;
    type InsuranceFundAccount = InsuranceFundAccount;
    type LiquidityIncentiveAccount = LiquidityIncentiveAccount;
    type DeployerBootstrapAccount = DeployerBootstrapAccount;
    type WeightInfo = pallet_economics::DefaultWeightInfo;
}

// --- Agent Governance ---

parameter_types! {
    /// 2-day deliberation period.
    pub const DeliberationPeriod: BlockNumber = 2 * DAYS;
    /// 3-day voting period.
    pub const VotingPeriod: BlockNumber = 3 * DAYS;
    /// 1-day execution delay (time-lock).
    pub const ExecutionDelay: BlockNumber = DAYS;
    /// Minimum 6,000 reputation to submit proposals.
    pub const MinProposalReputation: ReputationScore = 6_000;
    /// Max 20 active proposals at once.
    pub const MaxActiveProposals: u32 = 20;
    /// V2: Max 50 active treasury grants at once.
    pub const MaxActiveGrants: u32 = MAX_ACTIVE_GRANTS;
    /// V2: Max 10 milestones per treasury grant.
    pub const MaxMilestonesPerGrant: u32 = MAX_MILESTONES_PER_GRANT;
    /// H3 fix: Minimum voters required for a proposal to pass.
    pub const MinVoterCount: u32 = MIN_VOTER_COUNT;
    /// H3 fix: Minimum total vote weight for proposal validity.
    pub const MinTotalVoteWeight: u128 = MIN_TOTAL_VOTE_WEIGHT;
}

impl pallet_agent_governance::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type Identity = AgentIdentity;
    type Economics = Economics;
    type TreasuryAccount = TreasuryAccount;
    type DeliberationPeriod = DeliberationPeriod;
    type VotingPeriod = VotingPeriod;
    type ExecutionDelay = ExecutionDelay;
    type MinProposalReputation = MinProposalReputation;
    type MaxActiveProposals = MaxActiveProposals;
    type MaxActiveGrants = MaxActiveGrants;
    type MaxMilestonesPerGrant = MaxMilestonesPerGrant;
    type MinVoterCount = MinVoterCount;
    type MinTotalVoteWeight = ConstU128<{ MIN_TOTAL_VOTE_WEIGHT }>;
    type WeightInfo = pallet_agent_governance::DefaultWeightInfo;
}

// --- Constitution ---

impl pallet_constitution::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = pallet_constitution::DefaultWeightInfo;
}

// ============================================================
// Construct Runtime
// ============================================================

construct_runtime!(
    pub struct Runtime {
        // Core Substrate pallets
        System: frame_system,
        Timestamp: pallet_timestamp,
        Balances: pallet_balances,
        TransactionPayment: pallet_transaction_payment,
        Sudo: pallet_sudo,

        // Consensus
        Aura: pallet_aura,
        Grandpa: pallet_grandpa,
        Session: pallet_session,

        // Vesting (founder + contributor token lock)
        Vesting: pallet_vesting,

        // AgentChain pallets
        AgentIdentity: pallet_agent_identity,
        AgentMarket: pallet_agent_market,
        Economics: pallet_economics,
        AgentGovernance: pallet_agent_governance,
        Constitution: pallet_constitution,
    }
);

// ============================================================
// Runtime API implementations
// ============================================================

impl_runtime_apis! {
    impl sp_api::Core<Block> for Runtime {
        fn version() -> RuntimeVersion {
            VERSION
        }

        fn execute_block(block: Block) {
            Executive::execute_block(block);
        }

        fn initialize_block(header: &<Block as BlockT>::Header) -> sp_runtime::ExtrinsicInclusionMode {
            Executive::initialize_block(header)
        }
    }

    impl sp_api::Metadata<Block> for Runtime {
        fn metadata() -> OpaqueMetadata {
            OpaqueMetadata::new(Runtime::metadata().into())
        }

        fn metadata_at_version(version: u32) -> Option<OpaqueMetadata> {
            Runtime::metadata_at_version(version)
        }

        fn metadata_versions() -> Vec<u32> {
            Runtime::metadata_versions()
        }
    }

    impl sp_block_builder::BlockBuilder<Block> for Runtime {
        fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
            Executive::apply_extrinsic(extrinsic)
        }

        fn finalize_block() -> <Block as BlockT>::Header {
            Executive::finalize_block()
        }

        fn inherent_extrinsics(data: sp_inherents::InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
            data.create_extrinsics()
        }

        fn check_inherents(
            block: Block,
            data: sp_inherents::InherentData,
        ) -> sp_inherents::CheckInherentsResult {
            data.check_extrinsics(&block)
        }
    }

    impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
        fn validate_transaction(
            source: TransactionSource,
            tx: <Block as BlockT>::Extrinsic,
            block_hash: <Block as BlockT>::Hash,
        ) -> TransactionValidity {
            Executive::validate_transaction(source, tx, block_hash)
        }
    }

    impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
        fn offchain_worker(header: &<Block as BlockT>::Header) {
            Executive::offchain_worker(header)
        }
    }

    impl sp_consensus_aura::AuraApi<Block, AuraId> for Runtime {
        fn slot_duration() -> sp_consensus_aura::SlotDuration {
            sp_consensus_aura::SlotDuration::from_millis(Aura::slot_duration())
        }

        fn authorities() -> Vec<AuraId> {
            pallet_aura::Authorities::<Runtime>::get().into_inner()
        }
    }

    impl sp_session::SessionKeys<Block> for Runtime {
        fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8> {
            opaque::SessionKeys::generate(seed)
        }

        fn decode_session_keys(encoded: Vec<u8>) -> Option<Vec<(Vec<u8>, KeyTypeId)>> {
            opaque::SessionKeys::decode_into_raw_public_keys(&encoded)
        }
    }

    impl sp_consensus_grandpa::GrandpaApi<Block> for Runtime {
        fn grandpa_authorities() -> sp_consensus_grandpa::AuthorityList {
            Grandpa::grandpa_authorities()
        }

        fn current_set_id() -> sp_consensus_grandpa::SetId {
            Grandpa::current_set_id()
        }

        fn submit_report_equivocation_unsigned_extrinsic(
            _equivocation_proof: sp_consensus_grandpa::EquivocationProof<
                <Block as BlockT>::Hash,
                NumberFor<Block>,
            >,
            _key_owner_proof: sp_consensus_grandpa::OpaqueKeyOwnershipProof,
        ) -> Option<()> {
            None
        }

        fn generate_key_ownership_proof(
            _set_id: sp_consensus_grandpa::SetId,
            _authority_id: sp_consensus_grandpa::AuthorityId,
        ) -> Option<sp_consensus_grandpa::OpaqueKeyOwnershipProof> {
            None
        }
    }

    impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Nonce> for Runtime {
        fn account_nonce(account: AccountId) -> Nonce {
            System::account_nonce(account)
        }
    }

    impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<Block, Balance> for Runtime {
        fn query_info(
            uxt: <Block as BlockT>::Extrinsic,
            len: u32,
        ) -> pallet_transaction_payment_rpc_runtime_api::RuntimeDispatchInfo<Balance> {
            TransactionPayment::query_info(uxt, len)
        }

        fn query_fee_details(
            uxt: <Block as BlockT>::Extrinsic,
            len: u32,
        ) -> pallet_transaction_payment::FeeDetails<Balance> {
            TransactionPayment::query_fee_details(uxt, len)
        }

        fn query_weight_to_fee(weight: Weight) -> Balance {
            TransactionPayment::weight_to_fee(weight)
        }

        fn query_length_to_fee(length: u32) -> Balance {
            TransactionPayment::length_to_fee(length)
        }
    }

    impl sp_genesis_builder::GenesisBuilder<Block> for Runtime {
        fn build_state(config: Vec<u8>) -> sp_genesis_builder::Result {
            frame_support::genesis_builder_helper::build_state::<RuntimeGenesisConfig>(config)
        }

        fn get_preset(id: &Option<sp_genesis_builder::PresetId>) -> Option<Vec<u8>> {
            frame_support::genesis_builder_helper::get_preset::<RuntimeGenesisConfig>(id, |_| None)
        }

        fn preset_names() -> Vec<sp_genesis_builder::PresetId> {
            Vec::new()
        }
    }
}
</parameter name="file_text">