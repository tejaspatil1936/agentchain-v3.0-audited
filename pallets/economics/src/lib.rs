//! # Economics Pallet — V3 with Adaptive Burns, Recycling, and Auto-Compound
//!
//! Manages the economic lifecycle of the AgentChain network:
//! - Block reward distribution to validators from the 3.5B fund (halving schedule)
//! - Agent staking with bond/unbond/withdraw lifecycle + minimum bond requirement
//! - Tenure-weighted yield multipliers (1.0x → 2.0x over 2 years)
//! - Protocol fee tracking and paginated staker reward distribution
//! - Comprehensive ACH burn tracking (registration + fee + transaction fee + exit burns)
//! - Epoch boundary processing with snapshots and automatic pruning
//! - Gini coefficient tracking for ACH distribution
//! - V3.0: Adaptive registration burns (5K→100 ACH based on cumulative burn ratio)
//! - V3.0: Validator fund recycling (15% of marketplace + tx fees → fund)
//! - V3.0: Staker auto-compound with 5% bonus yield
//! - V3.0: Governance-tunable economic parameters with bounded ranges
//! - V3.0: Deployer exit burn tracking
//!
//! ## V2: Permissionless Validator Candidate System
//!
//! ### Problem (V1)
//! Validators were fixed at genesis (Alice, Bob, Charlie). The `new_session()`
//! hook returned `None` forever — no agent could join or leave the validator set
//! through any on-chain mechanism. 35% of token supply flowed exclusively to
//! genesis-defined authorities.
//!
//! ### Solution (V2): Stake-Weighted Random Selection
//!
//! **Candidacy**: Any active TEE-verified agent can register as a validator
//! candidate if they meet minimum stake (1M ACH) and reputation (7,000) thresholds.
//! Candidates register their session keys on-chain.
//!
//! **Selection**: At each session boundary, `new_session()` selects up to
//! `MaxActiveValidators` from the candidate pool using stake-weighted
//! deterministic random selection. Selection probability is proportional to
//! effective stake (raw stake × tenure multiplier).
//!
//! **Randomness**: Selection seed is derived from a hash chain of recent block
//! hashes combined with the session index. This is not a VRF (Aura doesn't
//! support it), but it's unpredictable without controlling the block production
//! of multiple consecutive blocks.
//!
//! **Fairness**: Expected block rewards over time are proportional to stake.
//! Even minimum-stake candidates have a chance of selection each session.
//! Deployer concentration limits (via identity pallet) prevent sybil attacks.
//!
//! ## Fee Revenue Flow
//! Market pallet → on_service_payment() → accumulates in StakerRewardPool
//! At epoch boundary → distribute proportional to stake × tenure_multiplier (paginated)
//!
//! ## Block Reward Flow
//! on_initialize() → transfer current_block_reward() from validator fund → block author
//!
//! ## Staking Model
//! Agents bond ACH (minimum 1,000 ACH) to earn yield from protocol fees.
//! Tenure multiplier rewards long-term stakers:
//!   0-3 months: 1.0x | 3-6 months: 1.1x | 6-12 months: 1.25x
//!   1-2 years: 1.5x  | 2+ years: 2.0x
//! Full unbond resets tenure clock (retention penalty).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use agentchain_primitives::*;
    use frame_support::{
        pallet_prelude::*,
        traits::{Currency, ReservableCurrency, ExistenceRequirement},
    };
    use frame_system::pallet_prelude::*;
    use sp_runtime::Saturating;

    type BalanceOf<T> =
        <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

    // ================================================================
    // Types
    // ================================================================

    /// Snapshot of economics at an epoch boundary.
    #[derive(Clone, Encode, Decode, MaxEncodedLen, TypeInfo, Debug, Default)]
    pub struct EpochSnapshot {
        /// Gini coefficient × 10,000 (basis points). 0 = perfect equality.
        pub gini_bps: u32,
        /// Number of active agents this epoch.
        pub active_agents: u32,
        /// Total ACH staked this epoch (in UNITS).
        pub total_staked_units: u64,
        /// Block reward rate this epoch (planck per block).
        pub block_reward: u128,
        /// Protocol fees collected this epoch (planck).
        pub fee_revenue: u128,
        /// ACH burned this epoch (planck). Per-epoch, not cumulative.
        pub epoch_burned: u128,
        /// Staker rewards distributed this epoch (planck).
        pub staker_rewards_distributed: u128,
        /// Block rewards distributed to validators this epoch (planck).
        pub block_rewards_distributed: u128,
        /// V3.0: ACH recycled to validator fund this epoch (planck).
        pub validator_fund_recycled: u128,
    }

    /// Info about an agent's staked ACH.
    #[derive(Clone, Encode, Decode, MaxEncodedLen, TypeInfo, Debug)]
    pub struct StakeInfo<Balance, BlockNumber> {
        /// Total actively staked amount.
        pub active: Balance,
        /// Block when staking first began (for tenure calculation).
        /// NOT reset when adding more stake — only reset on full unbond.
        pub stake_start_block: BlockNumber,
        /// Last block when stake was modified.
        pub last_stake_block: BlockNumber,
        /// V3.0: Opt-in auto-compound. When true, epoch staker rewards are
        /// added directly to active stake (with COMPOUND_BONUS_BPS extra yield)
        /// instead of being transferred to free balance.
        pub auto_compound: bool,
    }

    /// A chunk of ACH being unbonded (waiting for unlock).
    #[derive(Clone, Encode, Decode, MaxEncodedLen, TypeInfo, Debug)]
    pub struct UnbondingChunk<Balance, BlockNumber> {
        pub amount: Balance,
        pub unlock_block: BlockNumber,
    }

    /// Info about a validator candidate.
    #[derive(Clone, Encode, Decode, MaxEncodedLen, TypeInfo, Debug)]
    #[scale_info(skip_type_params(T))]
    pub struct ValidatorCandidateInfo<T: Config> {
        /// Block when the candidate registered.
        pub registered_at: BlockNumberFor<T>,
        /// Session index when last selected into active set (0 = never).
        pub last_active_session: u32,
        /// Number of sessions the candidate has been in the active set.
        pub sessions_active: u32,
        /// Whether the candidate is currently in the active validator set.
        pub is_active: bool,
        /// V3.0: Lifetime blocks produced while in active set.
        pub blocks_produced: u32,
        /// V3.0: Lifetime blocks expected (sessions_active × blocks_per_session).
        pub blocks_expected: u32,
        /// V3.0: Current consecutive active sessions streak.
        pub consecutive_sessions: u32,
    }

    // ================================================================
    // Config
    // ================================================================

    /// Trait for finding the current block author. Implemented by the runtime
    /// using Aura slot information.
    pub trait FindBlockAuthor<AccountId> {
        fn find_author() -> Option<AccountId>;
    }

    /// No-op implementation for tests / when no author is known.
    pub struct NoAuthor;
    impl<AccountId> FindBlockAuthor<AccountId> for NoAuthor {
        fn find_author() -> Option<AccountId> { None }
    }

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type Currency: ReservableCurrency<Self::AccountId>;

        /// Interface to the identity pallet.
        type Identity: AgentIdentityInterface<Self::AccountId>;

        /// Block author finder. Runtime wires this to Aura slot lookup.
        type BlockAuthorFinder: FindBlockAuthor<Self::AccountId>;

        /// Staker reward pool account — holds the 60% fee share until epoch distribution.
        type RewardPoolAccount: Get<Self::AccountId>;

        /// Validator reward fund account — holds the 3.5B genesis allocation.
        type ValidatorRewardFundAccount: Get<Self::AccountId>;

        /// Year-1 block reward in planck units.
        #[pallet::constant]
        type InitialBlockReward: Get<u128>;

        /// Number of blocks per halving period (2 years at 6s blocks).
        #[pallet::constant]
        type HalvingPeriod: Get<BlockNumberFor<Self>>;

        /// Gini coefficient threshold (bps) that triggers a governance alert.
        #[pallet::constant]
        type GiniAlertThreshold: Get<u32>;

        /// Unbonding period in blocks (7 days default).
        #[pallet::constant]
        type UnbondingPeriod: Get<BlockNumberFor<Self>>;

        /// Minimum bond amount to start the tenure clock.
        #[pallet::constant]
        type MinStakingBond: Get<BalanceOf<Self>>;

        /// Maximum staker reward distributions per epoch boundary call.
        #[pallet::constant]
        type MaxRewardDistributionsPerEpoch: Get<u32>;

        /// Maximum epoch snapshots to retain. Older ones are pruned.
        #[pallet::constant]
        type MaxEpochSnapshotHistory: Get<u32>;

        // === V2: Validator Candidate System ===

        /// Maximum number of active validators (block producers + finality voters).
        /// Bounded by GRANDPA's O(N²) message complexity.
        #[pallet::constant]
        type MaxActiveValidators: Get<u32>;

        /// Maximum validator candidates in the waiting pool.
        #[pallet::constant]
        type MaxValidatorCandidates: Get<u32>;

        /// Minimum ACH stake to register as a validator candidate.
        #[pallet::constant]
        type MinValidatorStake: Get<BalanceOf<Self>>;

        /// Minimum reputation score to register as a validator candidate.
        #[pallet::constant]
        type MinValidatorReputation: Get<u32>;

        /// Cooldown sessions after deregistering before validator stake can be unbonded.
        #[pallet::constant]
        type ValidatorCooldownSessions: Get<u32>;

        /// Interface to check if an account has registered session keys.
        /// Prevents candidates from registering without the keys needed to
        /// produce blocks and vote on finality.
        type ValidatorKeyCheck: ValidatorKeyCheck<Self::AccountId>;

        // === H6 fix: Governance-controlled fund accounts ===
        // V2.5: OnboardingFundAccount removed — 2B onboarding fund eliminated.
        // Agents must buy and burn ACH to register. Subsidizing registration
        // undermines buy pressure and creates a supply overhang.

        /// Liquidity bootstrap fund account — 700M ACH for AMM seeding.
        type LiquidityFundAccount: Get<Self::AccountId>;

        /// Community distribution fund account — 1B ACH for airdrops.
        type CommunityFundAccount: Get<Self::AccountId>;

        // === V3.0: New fund accounts ===

        /// Insurance fund account — 500M ACH emergency backstop.
        type InsuranceFundAccount: Get<Self::AccountId>;

        /// LP incentive reward account — 1B ACH distributed over 4 years.
        type LiquidityIncentiveAccount: Get<Self::AccountId>;

        /// Deployer bootstrap fund account — 500M ACH, 12-month sunset.
        type DeployerBootstrapAccount: Get<Self::AccountId>;

        type WeightInfo: WeightInfo;
    }

    pub trait WeightInfo {
        fn on_epoch_end() -> Weight;
    }

    pub struct DefaultWeightInfo;
    impl WeightInfo for DefaultWeightInfo {
        fn on_epoch_end() -> Weight { Weight::from_parts(150_000_000, 0) }
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // ================================================================
    // Storage
    // ================================================================

    /// Current epoch number. Single source of truth — all pallets read from here.
    #[pallet::storage]
    #[pallet::getter(fn current_epoch)]
    pub type CurrentEpoch<T: Config> = StorageValue<_, EpochNumber, ValueQuery>;

    /// Historical epoch snapshots (pruned to MaxEpochSnapshotHistory).
    #[pallet::storage]
    #[pallet::getter(fn epoch_snapshots)]
    pub type EpochSnapshots<T: Config> =
        StorageMap<_, Blake2_128Concat, EpochNumber, EpochSnapshot, OptionQuery>;

    /// Latest computed Gini coefficient (bps).
    #[pallet::storage]
    #[pallet::getter(fn latest_gini)]
    pub type LatestGini<T: Config> = StorageValue<_, u32, OptionQuery>;

    /// Validator tenure: AccountId → number of epochs as validator.
    #[pallet::storage]
    #[pallet::getter(fn validator_tenure)]
    pub type ValidatorTenure<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u32, ValueQuery>;

    /// Total blocks produced (for reward decay calculation).
    #[pallet::storage]
    pub type TotalBlocksProduced<T: Config> = StorageValue<_, u64, ValueQuery>;

    // --- Fee tracking ---

    /// Total protocol fees collected (lifetime, in planck).
    #[pallet::storage]
    #[pallet::getter(fn total_fees_collected)]
    pub type TotalFeesCollected<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// Total ACH burned (lifetime, in planck). All burn sources tracked.
    #[pallet::storage]
    #[pallet::getter(fn total_ach_burned)]
    pub type TotalAchBurned<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// Protocol fee revenue this epoch (for epoch snapshot, reset each epoch).
    #[pallet::storage]
    pub type EpochFeeRevenue<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// Staker reward pool counter.
    #[pallet::storage]
    #[pallet::getter(fn staker_reward_pool)]
    pub type StakerRewardPool<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// Block rewards distributed this epoch (in planck). Reset each epoch.
    #[pallet::storage]
    pub type EpochBlockRewards<T: Config> = StorageValue<_, u128, ValueQuery>;

    // --- Staking ---

    /// Agent stake info: AccountId → StakeInfo.
    #[pallet::storage]
    #[pallet::getter(fn agent_stakes)]
    pub type AgentStakes<T: Config> = StorageMap<
        _, Blake2_128Concat, T::AccountId,
        StakeInfo<BalanceOf<T>, BlockNumberFor<T>>,
        OptionQuery,
    >;

    /// Agents currently in unbonding: AccountId → Vec<UnbondingChunk>.
    #[pallet::storage]
    #[pallet::getter(fn unbonding)]
    pub type Unbonding<T: Config> = StorageMap<
        _, Blake2_128Concat, T::AccountId,
        BoundedVec<UnbondingChunk<BalanceOf<T>, BlockNumberFor<T>>, ConstU32<32>>,
        ValueQuery,
    >;

    /// Total ACH staked across all agents.
    #[pallet::storage]
    #[pallet::getter(fn total_staked)]
    pub type TotalStaked<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

    // === V2: Validator Candidate Storage ===

    /// Validator candidates: AccountId → CandidateInfo.
    /// Any active agent meeting minimum stake + reputation can register.
    #[pallet::storage]
    #[pallet::getter(fn validator_candidates)]
    pub type ValidatorCandidates<T: Config> = StorageMap<
        _, Blake2_128Concat, T::AccountId,
        ValidatorCandidateInfo<T>,
        OptionQuery,
    >;

    /// Count of registered validator candidates.
    #[pallet::storage]
    #[pallet::getter(fn candidate_count)]
    pub type CandidateCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// The current active validator set, as selected by the last `new_session()`.
    /// This is the canonical list — the session pallet mirrors it.
    #[pallet::storage]
    #[pallet::getter(fn active_validator_set)]
    pub type ActiveValidatorSet<T: Config> = StorageValue<
        _,
        BoundedVec<T::AccountId, T::MaxActiveValidators>,
        ValueQuery,
    >;

    /// Tracks which session index we last performed a rotation.
    /// Used to prevent double-rotation and generate rotation seeds.
    #[pallet::storage]
    pub type LastRotationSession<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// Deregistration cooldown tracker: AccountId → session index when
    /// cooldown expires. Prevents unbonding validator stake immediately
    /// after deregistering.
    #[pallet::storage]
    pub type ValidatorCooldowns<T: Config> = StorageMap<
        _, Blake2_128Concat, T::AccountId, u32, OptionQuery,
    >;

    /// Cursor for paginated staker reward distribution.
    /// Stores the last AccountId processed, so the next epoch resumes
    /// from where we left off. Prevents systematic exclusion of stakers
    /// beyond the per-epoch processing limit.
    #[pallet::storage]
    pub type RewardDistributionCursor<T: Config> =
        StorageValue<_, T::AccountId, OptionQuery>;

    /// Separate tracker for transaction fee revenue per epoch.
    /// Distinguishes marketplace protocol fees from gas fees for analytics.
    #[pallet::storage]
    pub type EpochTransactionFeeRevenue<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// L3 fix: Per-epoch ACH burned. Resets at each epoch boundary.
    /// Used in EpochSnapshot.epoch_burned so it reflects the current epoch only,
    /// not the cumulative all-time burn (which is in TotalAchBurned).
    #[pallet::storage]
    pub type EpochBurnAmount<T: Config> = StorageValue<_, u128, ValueQuery>;

    // === V3.0: Governance-Tunable Parameter Overrides ===
    // When set, these override the corresponding constants. When None,
    // the adaptive calculation or constant default is used.

    /// Override for registration burn amount. None = use adaptive calculation.
    #[pallet::storage]
    pub type TunableRegistrationBurn<T: Config> = StorageValue<_, BalanceOf<T>, OptionQuery>;

    /// Override for protocol fee rate (bps). None = use tier calculation.
    #[pallet::storage]
    pub type TunableProtocolFeeBps<T: Config> = StorageValue<_, u32, OptionQuery>;

    /// Override for fee burn split (bps). None = use FEE_SPLIT_BURN_BPS.
    #[pallet::storage]
    pub type TunableFeeBurnBps<T: Config> = StorageValue<_, u32, OptionQuery>;

    /// Override for validator fund recycle split (bps). None = use FEE_SPLIT_VALIDATOR_FUND_BPS.
    #[pallet::storage]
    pub type TunableValFundRecycleBps<T: Config> = StorageValue<_, u32, OptionQuery>;

    // === V3.0: Validator Fund Recycling ===

    /// Cumulative ACH recycled to the validator reward fund (lifetime).
    #[pallet::storage]
    #[pallet::getter(fn total_validator_fund_recycled)]
    pub type TotalValidatorFundRecycled<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// ACH recycled to validator fund this epoch (reset each epoch boundary).
    #[pallet::storage]
    pub type EpochValidatorFundRecycled<T: Config> = StorageValue<_, u128, ValueQuery>;

    // === V3.0: Deployer Exit Burn Tracking ===

    /// Cumulative deployer exit burns (lifetime, separate from registration burns).
    #[pallet::storage]
    #[pallet::getter(fn total_deployer_exit_burns)]
    pub type TotalDeployerExitBurns<T: Config> = StorageValue<_, u128, ValueQuery>;

    // ================================================================
    // Events
    // ================================================================

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// New epoch started.
        EpochStarted { epoch: EpochNumber },
        /// Gini coefficient computed.
        GiniComputed { epoch: EpochNumber, gini_bps: u32 },
        /// Gini coefficient exceeded alert threshold.
        GiniAlert { epoch: EpochNumber, gini_bps: u32, threshold: u32 },
        /// Block reward for this epoch.
        BlockRewardSet { reward_per_block: u128 },
        /// Block reward paid to author.
        BlockRewardPaid { author: T::AccountId, amount: u128 },
        /// Protocol fee was processed by the economics pallet.
        FeeProcessed {
            total_fee: u128,
            to_treasury: u128,
            burned: u128,
            to_stakers: u128,
        },
        /// ACH burned (from any source).
        AchBurned { amount: u128, cumulative: u128 },
        /// Agent bonded (staked) ACH.
        Bonded { who: T::AccountId, amount: BalanceOf<T> },
        /// Agent started unbonding ACH.
        Unbonded { who: T::AccountId, amount: BalanceOf<T> },
        /// Agent withdrew unbonded ACH.
        Withdrawn { who: T::AccountId, amount: BalanceOf<T> },
        /// Staker rewards distributed at epoch boundary.
        StakerRewardsDistributed { epoch: EpochNumber, total_distributed: u128 },
        /// Old epoch snapshot was pruned.
        EpochSnapshotPruned { epoch: EpochNumber },

        // === V2: Validator Events ===

        /// Agent registered as a validator candidate.
        ValidatorCandidateRegistered { who: T::AccountId },
        /// Agent deregistered as a validator candidate.
        ValidatorCandidateDeregistered { who: T::AccountId },
        /// Active validator set was rotated at session boundary.
        ValidatorSetRotated {
            session_index: u32,
            new_set_size: u32,
            total_candidates: u32,
        },
        /// A validator was selected into the active set.
        ValidatorSelected { who: T::AccountId, effective_stake: u128 },
        /// A validator was removed from the active set (not re-selected).
        ValidatorRotatedOut { who: T::AccountId },
        /// Funds distributed from a protocol fund account (H6 fix).
        FundDistributed {
            fund: T::AccountId,
            recipient: T::AccountId,
            amount: BalanceOf<T>,
        },
        /// V2.3 H2 fix: Ineligible validator candidate purged from pool.
        /// Anyone can call this to free dead entries that block new registrations.
        ValidatorCandidatePurged { who: T::AccountId },
        /// V2.4 C1 fix: Validator reward fund is running low.
        /// Governance should consider alternative validator compensation.
        ValidatorFundDepleting {
            remaining_balance: u128,
            epoch_expected_payout: u128,
        },

        // === V3.0: New events ===

        /// V3.0: Fees recycled to validator reward fund.
        ValidatorFundRecycled {
            amount: u128,
            cumulative: u128,
        },
        /// V3.0: Staker toggled auto-compound setting.
        AutoCompoundSet {
            who: T::AccountId,
            enabled: bool,
        },
        /// V3.0: Staker rewards auto-compounded into stake.
        RewardsAutoCompounded {
            who: T::AccountId,
            amount: BalanceOf<T>,
            bonus: BalanceOf<T>,
        },
        /// V3.0: Governance adjusted an economic parameter.
        EconomicParameterAdjusted {
            parameter: EconomicParameter,
            new_value: u128,
        },
        /// V3.0: Deployer exit burn recorded.
        DeployerExitBurnRecorded {
            amount: u128,
            cumulative: u128,
        },
    }

    // ================================================================
    // Errors
    // ================================================================

    #[pallet::error]
    pub enum Error<T> {
        /// Arithmetic overflow in economics computation.
        ArithmeticOverflow,
        /// Agent is not active (required for staking).
        NotActiveAgent,
        /// Agent has no active stake.
        NotStaked,
        /// Insufficient staked balance for unbond amount.
        InsufficientStake,
        /// Too many unbonding chunks (max 32).
        TooManyUnbondingChunks,
        /// Bond amount is below the minimum staking bond.
        BelowMinimumBond,

        // === V2: Validator Errors ===

        /// Already registered as a validator candidate.
        AlreadyCandidate,
        /// Not registered as a validator candidate.
        NotCandidate,
        /// Stake is below the minimum required for validator candidacy.
        InsufficientValidatorStake,
        /// Reputation is below the minimum required for validator candidacy.
        InsufficientValidatorReputation,
        /// Maximum number of validator candidates reached.
        CandidatePoolFull,
        /// Cannot unbond below validator minimum while registered as candidate.
        /// Deregister as candidate first.
        UnbondWouldBreachValidatorMinimum,
        /// Validator cooldown has not expired. Wait before unbonding.
        ValidatorCooldownActive,
        /// The specified account is not a recognized protocol fund account.
        InvalidFundAccount,
        /// Session keys (Aura + GRANDPA) have not been registered.
        /// Call `session.set_keys` before registering as a validator candidate.
        SessionKeysNotSet,
        /// V2.3 H2 fix: Cannot purge a candidate that is still eligible.
        /// Agent must be inactive, below min stake, or below min reputation.
        StillEligible,

        // === V3.0: New errors ===

        /// Tunable parameter value is below its allowed minimum.
        BelowParameterFloor,
        /// Tunable parameter value exceeds its allowed maximum.
        AboveParameterCeiling,
        /// The caller is not authorized for this governance action.
        NotGovernanceOrigin,
    }

    // ================================================================
    // Hooks
    // ================================================================

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(_now: BlockNumberFor<T>) -> Weight {
            TotalBlocksProduced::<T>::mutate(|n| *n = n.saturating_add(1));

            // === BLOCK REWARD DISTRIBUTION (audit fix C1 + v2.4 depletion check) ===
            let reward = Self::current_block_reward();
            if reward > 0 {
                if let Some(author) = T::BlockAuthorFinder::find_author() {
                    let fund = T::ValidatorRewardFundAccount::get();
                    let fund_balance: u128 = T::Currency::free_balance(&fund)
                        .try_into()
                        .unwrap_or(0);

                    // V2.4 C1 fix: Check fund balance BEFORE attempting transfer.
                    // Without this check, transfer silently fails when fund is depleted,
                    // and validators receive nothing with no warning.
                    if fund_balance >= reward {
                        let reward_balance: BalanceOf<T> = reward.try_into().unwrap_or_default();
                        if T::Currency::transfer(
                            &fund,
                            &author,
                            reward_balance,
                            ExistenceRequirement::AllowDeath,
                        ).is_ok() {
                            EpochBlockRewards::<T>::mutate(|r| *r = r.saturating_add(reward));
                            Self::deposit_event(Event::BlockRewardPaid {
                                author,
                                amount: reward,
                            });
                        }

                        // V2.4 C1 fix: Emit depletion warning when fund is running low.
                        // Check if remaining balance (after payment) is below 1% of
                        // expected epoch payouts (reward × blocks_per_epoch).
                        let remaining = fund_balance.saturating_sub(reward);
                        let epoch_expected = reward.saturating_mul(
                            EPOCH_DURATION_IN_BLOCKS as u128
                        );
                        let warning_threshold = epoch_expected
                            .saturating_mul(VALIDATOR_FUND_WARNING_THRESHOLD_BPS as u128)
                            / 10_000;
                        if remaining < warning_threshold && remaining > 0 {
                            Self::deposit_event(Event::ValidatorFundDepleting {
                                remaining_balance: remaining,
                                epoch_expected_payout: epoch_expected,
                            });
                        }
                    } else if fund_balance > 0 {
                        // Fund has some balance but less than a full reward.
                        // Pay what's available rather than wasting it.
                        let partial: BalanceOf<T> = fund_balance.try_into().unwrap_or_default();
                        if T::Currency::transfer(
                            &fund,
                            &author,
                            partial,
                            ExistenceRequirement::AllowDeath,
                        ).is_ok() {
                            EpochBlockRewards::<T>::mutate(|r| *r = r.saturating_add(fund_balance));
                            Self::deposit_event(Event::BlockRewardPaid {
                                author,
                                amount: fund_balance,
                            });
                        }
                        Self::deposit_event(Event::ValidatorFundDepleting {
                            remaining_balance: 0,
                            epoch_expected_payout: reward.saturating_mul(
                                EPOCH_DURATION_IN_BLOCKS as u128
                            ),
                        });
                    }
                    // else: fund_balance == 0, no payment possible, no event spam
                }
            }

            Weight::from_parts(15_000_000, 0)
        }
    }

    // ================================================================
    // Extrinsics
    // ================================================================

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Bond (stake) ACH. Must be an active agent.
        /// First bond must meet MinStakingBond to start the tenure clock.
        /// Adding more stake preserves tenure.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(100_000_000, 0))]
        pub fn bond(origin: OriginFor<T>, amount: BalanceOf<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(T::Identity::is_active_agent(&who), Error::<T>::NotActiveAgent);

            let is_new_staker = AgentStakes::<T>::get(&who).is_none();
            if is_new_staker {
                ensure!(amount >= T::MinStakingBond::get(), Error::<T>::BelowMinimumBond);
            }

            T::Currency::reserve(&who, amount)
                .map_err(|_| Error::<T>::ArithmeticOverflow)?;

            let now = <frame_system::Pallet<T>>::block_number();

            AgentStakes::<T>::mutate(&who, |maybe_info| {
                match maybe_info {
                    Some(info) => {
                        info.active = info.active.saturating_add(amount);
                        info.last_stake_block = now;
                    },
                    None => {
                        *maybe_info = Some(StakeInfo {
                            active: amount,
                            stake_start_block: now,
                            last_stake_block: now,
                            auto_compound: false,
                        });
                    }
                }
            });

            TotalStaked::<T>::mutate(|t| *t = t.saturating_add(amount));

            Self::deposit_event(Event::Bonded { who, amount });
            Ok(())
        }

        /// Start unbonding ACH. Tokens enter a 7-day unbonding period.
        /// If ALL stake is unbonded, tenure clock resets (the retention penalty).
        ///
        /// V2: If registered as a validator candidate, cannot unbond below
        /// MinValidatorStake. Deregister as candidate first.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(100_000_000, 0))]
        pub fn unbond(origin: OriginFor<T>, amount: BalanceOf<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // V2: Check validator candidate minimum
            if ValidatorCandidates::<T>::contains_key(&who) {
                if let Some(info) = AgentStakes::<T>::get(&who) {
                    let remaining = info.active.saturating_sub(amount);
                    ensure!(
                        remaining >= T::MinValidatorStake::get(),
                        Error::<T>::UnbondWouldBreachValidatorMinimum
                    );
                }
            }

            // V2: Check validator cooldown
            if let Some(cooldown_until) = ValidatorCooldowns::<T>::get(&who) {
                let current_session = LastRotationSession::<T>::get();
                ensure!(
                    current_session >= cooldown_until,
                    Error::<T>::ValidatorCooldownActive
                );
                // Cooldown expired — clean up
                ValidatorCooldowns::<T>::remove(&who);
            }

            AgentStakes::<T>::try_mutate(&who, |maybe_info| -> DispatchResult {
                let info = maybe_info.as_mut().ok_or(Error::<T>::NotStaked)?;
                ensure!(info.active >= amount, Error::<T>::InsufficientStake);

                info.active = info.active.saturating_sub(amount);

                let now = <frame_system::Pallet<T>>::block_number();
                let unlock = now.saturating_add(T::UnbondingPeriod::get());

                // If fully unstaked, RESET tenure (the retention penalty)
                if info.active == 0u32.into() {
                    *maybe_info = None;
                }

                Unbonding::<T>::try_mutate(&who, |chunks| {
                    chunks.try_push(UnbondingChunk { amount, unlock_block: unlock })
                        .map_err(|_| Error::<T>::TooManyUnbondingChunks)
                })?;

                TotalStaked::<T>::mutate(|t| *t = t.saturating_sub(amount));

                Ok(())
            })?;

            Self::deposit_event(Event::Unbonded { who, amount });
            Ok(())
        }

        /// Withdraw ACH that has completed the unbonding period.
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(80_000_000, 0))]
        pub fn withdraw_unbonded(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let now = <frame_system::Pallet<T>>::block_number();
            let mut total_withdrawn = BalanceOf::<T>::default();

            Unbonding::<T>::mutate(&who, |chunks| {
                chunks.retain(|chunk| {
                    if chunk.unlock_block <= now {
                        total_withdrawn = total_withdrawn.saturating_add(chunk.amount);
                        false
                    } else {
                        true
                    }
                });
            });

            if total_withdrawn > 0u32.into() {
                T::Currency::unreserve(&who, total_withdrawn);
                Self::deposit_event(Event::Withdrawn { who, amount: total_withdrawn });
            }

            Ok(())
        }

        // ============================================================
        // V2: Validator Candidate Extrinsics
        // ============================================================

        /// Register as a validator candidate.
        ///
        /// Requirements:
        /// - Must be an active TEE-verified agent
        /// - Must have at least `MinValidatorStake` ACH bonded
        /// - Must have reputation >= `MinValidatorReputation`
        /// - Must not already be a candidate
        /// - Candidate pool must not be full
        ///
        /// The agent must have already set their session keys via the
        /// session pallet's `set_keys` extrinsic before registering.
        /// Session keys are how the consensus layer identifies validators.
        ///
        /// Once registered, the agent becomes eligible for random selection
        /// into the active validator set at the next session boundary.
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(80_000_000, 0))]
        pub fn register_validator_candidate(
            origin: OriginFor<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // Must be an active agent (TEE-verified)
            ensure!(T::Identity::is_active_agent(&who), Error::<T>::NotActiveAgent);

            // Must not already be a candidate
            ensure!(
                !ValidatorCandidates::<T>::contains_key(&who),
                Error::<T>::AlreadyCandidate
            );

            // Must have minimum stake
            let stake_info = AgentStakes::<T>::get(&who)
                .ok_or(Error::<T>::InsufficientValidatorStake)?;
            ensure!(
                stake_info.active >= T::MinValidatorStake::get(),
                Error::<T>::InsufficientValidatorStake
            );

            // Must have minimum reputation
            let reputation = T::Identity::reputation(&who)
                .unwrap_or(0);
            ensure!(
                reputation >= T::MinValidatorReputation::get(),
                Error::<T>::InsufficientValidatorReputation
            );

            // Must not exceed candidate pool size
            ensure!(
                CandidateCount::<T>::get() < T::MaxValidatorCandidates::get(),
                Error::<T>::CandidatePoolFull
            );

            // C2 fix: Must have session keys registered (Aura + GRANDPA).
            // Without keys, the consensus layer cannot use this validator.
            ensure!(
                T::ValidatorKeyCheck::has_session_keys(&who),
                Error::<T>::SessionKeysNotSet
            );

            let now = <frame_system::Pallet<T>>::block_number();
            let info = ValidatorCandidateInfo::<T> {
                registered_at: now,
                last_active_session: 0,
                sessions_active: 0,
                is_active: false,
                blocks_produced: 0,
                blocks_expected: 0,
                consecutive_sessions: 0,
            };

            ValidatorCandidates::<T>::insert(&who, info);
            CandidateCount::<T>::mutate(|c| *c = c.saturating_add(1));

            Self::deposit_event(Event::ValidatorCandidateRegistered { who });

            Ok(())
        }

        /// Deregister as a validator candidate.
        ///
        /// The agent is removed from the candidate pool and will not be
        /// selected for future sessions. If currently in the active set,
        /// they will be removed at the next session rotation.
        ///
        /// A cooldown period is imposed before the agent can unbond their
        /// validator stake (prevents flash-in-flash-out attacks on consensus).
        #[pallet::call_index(4)]
        #[pallet::weight(Weight::from_parts(80_000_000, 0))]
        pub fn deregister_validator_candidate(
            origin: OriginFor<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            ensure!(
                ValidatorCandidates::<T>::contains_key(&who),
                Error::<T>::NotCandidate
            );

            ValidatorCandidates::<T>::remove(&who);
            CandidateCount::<T>::mutate(|c| *c = c.saturating_sub(1));

            // Set cooldown: stake cannot be unbonded for ValidatorCooldownSessions
            let current_session = LastRotationSession::<T>::get();
            let cooldown_until = current_session.saturating_add(T::ValidatorCooldownSessions::get());
            ValidatorCooldowns::<T>::insert(&who, cooldown_until);

            Self::deposit_event(Event::ValidatorCandidateDeregistered { who });

            Ok(())
        }

        /// Distribute funds from a protocol fund account.
        ///
        /// H6 fix: Provides governance-controlled access to protocol fund accounts.
        /// V2.5: Onboarding fund eliminated. Remaining distributable funds:
        /// - Liquidity fund (1.7B ACH): AMM seeding
        /// - Community fund (1B ACH): airdrops and grants
        ///
        /// Only callable by Root (sudo or governance-dispatched).
        /// Governance proposals can target this via the standard proposal flow.
        #[pallet::call_index(5)]
        #[pallet::weight(Weight::from_parts(80_000_000, 0))]
        pub fn distribute_fund(
            origin: OriginFor<T>,
            fund_account: T::AccountId,
            recipient: T::AccountId,
            amount: BalanceOf<T>,
        ) -> DispatchResult {
            ensure_root(origin)?;

            // Verify the fund_account is one of the recognized protocol fund accounts
            // V3.0: Added insurance, LP incentive, and deployer bootstrap funds.
            let liquidity = T::LiquidityFundAccount::get();
            let community = T::CommunityFundAccount::get();
            let insurance = T::InsuranceFundAccount::get();
            let lp_incentive = T::LiquidityIncentiveAccount::get();
            let bootstrap = T::DeployerBootstrapAccount::get();

            ensure!(
                fund_account == liquidity
                    || fund_account == community
                    || fund_account == insurance
                    || fund_account == lp_incentive
                    || fund_account == bootstrap,
                Error::<T>::InvalidFundAccount
            );

            T::Currency::transfer(
                &fund_account,
                &recipient,
                amount,
                ExistenceRequirement::AllowDeath,
            )?;

            Self::deposit_event(Event::FundDistributed {
                fund: fund_account,
                recipient,
                amount,
            });

            Ok(())
        }

        /// V2.3 H2 fix: Purge an ineligible validator candidate from the pool.
        ///
        /// When agents lose Active status, drop below minimum stake, or fall below
        /// minimum reputation, their ValidatorCandidates entry persists as a dead
        /// entry. Over time these accumulate and can fill the candidate pool,
        /// blocking new legitimate candidates (CandidatePoolFull error).
        ///
        /// Anyone can call this — it's a permissionless garbage collection crank.
        /// The candidate must actually be ineligible or the call fails.
        /// No cooldown is imposed (unlike voluntary deregistration) because the
        /// agent already lost eligibility through other means.
        #[pallet::call_index(6)]
        #[pallet::weight(Weight::from_parts(80_000_000, 0))]
        pub fn purge_ineligible_candidate(
            origin: OriginFor<T>,
            candidate: T::AccountId,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            ensure!(
                ValidatorCandidates::<T>::contains_key(&candidate),
                Error::<T>::NotCandidate
            );

            // The candidate must be ineligible: not an active agent, OR
            // below minimum stake, OR below minimum reputation.
            let is_active = T::Identity::is_active_agent(&candidate);
            let has_rep = T::Identity::reputation(&candidate)
                .map(|r| r >= T::MinValidatorReputation::get())
                .unwrap_or(false);
            let has_stake = AgentStakes::<T>::get(&candidate)
                .map(|info| {
                    let active: u128 = info.active.try_into().unwrap_or(0);
                    let min: u128 = T::MinValidatorStake::get().try_into().unwrap_or(0);
                    active >= min
                })
                .unwrap_or(false);

            let is_eligible = is_active && has_rep && has_stake;
            ensure!(!is_eligible, Error::<T>::StillEligible);

            ValidatorCandidates::<T>::remove(&candidate);
            CandidateCount::<T>::mutate(|c| *c = c.saturating_sub(1));

            Self::deposit_event(Event::ValidatorCandidatePurged { who: candidate });

            Ok(())
        }

        // === V3.0: New extrinsics ===

        /// Toggle auto-compound for staker rewards.
        /// When enabled, epoch reward distributions are added directly to the
        /// staker's bonded stake (with COMPOUND_BONUS_BPS extra yield) instead
        /// of being transferred to their free balance.
        #[pallet::call_index(7)]
        #[pallet::weight(Weight::from_parts(50_000_000, 0))]
        pub fn set_auto_compound(
            origin: OriginFor<T>,
            enabled: bool,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(AgentStakes::<T>::contains_key(&who), Error::<T>::NotStaked);

            AgentStakes::<T>::mutate(&who, |maybe_info| {
                if let Some(info) = maybe_info {
                    info.auto_compound = enabled;
                }
            });

            Self::deposit_event(Event::AutoCompoundSet { who, enabled });
            Ok(())
        }

        /// Governance: adjust an economic parameter within bounded ranges.
        /// Requires Root origin (sudo or governance-dispatched proposal).
        /// Changes take effect immediately — no epoch delay.
        ///
        /// Parameters and their bounds:
        /// - RegistrationBurn: TUNABLE_BURN_MIN..TUNABLE_BURN_MAX
        /// - ProtocolFeeBps: 0..TUNABLE_FEE_MAX_BPS (1,000 = 10%)
        /// - FeeBurnSplitBps: 0..TUNABLE_BURN_SPLIT_MAX_BPS (5,000 = 50%)
        /// - ValidatorFundRecycleBps: 0..5,000
        #[pallet::call_index(8)]
        #[pallet::weight(Weight::from_parts(30_000_000, 0))]
        pub fn adjust_economic_parameter(
            origin: OriginFor<T>,
            parameter: EconomicParameter,
            new_value: u128,
        ) -> DispatchResult {
            ensure_root(origin)?;

            match parameter {
                EconomicParameter::RegistrationBurn => {
                    ensure!(new_value >= TUNABLE_BURN_MIN as u128, Error::<T>::BelowParameterFloor);
                    ensure!(new_value <= TUNABLE_BURN_MAX as u128, Error::<T>::AboveParameterCeiling);
                    let val: BalanceOf<T> = new_value.try_into().unwrap_or_default();
                    TunableRegistrationBurn::<T>::put(val);
                },
                EconomicParameter::ProtocolFeeBps => {
                    ensure!(new_value <= TUNABLE_FEE_MAX_BPS as u128, Error::<T>::AboveParameterCeiling);
                    TunableProtocolFeeBps::<T>::put(new_value as u32);
                },
                EconomicParameter::FeeBurnSplitBps => {
                    ensure!(new_value <= TUNABLE_BURN_SPLIT_MAX_BPS as u128, Error::<T>::AboveParameterCeiling);
                    TunableFeeBurnBps::<T>::put(new_value as u32);
                },
                EconomicParameter::ValidatorFundRecycleBps => {
                    ensure!(new_value <= 5_000u128, Error::<T>::AboveParameterCeiling);
                    TunableValFundRecycleBps::<T>::put(new_value as u32);
                },
            }

            Self::deposit_event(Event::EconomicParameterAdjusted { parameter, new_value });
            Ok(())
        }
    }

    // ================================================================
    // Economics logic
    // ================================================================

    impl<T: Config> Pallet<T> {
        /// Compute the current block reward based on halving schedule.
        pub fn current_block_reward() -> u128 {
            let total_blocks = TotalBlocksProduced::<T>::get();
            let halving_period: u64 = T::HalvingPeriod::get()
                .try_into()
                .unwrap_or(10_512_000u64);

            if halving_period == 0 {
                return T::InitialBlockReward::get();
            }

            let halvings = total_blocks / halving_period;
            if halvings >= 64 {
                return 0;
            }

            T::InitialBlockReward::get() >> halvings
        }

        /// V3.0: Compute the current adaptive registration burn amount.
        ///
        /// 1. If a governance override is set, use that directly.
        /// 2. Otherwise, compute based on cumulative burn ratio:
        ///    - Below 5% burned: full REGISTRATION_BURN_ACH (5,000 ACH)
        ///    - 5-10% burned: linear taper from 5,000 → 100 ACH
        ///    - Above 10% burned: floor at ADAPTIVE_BURN_FLOOR (100 ACH)
        ///
        /// This prevents supply collapse at high adoption while maintaining
        /// anti-spam protection even when most tokens have been burned.
        pub fn current_registration_burn() -> BalanceOf<T> {
            // Check governance override first
            if let Some(override_val) = TunableRegistrationBurn::<T>::get() {
                return override_val;
            }

            let total_burned = TotalAchBurned::<T>::get();
            // Calculate burn ratio in bps (burned / total_supply × 10,000)
            let total_supply_units = TOTAL_ACH_SUPPLY / UNITS;
            let burned_units = total_burned / UNITS;
            let burn_ratio_bps = if total_supply_units > 0 {
                burned_units.saturating_mul(10_000) / total_supply_units
            } else {
                0
            };

            let burn = if burn_ratio_bps >= ADAPTIVE_BURN_HARD_CEILING_BPS as u128 {
                // Above 10%: floor
                ADAPTIVE_BURN_FLOOR
            } else if burn_ratio_bps >= ADAPTIVE_BURN_TARGET_BPS as u128 {
                // 5-10%: linear interpolation REGISTRATION_BURN_ACH → ADAPTIVE_BURN_FLOOR
                let progress = burn_ratio_bps.saturating_sub(ADAPTIVE_BURN_TARGET_BPS as u128);
                let range = (ADAPTIVE_BURN_HARD_CEILING_BPS - ADAPTIVE_BURN_TARGET_BPS) as u128;
                if range > 0 {
                    let reduction = (REGISTRATION_BURN_ACH - ADAPTIVE_BURN_FLOOR)
                        .saturating_mul(progress) / range;
                    REGISTRATION_BURN_ACH.saturating_sub(reduction)
                } else {
                    ADAPTIVE_BURN_FLOOR
                }
            } else {
                // Below 5%: full burn
                REGISTRATION_BURN_ACH
            };

            burn.try_into().unwrap_or_default()
        }

        /// Calculate the tenure-weighted yield multiplier for a staker.
        /// Returns basis points (10,000 = 1.0x).
        pub fn tenure_multiplier(who: &T::AccountId) -> u32 {
            let info = match AgentStakes::<T>::get(who) {
                Some(i) => i,
                None => return 0,
            };
            let now = <frame_system::Pallet<T>>::block_number();
            let tenure_blocks = now.saturating_sub(info.stake_start_block);
            let tenure: u32 = tenure_blocks.try_into().unwrap_or(u32::MAX);

            if tenure >= BLOCKS_2_YEARS {
                TENURE_MULTIPLIER_2Y_PLUS
            } else if tenure >= BLOCKS_1_YEAR {
                TENURE_MULTIPLIER_1_2Y
            } else if tenure >= BLOCKS_6_MONTHS {
                TENURE_MULTIPLIER_6_12M
            } else if tenure >= BLOCKS_3_MONTHS {
                TENURE_MULTIPLIER_3_6M
            } else {
                TENURE_MULTIPLIER_0_3M
            }
        }

        /// Compute the effective stake for a candidate (raw stake × tenure multiplier).
        /// Used for validator selection weighting.
        /// C3 fix: Capped at MAX_EFFECTIVE_VALIDATOR_STAKE to prevent capital-concentration
        /// capture. A validator staking 100M ACH has the same weight as one staking 10M.
        pub fn effective_stake(who: &T::AccountId) -> u128 {
            let info = match AgentStakes::<T>::get(who) {
                Some(i) => i,
                None => return 0,
            };
            let raw_stake: u128 = info.active.try_into().unwrap_or(0);
            let capped_stake = core::cmp::min(raw_stake, MAX_EFFECTIVE_VALIDATOR_STAKE);
            let multiplier = Self::tenure_multiplier(who) as u128;
            capped_stake.saturating_mul(multiplier) / 10_000
        }

        /// Compute Gini coefficient from a list of balances.
        /// Returns value in basis points (0 = equality, 10,000 = one holder).
        /// Uses the sorted-array formula: G = (2*sum(i*x_i)) / (n*sum(x_i)) - (n+1)/n
        /// This is O(n log n) instead of the naive O(n²) pairwise approach (audit fix M9).
        pub fn compute_gini(balances: &[u128]) -> u32 {
            let n = balances.len();
            if n <= 1 {
                return 0;
            }

            let mut sorted = alloc::vec::Vec::from(balances);
            sorted.sort_unstable();

            let sum: u128 = sorted.iter().copied().sum();
            if sum == 0 {
                return 0;
            }

            // G = (2 * sum(i * x_i)) / (n * sum) - (n+1)/n
            // where i is 1-indexed position in sorted array.
            let n_u128 = n as u128;
            let mut weighted_sum: u128 = 0;
            for (idx, &val) in sorted.iter().enumerate() {
                let position = (idx as u128).saturating_add(1);
                weighted_sum = weighted_sum.saturating_add(position.saturating_mul(val));
            }

            let two_weighted = weighted_sum.saturating_mul(2);
            let n_plus_1_sum = n_u128.saturating_add(1).saturating_mul(sum);

            let gini_bps = if two_weighted > n_plus_1_sum {
                let numerator = two_weighted.saturating_sub(n_plus_1_sum);
                numerator
                    .saturating_mul(10_000)
                    .checked_div(n_u128.saturating_mul(sum))
                    .unwrap_or(0)
            } else {
                0
            };

            core::cmp::min(gini_bps as u32, 10_000)
        }

        /// Distribute staker rewards from the accumulated fee pool.
        /// Each staker gets proportional to: stake × tenure_multiplier.
        /// PAGINATED with round-robin cursor: processes at most
        /// MaxRewardDistributionsPerEpoch stakers per epoch, resuming from
        /// where the previous epoch stopped. This prevents systematic
        /// exclusion of stakers beyond position 500 (audit fix H2).
        fn distribute_staker_rewards(epoch: EpochNumber) -> u128 {
            let pool_account = T::RewardPoolAccount::get();
            let pool_balance: u128 = T::Currency::free_balance(&pool_account)
                .try_into()
                .unwrap_or(0);
            if pool_balance == 0 {
                StakerRewardPool::<T>::put(0u128);
                return 0;
            }

            let max_distributions = T::MaxRewardDistributionsPerEpoch::get();

            // Phase 1: Compute total weighted stake across ALL stakers.
            // This must iterate everyone so reward proportions are correct.
            // CRITICAL: Must apply the same tenure_multiplier used in Phase 2,
            // otherwise sum(individual_rewards) > pool_balance when multipliers > 1.0x.
            let mut total_weighted: u128 = 0;
            for (acct, info) in AgentStakes::<T>::iter() {
                let stake: u128 = info.active.try_into().unwrap_or(0);
                let multiplier = Self::tenure_multiplier(&acct) as u128;
                let weighted = stake.saturating_mul(multiplier) / 10_000;
                total_weighted = total_weighted.saturating_add(weighted);
            }

            if total_weighted == 0 {
                StakerRewardPool::<T>::put(0u128);
                return 0;
            }

            // Phase 2: Distribute to up to max_distributions stakers,
            // starting from cursor position for fairness.
            let cursor = RewardDistributionCursor::<T>::get();
            let mut distributed: u128 = 0;
            let mut count: u32 = 0;
            let mut last_key: Option<T::AccountId> = None;
            let mut started_from_cursor = false;

            // Iterator starting from cursor (if set) or beginning
            let iter = if let Some(ref cursor_key) = cursor {
                // Start iteration after the cursor key using iter_from
                // Note: iter_from in Substrate starts AT the key (inclusive).
                // V2.3 C2 fix: We must skip the cursor entry itself because it was
                // already paid as the last entry of the previous epoch. Without this
                // skip, the cursor staker receives double rewards every epoch.
                started_from_cursor = true;
                AgentStakes::<T>::iter_from(
                    AgentStakes::<T>::hashed_key_for(cursor_key)
                )
            } else {
                AgentStakes::<T>::iter_from(
                    AgentStakes::<T>::map_storage_final_prefix()
                )
            };

            // V2.3 C2 fix: Track whether we need to skip the first entry
            // (the cursor entry that was already paid last epoch).
            // V2.4 C2 hardening: Remove the fragile equality check entirely.
            // The old code checked `Some(&acct) == cursor.as_ref()` which could
            // fail due to iterator ordering differences. Now we unconditionally
            // skip the first entry when started_from_cursor is true, since
            // iter_from always starts AT the cursor key (inclusive in Substrate).
            //
            // V2.4-audit fix: Only skip if the cursor account still exists.
            // If the cursor account unstaked between epochs, iter_from starts at
            // the NEXT key in storage order. Skipping that entry would penalize
            // an innocent staker who happened to be adjacent in storage.
            let mut skip_first = started_from_cursor
                && cursor.as_ref().map_or(false, |k| AgentStakes::<T>::contains_key(k));

            // First pass: cursor position to end
            for (acct, info) in iter {
                // V2.4 C2 fix: Unconditionally skip first entry when resuming.
                // This is the staker that was already paid as the last entry
                // of the previous epoch's distribution pass.
                if skip_first {
                    skip_first = false;
                    continue;
                }
                if count >= max_distributions {
                    break;
                }
                let stake: u128 = info.active.try_into().unwrap_or(0);
                let multiplier = Self::tenure_multiplier(&acct) as u128;
                let weighted = stake.saturating_mul(multiplier) / 10_000;
                if weighted > 0 {
                    let reward = pool_balance.saturating_mul(weighted) / total_weighted;
                    if reward > 0 {
                        let reward_balance: BalanceOf<T> = reward.try_into().unwrap_or_default();
                        if T::Currency::transfer(
                            &pool_account,
                            &acct,
                            reward_balance,
                            ExistenceRequirement::AllowDeath,
                        ).is_ok() {
                            distributed = distributed.saturating_add(reward);
                        }
                    }
                }
                last_key = Some(acct);
                count = count.saturating_add(1);
            }

            // Second pass: wrap around from beginning to cursor (if we started mid-map)
            if started_from_cursor && count < max_distributions {
                for (acct, info) in AgentStakes::<T>::iter() {
                    if count >= max_distributions {
                        break;
                    }
                    // Stop if we've reached the cursor position (full cycle)
                    if Some(&acct) == cursor.as_ref() {
                        break;
                    }
                    let stake: u128 = info.active.try_into().unwrap_or(0);
                    let multiplier = Self::tenure_multiplier(&acct) as u128;
                    let weighted = stake.saturating_mul(multiplier) / 10_000;
                    if weighted > 0 {
                        let reward = pool_balance.saturating_mul(weighted) / total_weighted;
                        if reward > 0 {
                            let reward_balance: BalanceOf<T> = reward.try_into().unwrap_or_default();
                            if T::Currency::transfer(
                                &pool_account,
                                &acct,
                                reward_balance,
                                ExistenceRequirement::AllowDeath,
                            ).is_ok() {
                                distributed = distributed.saturating_add(reward);
                            }
                        }
                    }
                    last_key = Some(acct);
                    count = count.saturating_add(1);
                }
            }

            // Save cursor for next epoch
            if let Some(key) = last_key {
                RewardDistributionCursor::<T>::put(key);
            } else {
                RewardDistributionCursor::<T>::kill();
            }

            let remaining: u128 = T::Currency::free_balance(&pool_account)
                .try_into()
                .unwrap_or(0);
            StakerRewardPool::<T>::put(remaining);

            Self::deposit_event(Event::StakerRewardsDistributed {
                epoch,
                total_distributed: distributed,
            });

            distributed
        }

        /// Prune old epoch snapshots beyond the retention window.
        /// Processes up to 20 old snapshots per epoch to bound weight (audit fix L7).
        fn prune_old_snapshots(current_epoch: EpochNumber) {
            let max_history = T::MaxEpochSnapshotHistory::get();
            if current_epoch > max_history {
                let cutoff = current_epoch - max_history;
                // Prune up to 20 snapshots per epoch to bound on_initialize weight.
                // Under normal operation, only 1 needs pruning per epoch. The 20-wide
                // window handles catch-up if pruning was skipped (e.g., runtime upgrade).
                let start = cutoff.saturating_sub(20);
                for epoch_to_prune in start..cutoff {
                    if EpochSnapshots::<T>::contains_key(epoch_to_prune) {
                        EpochSnapshots::<T>::remove(epoch_to_prune);
                        Self::deposit_event(Event::EpochSnapshotPruned {
                            epoch: epoch_to_prune,
                        });
                    }
                }
            }
        }

        /// Process an epoch boundary. Called by the session manager.
        pub fn process_epoch_end() {
            let epoch = CurrentEpoch::<T>::get();

            let active_agents = T::Identity::active_agent_count();
            let block_reward = Self::current_block_reward();
            let epoch_fees = EpochFeeRevenue::<T>::get();
            let epoch_block_rewards = EpochBlockRewards::<T>::get();

            let rewards_distributed = Self::distribute_staker_rewards(epoch);

            // M3 fix + Audit2 M1 fix + V2.4 M5 fix: Rotate the sample window
            // each epoch using a hash-based pseudorandom offset instead of the
            // deterministic `epoch * 37` which sampled the same stakers repeatedly.
            // The hash includes epoch and block hash for unpredictable rotation.
            const MAX_GINI_SAMPLE: usize = 200;
            let staker_count = AgentStakes::<T>::iter().count();
            let skip_count = if staker_count > MAX_GINI_SAMPLE {
                // V2.4 M5 fix: Use cryptographic hash for sample offset.
                // V2.4-audit: Must use parent block hash. block_hash(current_block)
                // returns 0x00..00 in Substrate because the current block hasn't been
                // finalized yet. Using the zero hash made the seed deterministic per
                // epoch — no better than the original bug.
                let current_block = <frame_system::Pallet<T>>::block_number();
                let parent_hash = <frame_system::Pallet<T>>::block_hash(
                    current_block.saturating_sub(1u32.into())
                );
                let seed = sp_io::hashing::blake2_256(
                    &(epoch, parent_hash, b"gini_sample").encode()
                );
                let seed_u64 = u64::from_le_bytes(
                    seed[0..8].try_into().unwrap_or([0u8; 8])
                );
                (seed_u64 as usize) % staker_count
            } else {
                0  // Small population: sample everyone, no skip needed
            };
            let staker_balances: alloc::vec::Vec<u128> = AgentStakes::<T>::iter()
                .skip(skip_count)
                .take(MAX_GINI_SAMPLE)
                .map(|(_, info)| info.active.try_into().unwrap_or(0u128))
                .filter(|b| *b > 0)
                .collect();
            let gini_bps = if staker_balances.len() >= 2 {
                let computed = Self::compute_gini(&staker_balances);
                LatestGini::<T>::put(computed);
                Self::deposit_event(Event::GiniComputed { epoch, gini_bps: computed });
                computed
            } else {
                LatestGini::<T>::get().unwrap_or(0)
            };

            let total_staked: u128 = TotalStaked::<T>::get().try_into().unwrap_or(0);
            let total_staked_units = (total_staked / UNITS) as u64;

            let snapshot = EpochSnapshot {
                gini_bps,
                active_agents,
                total_staked_units,
                block_reward,
                fee_revenue: epoch_fees,
                // Audit2 M4 fix: Renamed from total_burned for clarity — this is per-epoch.
                // Cumulative total remains available via TotalAchBurned storage.
                epoch_burned: EpochBurnAmount::<T>::get(),
                staker_rewards_distributed: rewards_distributed,
                block_rewards_distributed: epoch_block_rewards,
                // V3.0: Track how much was recycled to validator fund this epoch.
                validator_fund_recycled: EpochValidatorFundRecycled::<T>::get(),
            };

            EpochSnapshots::<T>::insert(epoch, &snapshot);

            if snapshot.gini_bps > T::GiniAlertThreshold::get() {
                Self::deposit_event(Event::GiniAlert {
                    epoch,
                    gini_bps: snapshot.gini_bps,
                    threshold: T::GiniAlertThreshold::get(),
                });
            }

            Self::prune_old_snapshots(epoch);

            EpochFeeRevenue::<T>::put(0u128);
            EpochBlockRewards::<T>::put(0u128);
            EpochTransactionFeeRevenue::<T>::put(0u128);
            EpochBurnAmount::<T>::put(0u128);
            EpochValidatorFundRecycled::<T>::put(0u128);

            let next_epoch = epoch.saturating_add(1);
            CurrentEpoch::<T>::put(next_epoch);

            Self::deposit_event(Event::EpochStarted { epoch: next_epoch });
            Self::deposit_event(Event::BlockRewardSet {
                reward_per_block: block_reward,
            });
        }

        /// Get the tenure of a validator.
        pub fn get_validator_tenure(who: &T::AccountId) -> u32 {
            ValidatorTenure::<T>::get(who)
        }

        // ============================================================
        // V2: Validator Selection Logic
        // ============================================================

        /// Select the active validator set from the candidate pool.
        ///
        /// Uses stake-weighted deterministic random selection:
        /// 1. Collect all eligible candidates with their effective stake
        /// 2. Generate a pseudorandom seed from block hashes + session index
        /// 3. Perform weighted selection without replacement up to MaxActiveValidators
        ///
        /// The selection is deterministic given the same seed, so all validators
        /// will agree on the same set. The seed is derived from finalized block
        /// hashes, which cannot be predicted or manipulated without controlling
        /// block production over multiple consecutive blocks.
        ///
        /// Returns `Some(new_validators)` if the set changed, `None` if no
        /// candidates are available (fallback: keep existing set).
        fn select_validator_set(session_index: u32) -> Option<alloc::vec::Vec<T::AccountId>> {
            // Collect all eligible candidates
            let mut candidates: alloc::vec::Vec<(T::AccountId, u128)> = alloc::vec::Vec::new();

            for (acct, _candidate_info) in ValidatorCandidates::<T>::iter() {
                // Re-verify eligibility at selection time
                if !T::Identity::is_active_agent(&acct) {
                    continue;
                }
                let reputation = T::Identity::reputation(&acct).unwrap_or(0);
                if reputation < T::MinValidatorReputation::get() {
                    continue;
                }
                let eff_stake = Self::effective_stake(&acct);
                if eff_stake == 0 {
                    continue;
                }
                // Verify they still meet minimum stake
                let stake_info = match AgentStakes::<T>::get(&acct) {
                    Some(info) => info,
                    None => continue,
                };
                let min_stake: u128 = T::MinValidatorStake::get().try_into().unwrap_or(0);
                let active_stake: u128 = stake_info.active.try_into().unwrap_or(0);
                if active_stake < min_stake {
                    continue;
                }

                candidates.push((acct, eff_stake));
            }

            // If no eligible candidates, return None (keep existing set)
            if candidates.is_empty() {
                return None;
            }

            let max_validators = T::MaxActiveValidators::get() as usize;

            // If fewer candidates than max, all candidates become validators
            if candidates.len() <= max_validators {
                // Sort by effective stake descending for determinism
                candidates.sort_by(|a, b| b.1.cmp(&a.1));
                let selected: alloc::vec::Vec<T::AccountId> =
                    candidates.into_iter().map(|(acct, _)| acct).collect();
                return Some(selected);
            }

            // Generate selection seed from MULTIPLE block hashes + session index.
            // V2.4 H5 hardening: Increased from 10 samples over 100 blocks to
            // 20 samples over 300 blocks. An attacker must now control block
            // production across 300 consecutive blocks (30 minutes at 6s blocks)
            // to reliably influence the seed. Additional entropy from staker count
            // and total staked amount makes the seed dependent on chain state that
            // changes with every bond/unbond transaction.
            //
            // Salt 0x56414C53 = "VALS" in ASCII.
            let current_block = <frame_system::Pallet<T>>::block_number();
            let total_staked_entropy: u128 = TotalStaked::<T>::get().try_into().unwrap_or(0);
            let candidate_count_entropy = CandidateCount::<T>::get();
            let mut accumulator = sp_io::hashing::blake2_256(
                &(session_index, 0x56414C53u32, total_staked_entropy, candidate_count_entropy).encode()
            );
            for i in 0..20u32 {
                // V2.4-audit: Start from offset 1 (parent block), not 0 (current block).
                // block_hash(current_block) returns 0x00..00 in Substrate because the
                // current block hasn't been finalized. Starting at 1 ensures all 20
                // hash inputs are real block hashes.
                let sample_offset: u32 = i.saturating_mul(15).saturating_add(1);
                let sample_block = current_block.saturating_sub(sample_offset.into());
                let block_hash = <frame_system::Pallet<T>>::block_hash(sample_block);
                accumulator = sp_io::hashing::blake2_256(
                    &(accumulator, block_hash).encode()
                );
            }
            let seed_bytes = accumulator;

            // Stake-weighted selection without replacement
            // Algorithm: for each slot, generate a random threshold based on
            // remaining total weight. Walk through candidates; the first one
            // whose cumulative weight exceeds the threshold is selected.
            let mut selected: alloc::vec::Vec<T::AccountId> = alloc::vec::Vec::new();
            let mut remaining_candidates = candidates;
            let mut nonce: u32 = 0;

            for _ in 0..max_validators {
                if remaining_candidates.is_empty() {
                    break;
                }

                let total_weight: u128 = remaining_candidates.iter()
                    .map(|(_, w)| *w)
                    .sum();

                if total_weight == 0 {
                    break;
                }

                // Generate deterministic random number for this selection round
                let round_bytes = sp_io::hashing::blake2_256(
                    &(seed_bytes, nonce).encode()
                );
                // Use first 16 bytes as u128 for the random threshold
                let random_u128 = u128::from_le_bytes(
                    round_bytes[0..16].try_into().unwrap_or([0u8; 16])
                );
                let threshold = random_u128 % total_weight;

                // Walk through candidates, select the one at the threshold
                let mut cumulative: u128 = 0;
                let mut selected_idx = 0;
                for (idx, (_, weight)) in remaining_candidates.iter().enumerate() {
                    cumulative = cumulative.saturating_add(*weight);
                    if cumulative > threshold {
                        selected_idx = idx;
                        break;
                    }
                }

                let (chosen_acct, chosen_stake) = remaining_candidates.remove(selected_idx);
                Self::deposit_event(Event::ValidatorSelected {
                    who: chosen_acct.clone(),
                    effective_stake: chosen_stake,
                });
                selected.push(chosen_acct);
                nonce = nonce.saturating_add(1);
            }

            if selected.is_empty() {
                None
            } else {
                Some(selected)
            }
        }

        /// Update candidate records after a validator set rotation.
        fn update_candidate_records(new_set: &[T::AccountId], session_index: u32) {
            // Mark previous active validators as inactive
            let old_set = ActiveValidatorSet::<T>::get();
            for old_validator in old_set.iter() {
                if !new_set.contains(old_validator) {
                    ValidatorCandidates::<T>::mutate(old_validator, |maybe_info| {
                        if let Some(info) = maybe_info {
                            info.is_active = false;
                        }
                    });
                    Self::deposit_event(Event::ValidatorRotatedOut {
                        who: old_validator.clone(),
                    });
                }
            }

            // Mark new active validators
            for validator in new_set {
                ValidatorCandidates::<T>::mutate(validator, |maybe_info| {
                    if let Some(info) = maybe_info {
                        info.is_active = true;
                        info.last_active_session = session_index;
                        info.sessions_active = info.sessions_active.saturating_add(1);
                    }
                });

                // Increment validator tenure
                // V2.4 M4 fix: Cap at u32::MAX to prevent overflow after ~490 years
                ValidatorTenure::<T>::mutate(validator, |tenure| {
                    if *tenure < u32::MAX {
                        *tenure = tenure.saturating_add(1);
                    }
                });
            }

            // Update stored active set
            let bounded: BoundedVec<T::AccountId, T::MaxActiveValidators> =
                new_set.to_vec().try_into().unwrap_or_default();
            ActiveValidatorSet::<T>::put(bounded);
        }
    }

    // ================================================================
    // EconomicsInterface implementation
    // ================================================================

    impl<T: Config> EconomicsInterface<T::AccountId, BalanceOf<T>> for Pallet<T> {
        fn on_service_payment(
            fee_amount: BalanceOf<T>,
            treasury_amount: BalanceOf<T>,
            burn_amount: BalanceOf<T>,
        ) {
            let fee_u128: u128 = fee_amount.try_into().unwrap_or(0u128);
            let treasury_u128: u128 = treasury_amount.try_into().unwrap_or(0u128);
            let burn_u128: u128 = burn_amount.try_into().unwrap_or(0u128);

            // V3.0: Account for the validator fund recycle share when computing
            // the staker amount. The market pallet sends recycle tokens directly
            // to the validator fund, so we must subtract that portion here to keep
            // StakerRewardPool in sync with the pool account's actual balance.
            let recycle_bps = TunableValFundRecycleBps::<T>::get()
                .unwrap_or(FEE_SPLIT_VALIDATOR_FUND_BPS);
            let recycle_u128 = fee_u128.saturating_mul(recycle_bps as u128) / 10_000;
            let staker_u128: u128 = fee_u128
                .saturating_sub(treasury_u128)
                .saturating_sub(burn_u128)
                .saturating_sub(recycle_u128);

            TotalFeesCollected::<T>::mutate(|t| *t = t.saturating_add(fee_u128));
            TotalAchBurned::<T>::mutate(|t| *t = t.saturating_add(burn_u128));
            EpochBurnAmount::<T>::mutate(|t| *t = t.saturating_add(burn_u128));
            EpochFeeRevenue::<T>::mutate(|t| *t = t.saturating_add(fee_u128));
            StakerRewardPool::<T>::mutate(|t| *t = t.saturating_add(staker_u128));

            // V3.0: Track recycled amount
            TotalValidatorFundRecycled::<T>::mutate(|t| *t = t.saturating_add(recycle_u128));
            EpochValidatorFundRecycled::<T>::mutate(|t| *t = t.saturating_add(recycle_u128));

            Self::deposit_event(Event::FeeProcessed {
                total_fee: fee_u128,
                to_treasury: treasury_u128,
                burned: burn_u128,
                to_stakers: staker_u128,
            });

            if recycle_u128 > 0 {
                Self::deposit_event(Event::ValidatorFundRecycled {
                    amount: recycle_u128,
                    cumulative: TotalValidatorFundRecycled::<T>::get(),
                });
            }

            if burn_u128 > 0 {
                Self::deposit_event(Event::AchBurned {
                    amount: burn_u128,
                    cumulative: TotalAchBurned::<T>::get(),
                });
            }
        }

        fn record_fee_revenue(amount: BalanceOf<T>) {
            let amt: u128 = amount.try_into().unwrap_or(0u128);
            EpochFeeRevenue::<T>::mutate(|t| *t = t.saturating_add(amt));
            TotalFeesCollected::<T>::mutate(|t| *t = t.saturating_add(amt));
        }

        fn record_burn(amount: BalanceOf<T>) {
            let amt: u128 = amount.try_into().unwrap_or(0u128);
            TotalAchBurned::<T>::mutate(|t| *t = t.saturating_add(amt));
            EpochBurnAmount::<T>::mutate(|t| *t = t.saturating_add(amt));
            // L8 fix: Emit AchBurned event for transaction fee burns too,
            // not just marketplace burns.
            if amt > 0 {
                Self::deposit_event(Event::AchBurned {
                    amount: amt,
                    cumulative: TotalAchBurned::<T>::get(),
                });
            }
        }

        fn record_transaction_fee(amount: BalanceOf<T>) {
            let amt: u128 = amount.try_into().unwrap_or(0u128);
            EpochTransactionFeeRevenue::<T>::mutate(|t| *t = t.saturating_add(amt));
            // Also update the general fee counters for backward compatibility
            EpochFeeRevenue::<T>::mutate(|t| *t = t.saturating_add(amt));
            TotalFeesCollected::<T>::mutate(|t| *t = t.saturating_add(amt));
        }

        fn staker_reward_pool_account() -> T::AccountId {
            T::RewardPoolAccount::get()
        }

        fn current_epoch() -> EpochNumber {
            CurrentEpoch::<T>::get()
        }

        fn staker_stake_of(who: &T::AccountId) -> BalanceOf<T> {
            AgentStakes::<T>::get(who)
                .map(|info| info.active)
                .unwrap_or_default()
        }

        fn validator_reward_fund_account() -> T::AccountId {
            T::ValidatorRewardFundAccount::get()
        }

        // --- V3.0 additions ---

        fn current_registration_burn() -> BalanceOf<T> {
            Self::current_registration_burn()
        }

        fn record_deployer_exit_burn(amount: BalanceOf<T>) {
            let amt: u128 = amount.try_into().unwrap_or(0u128);
            TotalDeployerExitBurns::<T>::mutate(|t| *t = t.saturating_add(amt));
            TotalAchBurned::<T>::mutate(|t| *t = t.saturating_add(amt));
            EpochBurnAmount::<T>::mutate(|t| *t = t.saturating_add(amt));
            if amt > 0 {
                Self::deposit_event(Event::DeployerExitBurnRecorded {
                    amount: amt,
                    cumulative: TotalDeployerExitBurns::<T>::get(),
                });
                Self::deposit_event(Event::AchBurned {
                    amount: amt,
                    cumulative: TotalAchBurned::<T>::get(),
                });
            }
        }

        fn tunable_protocol_fee_bps() -> Option<u32> {
            TunableProtocolFeeBps::<T>::get()
        }

        fn tunable_fee_burn_bps() -> Option<u32> {
            TunableFeeBurnBps::<T>::get()
        }

        fn tunable_validator_fund_recycle_bps() -> Option<u32> {
            TunableValFundRecycleBps::<T>::get()
        }
    }

    // ================================================================
    // SessionManager — V2: stake-weighted validator rotation
    // ================================================================

    impl<T: Config> pallet_session::SessionManager<T::AccountId> for Pallet<T> {
        fn new_session(new_index: u32) -> Option<alloc::vec::Vec<T::AccountId>> {
            // Perform stake-weighted random selection from validator candidates.
            // Returns Some(new_set) to rotate validators, or None to keep current set.

            LastRotationSession::<T>::put(new_index);

            let result = Self::select_validator_set(new_index);

            if let Some(ref new_set) = result {
                Self::update_candidate_records(new_set, new_index);

                Self::deposit_event(Event::ValidatorSetRotated {
                    session_index: new_index,
                    new_set_size: new_set.len() as u32,
                    total_candidates: CandidateCount::<T>::get(),
                });
            }

            result
        }

        fn end_session(_end_index: u32) {
            // Fires at every epoch boundary — process economics.
            Self::process_epoch_end();
        }

        fn start_session(_start_index: u32) {
            // No action needed at session start.
        }
    }

    impl<T: Config> sp_runtime::traits::Convert<T::AccountId, Option<T::AccountId>> for Pallet<T> {
        fn convert(account: T::AccountId) -> Option<T::AccountId> {
            Some(account)
        }
    }
}
