//! # Agent Identity Pallet — V1.5 TEE-Enforced
//!
//! The foundation pallet of AgentChain. Enforces the "AI agent only" invariant
//! through structural TEE attestation validation and a two-phase registration
//! flow with offchain cryptographic verification.
//!
//! ## V1.5 Changes: Real AI Agent Only Enforcement
//!
//! ### Problem (V1)
//! `verify_attestation()` accepted any bytes — humans with wallets could register
//! as "agents" by sending empty attestation data. The "AI agent only" claim was
//! cosmetic, not enforced.
//!
//! ### Solution (V1.5): Three-Layer Defense
//!
//! **Layer 1 — Platform Gate**: `AllowSimulatedTee` config flag blocks
//! `TeePlatform::Simulated` on non-dev chains. No simulated agents on testnet/mainnet.
//!
//! **Layer 2 — Format Validation (on-chain)**: `verify_attestation_format()` parses
//! the attestation bytes and validates binary structure:
//!   - SGX: Quote v3 header (version, key type, vendor ID), MRENCLAVE extraction
//!   - SEV-SNP: Report structure (version, sig algorithm), measurement extraction
//!   Rejects structurally invalid data. Participants need real TEE hardware or
//!   deep format knowledge to pass this check.
//!
//! **Layer 3 — Cryptographic Verification (offchain)**: Agents register as `Pending`.
//! Offchain workers (or sudo acting as verification oracle) cryptographically verify
//! attestation signatures, certificate chains, and TCB status, then call
//! `confirm_agent()` to activate. Only `Active` agents can participate in marketplace,
//! governance, or staking.
//!
//! ### Enclave Whitelist
//! Governance maintains `ApprovedEnclaves` — a map of MRENCLAVE/measurement hashes
//! to approved agent software names. `confirm_agent()` checks the extracted
//! measurement against this whitelist. Unknown code measurements are rejected.
//!
//! ### Liveness Hardening
//! V2.2: Liveness responses use cryptographic signed digests instead of full
//! attestation blobs. At registration, the TEE generates an sr25519 keypair
//! inside the enclave and places the public key in REPORTDATA. For each
//! challenge, the enclave signs `hash(seed || agent_id)` with the private key.
//! On-chain, a single sr25519_verify call proves the enclave is still running.
//! This is ~100x cheaper than the V1.5 approach (64-byte signature vs 4KB blob),
//! cryptographically unforgeable (the private key cannot leave the enclave),
//! and resistant to replay (challenge seeds include grandparent block hash).
//!
//! Additional V2.2 anti-gaming measures:
//! - MinResponseDelay prevents same-block responses
//! - Escalating penalties for consecutive missed challenges (up to 5x base)
//! - Escalating reactivation costs: burn multiplier + lower starting reputation
//! - Consecutive miss history persists across reactivations
//! - Challenge scheduling overflow protection (retry on adjacent blocks)
//!
//! ## Responsibilities
//! - Agent registration with TEE attestation format validation
//! - Two-phase verification: Pending → Active via confirm_agent
//! - Registration ACH burn (anti-spam + deflationary)
//! - Deployer transparency graph
//! - Deployer account mapping and staking lifecycle
//! - Bounded liveness challenges with challenge-seed binding
//! - Decelerated reputation tracking
//! - Enclave whitelist management
//! - `AgentIdentityInterface` trait for cross-pallet queries

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use agentchain_primitives::*;
    use frame_support::{
        pallet_prelude::*,
        traits::{Currency, ExistenceRequirement, ReservableCurrency},
    };
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::Hash;
    use sp_core::sr25519;

    type BalanceOf<T> =
        <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

    // ================================================================
    // Pallet-local types
    // ================================================================

    /// Full on-chain record for a registered agent.
    #[derive(Clone, Encode, Decode, MaxEncodedLen, TypeInfo, Debug)]
    #[scale_info(skip_type_params(T))]
    pub struct AgentRecord<T: Config> {
        /// W3C DID identifier.
        pub did: BoundedDid,
        /// TEE attestation evidence (raw bytes).
        pub attestation: BoundedAttestation,
        /// TEE platform type.
        pub tee_platform: TeePlatform,
        /// Model family/version info.
        pub model_info: BoundedModelInfo,
        /// Deployer that registered this agent.
        pub deployer: DeployerId,
        /// Current lifecycle status.
        pub status: AgentStatus,
        /// Reputation score (basis points 0–10,000).
        pub reputation: ReputationScore,
        /// Block number when the agent registered.
        pub registered_at: BlockNumberFor<T>,
        /// Block number of last successful liveness response.
        pub last_liveness: BlockNumberFor<T>,
        /// Deployer revenue share ratio (basis points, e.g. 3000 = 30%).
        pub deployer_revenue_bps: u16,
        /// MRENCLAVE (SGX) or Measurement (SEV-SNP) extracted from attestation.
        /// None only for Simulated platform on dev chains.
        pub enclave_measurement: Option<H256>,
        /// MRSIGNER (SGX) extracted from attestation. None for SEV-SNP and Simulated.
        pub enclave_signer: Option<H256>,
        /// V2.2: Sr25519 public key generated inside the TEE enclave.
        /// Extracted from REPORTDATA[0..32] at registration. Used for
        /// cryptographic liveness challenge-response verification.
        /// None only for Simulated platform on dev chains.
        pub enclave_public_key: Option<H256>,
        /// V2.2: Consecutive missed liveness challenges (not reset on reactivation).
        /// Drives penalty escalation: penalty = base_penalty * min(consecutive_misses, cap).
        pub consecutive_misses: u32,
        /// V2.2: Lifetime count of times this agent has been suspended.
        /// Drives reactivation cost escalation: higher burn + lower starting reputation.
        pub total_suspensions: u32,
    }

    /// A liveness challenge issued to an agent.
    #[derive(Clone, Encode, Decode, MaxEncodedLen, TypeInfo, Debug)]
    #[scale_info(skip_type_params(T))]
    pub struct LivenessChallenge<T: Config> {
        /// Random seed for the challenge task.
        pub seed: H256,
        /// Block at which the challenge was issued.
        pub issued_at: BlockNumberFor<T>,
        /// Block by which the agent must respond.
        pub deadline: BlockNumberFor<T>,
    }

    // ================================================================
    // Pallet configuration
    // ================================================================

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching runtime event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Currency for registration burns and deployer staking.
        type Currency: ReservableCurrency<Self::AccountId>;

        /// Amount of ACH burned on agent registration (anti-spam + deflationary).
        #[pallet::constant]
        type RegistrationBurnAmount: Get<BalanceOf<Self>>;

        /// ACH stake required per agent registered (locked for agent's lifetime).
        #[pallet::constant]
        type DeployerStakePerAgent: Get<BalanceOf<Self>>;

        /// Maximum agents a single deployer can register.
        #[pallet::constant]
        type MaxAgentsPerDeployer: Get<u32>;

        /// Blocks between liveness challenges for each agent.
        #[pallet::constant]
        type LivenessInterval: Get<BlockNumberFor<Self>>;

        /// Blocks an agent has to respond to a challenge.
        #[pallet::constant]
        type ChallengeWindow: Get<BlockNumberFor<Self>>;

        /// Reputation penalty for missing a liveness challenge (basis points).
        #[pallet::constant]
        type LivenessPenalty: Get<u32>;

        /// Reputation boost for passing a liveness challenge (basis points).
        #[pallet::constant]
        type LivenessReward: Get<u32>;

        /// Maximum model concentration before surcharge kicks in (basis points).
        /// V2.2: No longer a hard limit. When a model family exceeds this threshold,
        /// new registrations of that family pay an escalating burn surcharge.
        /// Set to 3,300 = 33%. Acts as an economic diversity incentive.
        #[pallet::constant]
        type MaxModelConcentration: Get<u32>;

        /// Maximum liveness challenges to process per block.
        #[pallet::constant]
        type MaxChallengesPerBlock: Get<u32>;

        /// Deployer stake unlock cooldown after agent deactivation (blocks).
        #[pallet::constant]
        type DeployerUnstakeCooldown: Get<BlockNumberFor<Self>>;

        /// Whether `TeePlatform::Simulated` is allowed for registration.
        /// MUST be `false` on testnet and mainnet. Only `true` for local dev.
        ///
        /// When false, register_agent will reject any attestation with
        /// `tee_platform = Simulated`, enforcing that all agents must provide
        /// real TEE attestation evidence.
        #[pallet::constant]
        type AllowSimulatedTee: Get<bool>;

        /// Timeout for pending verification (blocks).
        /// If offchain verification doesn't confirm within this window,
        /// the agent can reclaim their registration (deployer stake refunded).
        #[pallet::constant]
        type VerificationTimeout: Get<BlockNumberFor<Self>>;

        /// V2.2: Minimum blocks between challenge issuance and valid response.
        /// Prevents same-block responses which eliminate timing pressure.
        /// Recommended: 2 blocks (12 seconds) — trivial for legitimate TEE agents,
        /// prevents co-located bots from responding within the same block.
        #[pallet::constant]
        type MinResponseDelay: Get<BlockNumberFor<Self>>;

        /// V2.2: Maximum penalty escalation multiplier for consecutive misses.
        /// First miss = 1x base penalty, second = 2x, ..., Nth = min(N, cap)x.
        #[pallet::constant]
        type PenaltyEscalationCap: Get<u32>;

        /// V3.0: Economics pallet callback for adaptive burn, exit burn tracking,
        /// and validator fund recycling.
        type EconomicsCallback: EconomicsInterface<Self::AccountId, BalanceOf<Self>>;

        type WeightInfo: WeightInfo;
    }

    pub trait WeightInfo {
        fn register_agent() -> Weight;
        fn update_reputation() -> Weight;
    }

    pub struct DefaultWeightInfo;
    impl WeightInfo for DefaultWeightInfo {
        fn register_agent() -> Weight { Weight::from_parts(150_000_000, 0) }
        fn update_reputation() -> Weight { Weight::from_parts(20_000_000, 0) }
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // ================================================================
    // Storage
    // ================================================================

    /// Map: AccountId → AgentRecord.
    #[pallet::storage]
    #[pallet::getter(fn agents)]
    pub type Agents<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, AgentRecord<T>, OptionQuery>;

    /// Map: DeployerId → Vec<AccountId>. The deployer transparency graph.
    #[pallet::storage]
    #[pallet::getter(fn deployer_agents)]
    pub type DeployerAgents<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        DeployerId,
        BoundedVec<T::AccountId, T::MaxAgentsPerDeployer>,
        ValueQuery,
    >;

    /// Map: DeployerId → AccountId (deployer's withdrawal wallet).
    #[pallet::storage]
    #[pallet::getter(fn deployer_accounts)]
    pub type DeployerAccounts<T: Config> =
        StorageMap<_, Blake2_128Concat, DeployerId, T::AccountId, OptionQuery>;

    /// Deployer stake tracking: DeployerId → total ACH locked.
    #[pallet::storage]
    #[pallet::getter(fn deployer_stakes)]
    pub type DeployerStakes<T: Config> =
        StorageMap<_, Blake2_128Concat, DeployerId, BalanceOf<T>, ValueQuery>;

    /// Track when each agent was deactivated (for deployer unstake cooldown).
    #[pallet::storage]
    pub type DeactivatedAt<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, BlockNumberFor<T>, OptionQuery>;

    /// Count of active agents (only fully verified agents).
    #[pallet::storage]
    #[pallet::getter(fn active_agent_count_storage)]
    pub type ActiveAgentCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// Count of agents currently in Pending verification state.
    #[pallet::storage]
    #[pallet::getter(fn pending_agent_count)]
    pub type PendingAgentCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// Pending liveness challenges.
    #[pallet::storage]
    #[pallet::getter(fn pending_challenges)]
    pub type PendingChallenges<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, LivenessChallenge<T>, OptionQuery>;

    /// Next scheduled challenge block for each agent.
    #[pallet::storage]
    #[pallet::getter(fn next_challenge_block)]
    pub type NextChallengeBlock<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, BlockNumberFor<T>, OptionQuery>;

    /// Block-indexed queue of agents whose challenges are due at a specific block.
    /// Enables O(1) lookup per block instead of O(n) iteration over all agents.
    /// Updated whenever a challenge is scheduled (registration, liveness response).
    #[pallet::storage]
    pub type ChallengesDueAt<T: Config> = StorageMap<
        _, Blake2_128Concat, BlockNumberFor<T>,
        BoundedVec<T::AccountId, T::MaxChallengesPerBlock>,
        ValueQuery,
    >;

    /// V2.3 H1 fix: Overflow buffer for agents that couldn't be scheduled into
    /// ChallengesDueAt because all retry blocks were full. This should be empty
    /// under normal operation (50 agents/block × 100 retries = 5,000 capacity).
    /// Phase 2.5 of on_initialize drains this by retrying schedule_challenge each block.
    /// Bounded in practice: only populated under extreme congestion, drained every block.
    #[pallet::storage]
    pub type ChallengeOverflow<T: Config> = StorageValue<
        _,
        alloc::vec::Vec<(T::AccountId, BlockNumberFor<T>)>,
        ValueQuery,
    >;

    /// V2.4 C3 fix: Separate overflow buffer for agents whose expiry processing
    /// was deferred due to per-block limits. Unlike ChallengeOverflow (which holds
    /// scheduling failures that need re-scheduling), this holds agents that MISSED
    /// their challenge deadline and need PENALTY processing.
    ///
    /// Keeping these separate prevents false penalties: ChallengeOverflow agents
    /// haven't failed — they just couldn't be scheduled. ExpiryOverflow agents
    /// definitely failed — their deadline passed without a response.
    #[pallet::storage]
    pub type ExpiryOverflow<T: Config> = StorageValue<
        _,
        alloc::vec::Vec<(T::AccountId, BlockNumberFor<T>)>,
        ValueQuery,
    >;

    /// Block-indexed queue of agents whose liveness challenges expire at a specific block.
    /// Enables O(1) expired-challenge lookup instead of O(n) iteration over PendingChallenges.
    /// Populated when a challenge is issued; consumed in Phase 1 of on_initialize.
    /// (Audit fix H5: bounded liveness challenge expiry processing)
    #[pallet::storage]
    pub type ChallengeExpiresAt<T: Config> = StorageMap<
        _, Blake2_128Concat, BlockNumberFor<T>,
        BoundedVec<T::AccountId, T::MaxChallengesPerBlock>,
        ValueQuery,
    >;

    /// Cumulative ACH burned via agent registration.
    #[pallet::storage]
    #[pallet::getter(fn total_registration_burns)]
    pub type TotalRegistrationBurns<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

    /// Approved enclave measurements (MRENCLAVE / SEV-SNP measurement hash).
    /// Only agents running code matching one of these measurements will be
    /// confirmed as Active. Managed by root/governance.
    ///
    /// Key: H256 measurement hash
    /// Value: human-readable name of the approved agent software
    #[pallet::storage]
    #[pallet::getter(fn approved_enclaves)]
    pub type ApprovedEnclaves<T: Config> =
        StorageMap<_, Blake2_128Concat, H256, BoundedName, OptionQuery>;

    /// Count of approved enclaves (for quick empty-check).
    #[pallet::storage]
    #[pallet::getter(fn approved_enclave_count)]
    pub type ApprovedEnclaveCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// Model family concentration tracker: hash(model_info) → active agent count.
    /// V2.2: Observatory metric — used for concentration surcharge calculation
    /// and governance visibility. Does NOT hard-block registration.
    /// Deployers pay escalating burn surcharges when their model family
    /// exceeds the concentration threshold, incentivizing diversity.
    #[pallet::storage]
    pub type ModelFamilyCounts<T: Config> =
        StorageMap<_, Blake2_128Concat, H256, u32, ValueQuery>;

    // ================================================================
    // Genesis Config — bootstrap approved enclave measurements
    // ================================================================

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        /// Pre-approved enclave measurements loaded at genesis.
        /// Each entry is (H256 measurement, Vec<u8> name).
        /// For devnet, this can be empty if AllowSimulatedTee is true.
        /// For testnet/mainnet, populate with known-good agent measurements.
        pub approved_enclaves: alloc::vec::Vec<(H256, alloc::vec::Vec<u8>)>,
        #[serde(skip)]
        pub _phantom: core::marker::PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            for (measurement, name_bytes) in &self.approved_enclaves {
                let name: BoundedName = name_bytes.clone()
                    .try_into()
                    .expect("approved enclave name exceeds 128 bytes");
                ApprovedEnclaves::<T>::insert(measurement, name);
                ApprovedEnclaveCount::<T>::mutate(|c| *c = c.saturating_add(1));
            }
        }
    }

    // ================================================================
    // Events
    // ================================================================

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Agent registered with Pending status, awaiting offchain verification.
        AgentRegisteredPending {
            agent: T::AccountId,
            deployer: DeployerId,
            tee_platform: TeePlatform,
            enclave_measurement: Option<H256>,
        },
        /// Agent status changed.
        AgentStatusChanged {
            agent: T::AccountId,
            old_status: AgentStatus,
            new_status: AgentStatus,
        },
        /// Offchain verification confirmed — agent is now Active.
        AgentVerificationConfirmed {
            agent: T::AccountId,
            enclave_measurement: Option<H256>,
            verifier: T::AccountId,
        },
        /// Offchain verification rejected — agent deactivated.
        AgentVerificationRejected {
            agent: T::AccountId,
            reason: BoundedName,
        },
        /// An agent's reputation was updated.
        ReputationUpdated {
            agent: T::AccountId,
            old_score: ReputationScore,
            new_score: ReputationScore,
        },
        /// A liveness challenge was issued.
        LivenessChallengeIssued {
            agent: T::AccountId,
            deadline: BlockNumberFor<T>,
        },
        /// A liveness response was processed.
        LivenessResponseProcessed {
            agent: T::AccountId,
            passed: bool,
        },
        /// ACH was burned during agent registration.
        RegistrationBurnCompleted {
            agent: T::AccountId,
            amount: BalanceOf<T>,
            total_burned: BalanceOf<T>,
        },
        /// Deployer account was registered.
        DeployerAccountRegistered {
            deployer: DeployerId,
            account: T::AccountId,
        },
        /// Deployer account was updated.
        DeployerAccountUpdated {
            deployer: DeployerId,
            old_account: T::AccountId,
            new_account: T::AccountId,
        },
        /// V2.2: Agent provided a deployer_account that differs from the stored one.
        /// The provided account was ignored; the stored account is used for staking.
        /// This indicates misconfiguration in the agent's registration parameters.
        DeployerAccountIgnored {
            deployer: DeployerId,
            provided: T::AccountId,
            stored: T::AccountId,
        },
        /// Deployer staked ACH for an agent.
        DeployerStaked {
            deployer: DeployerId,
            amount: BalanceOf<T>,
            total_staked: BalanceOf<T>,
        },
        /// Deployer released stake for a deactivated agent.
        /// V3.0: Now includes exit burn amount and agent tenure.
        DeployerStakeReleased {
            deployer: DeployerId,
            agent: T::AccountId,
            refunded: BalanceOf<T>,
            /// V3.0: Portion of stake burned based on agent tenure.
            burned: BalanceOf<T>,
            /// V3.0: Agent tenure in blocks at time of exit.
            tenure_blocks: BlockNumberFor<T>,
        },
        /// A new enclave measurement was approved.
        EnclaveApproved {
            measurement: H256,
            name: BoundedName,
        },
        /// An enclave measurement was removed from the whitelist.
        EnclaveRemoved {
            measurement: H256,
        },
        /// A pending registration was reclaimed after verification timeout.
        PendingRegistrationReclaimed {
            agent: T::AccountId,
            deployer: DeployerId,
        },
        /// V2.2: Model family concentration crossed the surcharge threshold.
        /// Emitted whenever a new agent pushes a model family above the
        /// configured threshold. Provides governance with real-time visibility.
        ModelConcentrationAlert {
            model_family_hash: H256,
            family_count: u32,
            total_active: u32,
            concentration_bps: u32,
        },
        /// V2.2: An extra registration burn was applied because the agent's
        /// model family exceeds the concentration threshold.
        ConcentrationSurchargeApplied {
            agent: T::AccountId,
            model_family_hash: H256,
            base_burn: BalanceOf<T>,
            surcharge: BalanceOf<T>,
            total_burn: BalanceOf<T>,
            concentration_bps: u32,
        },
        /// Agent withdrew funds to deployer's registered account.
        AgentFundsWithdrawn {
            agent: T::AccountId,
            deployer: DeployerId,
            deployer_account: T::AccountId,
            amount: BalanceOf<T>,
        },
        /// V2.2: Deactivated agent's on-chain record was purged to free storage.
        /// The AccountId is now available for new registration.
        AgentPurged {
            agent: T::AccountId,
            deployer: DeployerId,
        },
    }

    // ================================================================
    // Errors
    // ================================================================

    #[pallet::error]
    pub enum Error<T> {
        /// Agent is already registered.
        AlreadyRegistered,
        /// Agent is not registered.
        NotRegistered,
        /// TEE attestation verification failed.
        AttestationFailed,
        /// Deployer has reached the maximum number of agents.
        DeployerCapExceeded,
        /// No pending liveness challenge for this agent.
        NoPendingChallenge,
        /// Challenge deadline has passed.
        ChallengeExpired,
        /// Deployer revenue share must be <= 10,000 basis points.
        InvalidRevenueShare,
        /// Agent does not have enough ACH to cover the registration burn.
        InsufficientBalanceForRegistration,
        /// Deployer does not have enough ACH for the per-agent stake.
        DeployerInsufficientStake,
        /// Deployer account not set.
        DeployerAccountNotSet,
        /// Only the current deployer account can perform this action.
        NotDeployerAccount,
        /// Agent is not in Deactivated status.
        AgentNotDeactivated,
        /// Deployer unstake cooldown has not elapsed yet.
        UnstakeCooldownNotElapsed,
        /// Agent is already deactivated.
        AlreadyDeactivated,

        // === V1.5 TEE Enforcement Errors ===

        /// `TeePlatform::Simulated` is not allowed on this chain.
        /// Set `AllowSimulatedTee = true` in the runtime config for devnet only.
        SimulatedTeeNotAllowed,
        /// Attestation data is too short for the claimed TEE platform.
        AttestationTooShort,
        /// SGX Quote version field is not 3 (0x0003).
        InvalidQuoteVersion,
        /// SGX attestation key type is not ECDSA-256-with-P-256 (0x0002).
        InvalidAttestationKeyType,
        /// SGX QE Vendor ID does not match Intel's production vendor ID.
        InvalidQeVendorId,
        /// SEV-SNP report version is not 2.
        InvalidSevSnpVersion,
        /// SEV-SNP signature algorithm is not ECDSA P-384 (1).
        InvalidSevSnpSigAlgo,
        /// The enclave measurement extracted from attestation is not in
        /// the `ApprovedEnclaves` whitelist. Add it via `add_approved_enclave`.
        EnclaveNotApproved,
        /// Agent is not in Pending status (required for confirm/reject).
        AgentNotPending,
        /// No approved enclaves configured. At least one must exist before
        /// agents can be confirmed (prevents accidental open registration).
        NoApprovedEnclaves,
        /// Verification timeout has not elapsed (for reclaim).
        VerificationTimeoutNotElapsed,
        /// Enclave measurement already approved.
        EnclaveAlreadyApproved,
        /// Withdrawal amount must be greater than zero.
        WithdrawalAmountZero,
        /// V2.2: Liveness response submitted too soon after challenge issuance.
        /// Must wait at least `MinResponseDelay` blocks.
        ResponseTooEarly,
        /// V2.2: Agent has no enclave public key registered (Simulated agents
        /// on dev chains bypass signature verification).
        NoEnclavePublicKey,
        /// V2.2: Agent does not have enough ACH to cover reactivation burn.
        InsufficientBalanceForReactivation,
        /// V2.2: Agent is not in Suspended status (required for reactivation).
        AgentNotSuspended,
        /// V2.2: model_info must not be empty. At least 1 byte is required
        /// for model family classification.
        ModelInfoEmpty,
    }

    // ================================================================
    // Hooks — BOUNDED: capped at MaxChallengesPerBlock per block
    // ================================================================

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(now: BlockNumberFor<T>) -> Weight {
            let mut weight = Weight::zero();
            let max_per_block = T::MaxChallengesPerBlock::get();
            let mut processed: u32 = 0;

            // V2.4 C3 fix: Phase 0 — Drain ExpiryOverflow buffer from previous
            // blocks where try_push failed during expiry spillover. These agents
            // were consumed from their original expiry queue but never re-inserted,
            // so they would permanently escape penalty without this drain.
            //
            // IMPORTANT: This drains ExpiryOverflow (penalty targets), NOT
            // ChallengeOverflow (scheduling failures). Mixing them would falsely
            // penalize agents that merely couldn't be scheduled.
            let overflow = ExpiryOverflow::<T>::take();
            if !overflow.is_empty() {
                let mut overflow_idx: usize = 0;
                for (agent_id, _target_block) in overflow.iter() {
                    if processed >= max_per_block {
                        // Re-insert remaining overflow for next block.
                        // V2.4 BUG-4 fix: Use overflow_idx (actual loop position)
                        // instead of processed (which only counts successful penalties).
                        let remaining: alloc::vec::Vec<_> = overflow[overflow_idx..]
                            .to_vec();
                        ExpiryOverflow::<T>::put(remaining);
                        break;
                    }
                    overflow_idx += 1;
                    // Process this overflowed agent as if their challenge expired
                    if PendingChallenges::<T>::get(agent_id).is_some() {
                        if let Some(mut record) = Agents::<T>::get(agent_id) {
                            record.consecutive_misses = record.consecutive_misses.saturating_add(1);
                            let escalation = core::cmp::min(
                                record.consecutive_misses,
                                T::PenaltyEscalationCap::get(),
                            );
                            let base_penalty = T::LivenessPenalty::get();
                            let scaled_penalty = base_penalty.saturating_mul(escalation);

                            let old = record.reputation;
                            record.reputation = record.reputation.saturating_sub(scaled_penalty);

                            if record.reputation == REPUTATION_ZERO
                                && record.status == AgentStatus::Active
                            {
                                let old_status = record.status;
                                record.status = AgentStatus::Suspended;
                                ActiveAgentCount::<T>::mutate(|c| *c = c.saturating_sub(1));
                                let mfk = T::Hashing::hash_of(&record.model_info);
                                ModelFamilyCounts::<T>::mutate(mfk, |c| *c = c.saturating_sub(1));
                                Self::deposit_event(Event::AgentStatusChanged {
                                    agent: agent_id.clone(),
                                    old_status,
                                    new_status: AgentStatus::Suspended,
                                });
                            }

                            Self::deposit_event(Event::ReputationUpdated {
                                agent: agent_id.clone(),
                                old_score: old,
                                new_score: record.reputation,
                            });

                            Agents::<T>::insert(agent_id, record);
                        }
                        PendingChallenges::<T>::remove(agent_id);
                        Self::deposit_event(Event::LivenessResponseProcessed {
                            agent: agent_id.clone(),
                            passed: false,
                        });
                        processed = processed.saturating_add(1);
                        weight = weight.saturating_add(Weight::from_parts(50_000_000, 0));
                    }
                }
            }

            // Phase 1: Check for agents with pending challenges past deadline.
            // H5 fix: Uses ChallengeExpiresAt index for O(1) lookup instead of
            // iterating all PendingChallenges entries (was O(n) for n agents).
            // Also checks a small lookback window in case blocks were skipped.
            //
            // V2.3 fix (C1): `take` destructively consumes the entire list from
            // storage. If we hit the per-block processing cap, unprocessed agents
            // must be re-inserted for the next block — otherwise they escape
            // penalty entirely and their PendingChallenges entries become orphans.
            let lookback: BlockNumberFor<T> = 3u32.into();
            let start_block = now.saturating_sub(lookback);
            let mut current_check = start_block;
            'outer: while current_check <= now && processed < max_per_block {
                let expired_agents = ChallengeExpiresAt::<T>::take(current_check);
                let agent_list: alloc::vec::Vec<_> = expired_agents.into_inner();
                for (idx, agent_id) in agent_list.iter().enumerate() {
                    if processed >= max_per_block {
                        // V2.4 C3 fix: Re-insert unprocessed agents. If try_push fails
                        // (next block's queue full), push to ExpiryOverflow (NOT
                        // ChallengeOverflow) to ensure they get penalty processing.
                        let spillover = &agent_list[idx..];
                        if !spillover.is_empty() {
                            let next = now.saturating_add(1u32.into());
                            let mut overflow_needed: alloc::vec::Vec<(T::AccountId, BlockNumberFor<T>)> = alloc::vec::Vec::new();
                            ChallengeExpiresAt::<T>::mutate(next, |agents| {
                                for a in spillover {
                                    if agents.try_push(a.clone()).is_err() {
                                        // V2.4 C3 fix: Queue full — route to ExpiryOverflow
                                        overflow_needed.push((a.clone(), next));
                                    }
                                }
                            });
                            if !overflow_needed.is_empty() {
                                ExpiryOverflow::<T>::mutate(|ov| {
                                    ov.extend(overflow_needed);
                                });
                            }
                        }
                        break 'outer;
                    }
                    // Verify this agent still has a pending challenge (may have responded)
                    if PendingChallenges::<T>::get(agent_id).is_none() {
                        continue;
                    }

                    if let Some(mut record) = Agents::<T>::get(agent_id) {
                        // V2.2: Increment consecutive misses and apply escalating penalty.
                        record.consecutive_misses = record.consecutive_misses.saturating_add(1);
                        let escalation = core::cmp::min(
                            record.consecutive_misses,
                            T::PenaltyEscalationCap::get(),
                        );
                        let base_penalty = T::LivenessPenalty::get();
                        let scaled_penalty = base_penalty.saturating_mul(escalation);

                        let old = record.reputation;
                        record.reputation = record.reputation.saturating_sub(scaled_penalty);

                        if record.reputation == REPUTATION_ZERO {
                            let old_status = record.status;
                            record.status = AgentStatus::Suspended;
                            ActiveAgentCount::<T>::mutate(|c| *c = c.saturating_sub(1));
                            // Audit2 H2 fix: Decrement model concentration when leaving Active.
                            // Only Active agents have ModelFamilyCounts incremented (at confirm_agent).
                            if old_status == AgentStatus::Active {
                                let mfk = T::Hashing::hash_of(&record.model_info);
                                ModelFamilyCounts::<T>::mutate(mfk, |c| *c = c.saturating_sub(1));
                            }
                            Self::deposit_event(Event::AgentStatusChanged {
                                agent: agent_id.clone(),
                                old_status,
                                new_status: AgentStatus::Suspended,
                            });
                        }

                        Self::deposit_event(Event::ReputationUpdated {
                            agent: agent_id.clone(),
                            old_score: old,
                            new_score: record.reputation,
                        });

                        Agents::<T>::insert(agent_id, record);
                    }

                    PendingChallenges::<T>::remove(agent_id);

                    Self::deposit_event(Event::LivenessResponseProcessed {
                        agent: agent_id.clone(),
                        passed: false,
                    });

                    processed = processed.saturating_add(1);
                    weight = weight.saturating_add(Weight::from_parts(50_000_000, 0));
                }
                current_check = current_check.saturating_add(1u32.into());
            }

            // Phase 2: Issue new challenges for agents that are due.
            // Uses ChallengesDueAt index for O(1) lookup instead of O(n) iteration.
            //
            // V2.2 fixes:
            // - Guard: Skip agents that already have a pending challenge (prevents
            //   silent overwrite which would erase the missed-challenge penalty).
            // - Overflow: If ChallengesDueAt was full at scheduling time and some
            //   agents were silently dropped, they get rescheduled via fallback
            //   in the next interval (schedule_challenge handles the retry).
            // - Seed hardening: Includes block_hash from 2 blocks ago as additional
            //   entropy, making seed less predictable to block producers.
            let remaining = max_per_block.saturating_sub(processed);
            if remaining > 0 {
                let due_agents = ChallengesDueAt::<T>::take(now);
                for agent_id in due_agents.iter().take(remaining as usize) {
                    if let Some(record) = Agents::<T>::get(agent_id) {
                        if record.status == AgentStatus::Active {
                            // V2.2: Guard — do not overwrite existing pending challenge.
                            // If the agent already has a pending challenge (e.g. from a
                            // previous round that hasn't expired yet), skip issuance.
                            // The existing challenge's expiry will handle the penalty.
                            if PendingChallenges::<T>::get(agent_id).is_some() {
                                // Reschedule for next interval so we don't lose this agent
                                let next = now.saturating_add(T::LivenessInterval::get());
                                Self::schedule_challenge(agent_id, next);
                                continue;
                            }

                            // V2.4 H2 fix: Hardened seed — accumulates 5 block hashes
                            // spanning 10 blocks into the past. The old approach used
                            // only parent_hash + grandparent_hash, both known to block
                            // producers before challenge issuance. Now an attacker must
                            // control block production across 10+ blocks to predict seeds.
                            // Agent-specific data (reputation, consecutive_misses) adds
                            // per-agent entropy that changes with every interaction.
                            let mut seed_accumulator = sp_io::hashing::blake2_256(
                                &(now, agent_id, b"liveness_v2.4").encode()
                            );
                            // V2.4-audit: Use offsets [1,3,5,7,9] instead of [0,2,4,6,8].
                            // block_hash(now) returns 0x00..00 because the current block
                            // hasn't been finalized. Starting at offset 1 ensures all
                            // 5 hash inputs are real block hashes spanning 10 blocks.
                            for offset in [1u32, 3, 5, 7, 9] {
                                let sample_block = now.saturating_sub(offset.into());
                                let bh = <frame_system::Pallet<T>>::block_hash(sample_block);
                                seed_accumulator = sp_io::hashing::blake2_256(
                                    &(seed_accumulator, bh).encode()
                                );
                            }
                            // Include agent-specific state as additional entropy
                            let agent_entropy = (
                                record.reputation,
                                record.consecutive_misses,
                                record.last_liveness,
                            );
                            seed_accumulator = sp_io::hashing::blake2_256(
                                &(seed_accumulator, agent_entropy).encode()
                            );
                            let seed = T::Hashing::hash_of(&seed_accumulator);

                            let deadline = now.saturating_add(T::ChallengeWindow::get());

                            let challenge = LivenessChallenge::<T> {
                                seed,
                                issued_at: now,
                                deadline,
                            };

                            PendingChallenges::<T>::insert(agent_id, challenge);
                            // H5 fix: Index the deadline for O(1) expiry lookup.
                            // V2.2: If push fails (BoundedVec full), the expiry won't fire
                            // from the index — but the agent can still respond, and the
                            // challenge will be picked up on the next pass via lookback.
                            ChallengeExpiresAt::<T>::mutate(deadline, |agents| {
                                let _ = agents.try_push(agent_id.clone());
                            });
                            let next = now.saturating_add(T::LivenessInterval::get());
                            Self::schedule_challenge(agent_id, next);

                            Self::deposit_event(Event::LivenessChallengeIssued {
                                agent: agent_id.clone(),
                                deadline,
                            });

                            weight = weight.saturating_add(Weight::from_parts(30_000_000, 0));
                        }
                    }
                }
                // V2.2: Handle overflow — if more agents were due than `remaining`,
                // the ones not processed were consumed from ChallengesDueAt but never
                // issued. Reschedule them for the next block so they aren't orphaned.
                if due_agents.len() > remaining as usize {
                    for orphan in due_agents.iter().skip(remaining as usize) {
                        let next = now.saturating_add(1u32.into());
                        Self::schedule_challenge(orphan, next);
                    }
                }
            }

            // Phase 2.5 (V2.3 H1 fix): Drain the challenge overflow buffer.
            // Agents land here only when 100+ consecutive blocks' ChallengesDueAt
            // queues were all full — extremely unlikely, but must be handled.
            // Re-attempt scheduling from the current block + 1 interval, giving
            // them a fresh window of retry targets.
            let overflow = ChallengeOverflow::<T>::take();
            if !overflow.is_empty() {
                for (agent_id, _original_target) in overflow {
                    // Only reschedule if the agent is still Active and doesn't
                    // already have a pending challenge or a valid scheduled block.
                    if let Some(record) = Agents::<T>::get(&agent_id) {
                        if record.status == AgentStatus::Active
                            && PendingChallenges::<T>::get(&agent_id).is_none()
                        {
                            let next = now.saturating_add(T::LivenessInterval::get());
                            Self::schedule_challenge(&agent_id, next);
                        }
                    }
                }
                weight = weight.saturating_add(Weight::from_parts(10_000_000, 0));
            }

            weight
        }
    }

    // ================================================================
    // Extrinsics
    // ================================================================

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register a new agent on-chain.
        ///
        /// ## V1.5 TEE Enforcement
        /// - Blocks `TeePlatform::Simulated` unless `AllowSimulatedTee` is true
        /// - Validates attestation binary format (SGX Quote v3 / SEV-SNP report)
        /// - Extracts enclave measurement (MRENCLAVE / launch digest)
        /// - Sets initial status to `Pending` (NOT Active)
        /// - Agent cannot participate in marketplace/governance/staking until
        ///   `confirm_agent()` is called after offchain verification
        ///
        /// Burns `RegistrationBurnAmount` ACH from the agent's account.
        /// Locks `DeployerStakePerAgent` ACH from the deployer's account.
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::register_agent())]
        pub fn register_agent(
            origin: OriginFor<T>,
            did: BoundedDid,
            attestation: BoundedAttestation,
            tee_platform: TeePlatform,
            model_info: BoundedModelInfo,
            deployer: DeployerId,
            deployer_account: T::AccountId,
            deployer_revenue_bps: u16,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // Must not already be registered
            ensure!(!Agents::<T>::contains_key(&who), Error::<T>::AlreadyRegistered);

            // Revenue share must be valid
            ensure!(deployer_revenue_bps <= 10_000, Error::<T>::InvalidRevenueShare);

            // V2.2: model_info must not be empty. Empty model_info hashes to a
            // single "null family" that all empty-info agents share, defeating
            // concentration tracking. At least 1 byte is required.
            ensure!(!model_info.is_empty(), Error::<T>::ModelInfoEmpty);

            // === V1.5: BLOCK SIMULATED TEE ON NON-DEV CHAINS ===
            if tee_platform == TeePlatform::Simulated {
                ensure!(T::AllowSimulatedTee::get(), Error::<T>::SimulatedTeeNotAllowed);
            }

            // Check deployer cap
            let mut deployer_list = DeployerAgents::<T>::get(&deployer);
            deployer_list
                .try_push(who.clone())
                .map_err(|_| Error::<T>::DeployerCapExceeded)?;

            // === V1.5: VALIDATE ATTESTATION FORMAT + EXTRACT MEASUREMENT ===
            let (enclave_measurement, enclave_signer, enclave_public_key) =
                Self::verify_attestation_format(&tee_platform, &attestation)?;

            // V2.2: Reject all-zero enclave public key for real TEE platforms.
            // A zero key means REPORTDATA was empty — the TEE agent didn't generate
            // a keypair. This agent would pass registration but fail every liveness
            // challenge (no valid signature possible against a zero public key).
            if tee_platform != TeePlatform::Simulated {
                if let Some(pk) = &enclave_public_key {
                    ensure!(*pk != H256::zero(), Error::<T>::NoEnclavePublicKey);
                } else {
                    return Err(Error::<T>::NoEnclavePublicKey.into());
                }
            }

            // === MODEL CONCENTRATION: Deferred to confirm_agent for real TEE agents ===
            // For simulated agents (dev only), we check and increment here since
            // they go straight to Active. For real TEE, the check happens at
            // confirm_agent when Pending→Active, ensuring both numerator (family count)
            // and denominator (active count) only count Active agents. (H3 fix)
            let model_family_key = T::Hashing::hash_of(&model_info);

            // === REGISTRATION BURN ===
            // V3.0: Use adaptive burn amount from economics pallet instead of
            // fixed constant. Tapers from 5K→100 ACH as cumulative burns approach cap.
            let burn_amount = T::EconomicsCallback::current_registration_burn();
            if burn_amount > 0u32.into() {
                // V2.4 H1 fix: Pre-check that agent has enough free balance to
                // cover BOTH the registration burn AND the worst-case concentration
                // surcharge. Without this, a strategic agent can register with exactly
                // burn_amount in free balance, leaving zero for the surcharge — which
                // makes the concentration mechanism ineffective.
                //
                // Worst case: concentration tier 3 (66%+) = 3x base burn surcharge.
                let max_possible_surcharge = burn_amount.saturating_mul(3u32.into());
                let total_needed = burn_amount.saturating_add(max_possible_surcharge);
                let free = T::Currency::free_balance(&who);
                ensure!(free >= total_needed, Error::<T>::InsufficientBalanceForRegistration);

                let (imbalance, _remaining) = T::Currency::slash(&who, burn_amount);
                drop(imbalance);

                let new_total = TotalRegistrationBurns::<T>::get().saturating_add(burn_amount);
                TotalRegistrationBurns::<T>::put(new_total);

                Self::deposit_event(Event::RegistrationBurnCompleted {
                    agent: who.clone(),
                    amount: burn_amount,
                    total_burned: new_total,
                });
            }

            // === DEPLOYER ACCOUNT MAPPING ===
            // First agent for this deployer: set the deployer account.
            // Subsequent agents: the deployer_account parameter is ignored —
            // the existing mapping is used for stake reservation.
            if !DeployerAccounts::<T>::contains_key(&deployer) {
                DeployerAccounts::<T>::insert(&deployer, &deployer_account);
                Self::deposit_event(Event::DeployerAccountRegistered {
                    deployer,
                    account: deployer_account.clone(),
                });
            } else {
                // V2.2: Warn if the provided deployer_account differs from the stored one.
                // This catches misconfiguration where an agent passes a different account
                // than the deployer originally registered. The parameter is still ignored.
                let stored = DeployerAccounts::<T>::get(&deployer);
                if stored.as_ref() != Some(&deployer_account) {
                    Self::deposit_event(Event::DeployerAccountIgnored {
                        deployer,
                        provided: deployer_account.clone(),
                        stored: stored.expect("checked contains_key above"),
                    });
                }
            }

            // === DEPLOYER STAKING ===
            let stake_amount = T::DeployerStakePerAgent::get();
            if stake_amount > 0u32.into() {
                let deployer_acct = DeployerAccounts::<T>::get(&deployer)
                    .ok_or(Error::<T>::DeployerAccountNotSet)?;
                T::Currency::reserve(&deployer_acct, stake_amount)
                    .map_err(|_| Error::<T>::DeployerInsufficientStake)?;

                let new_total = DeployerStakes::<T>::get(&deployer).saturating_add(stake_amount);
                DeployerStakes::<T>::insert(&deployer, new_total);

                Self::deposit_event(Event::DeployerStaked {
                    deployer,
                    amount: stake_amount,
                    total_staked: new_total,
                });
            }

            let now = <frame_system::Pallet<T>>::block_number();

            // === V1.5: PENDING STATUS ===
            // Simulated agents on dev chains go straight to Active.
            // Real TEE agents start as Pending, awaiting offchain verification.
            let initial_status = if tee_platform == TeePlatform::Simulated {
                AgentStatus::Active
            } else {
                AgentStatus::Pending
            };

            let record = AgentRecord::<T> {
                did,
                attestation,
                tee_platform,
                model_info,
                deployer,
                status: initial_status,
                reputation: REPUTATION_START,
                registered_at: now,
                last_liveness: now,
                deployer_revenue_bps,
                enclave_measurement,
                enclave_signer,
                enclave_public_key,
                consecutive_misses: 0,
                total_suspensions: 0,
            };

            // Write storage
            Agents::<T>::insert(&who, record);
            DeployerAgents::<T>::insert(&deployer, deployer_list);
            if initial_status == AgentStatus::Active {
                // Simulated on dev: skip pending, go straight to active.
                // V2.2: Apply concentration surcharge instead of hard block.
                // Agents can always register — concentrated models just cost more.
                let current_family_count = ModelFamilyCounts::<T>::get(model_family_key);
                let total_active = ActiveAgentCount::<T>::get();
                Self::apply_concentration_surcharge(
                    &who,
                    model_family_key,
                    current_family_count,
                    total_active,
                );
                ModelFamilyCounts::<T>::mutate(model_family_key, |c| *c = c.saturating_add(1));
                ActiveAgentCount::<T>::mutate(|c| *c = c.saturating_add(1));
                let first_challenge = now.saturating_add(T::LivenessInterval::get());
                Self::schedule_challenge(&who, first_challenge);
            } else {
                // Real TEE: increment pending count, no liveness until confirmed.
                // ModelFamilyCounts NOT incremented here — deferred to confirm_agent
                // so concentration ratio only counts Active agents (H3 fix).
                PendingAgentCount::<T>::mutate(|c| *c = c.saturating_add(1));
            }

            Self::deposit_event(Event::AgentRegisteredPending {
                agent: who,
                deployer,
                tee_platform,
                enclave_measurement,
            });

            Ok(())
        }

        /// Respond to a liveness challenge.
        ///
        /// ## V1.5 Hardening
        /// For real TEE platforms, the response must contain the challenge seed
        /// at the correct offset in the attestation report data field.
        /// This prevents trivial "any bytes" responses.
        ///
        /// Reputation gain is decelerated at higher tiers:
        ///   Below 6,000: full reward
        ///   6,000–8,000: half reward
        ///   Above 8,000: quarter reward
        /// Respond to a liveness challenge with a signed digest.
        ///
        /// V2.2: The agent signs `hash(seed || agent_id)` with the sr25519 private key
        /// held inside the TEE enclave. On-chain verification proves the enclave is
        /// still running without requiring a full attestation report.
        ///
        /// Changes from V1.5:
        /// - Response is a 64-byte sr25519 signature (was 4KB attestation blob)
        /// - Signature verified against registered enclave_public_key
        /// - MinResponseDelay enforced (prevents same-block responses)
        /// - Penalty escalation for consecutive failures
        /// - consecutive_misses counter tracks failure history
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(100_000_000, 0))]
        pub fn respond_liveness(
            origin: OriginFor<T>,
            signature: BoundedLivenessSignature,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let mut record = Agents::<T>::get(&who).ok_or(Error::<T>::NotRegistered)?;
            let challenge = PendingChallenges::<T>::get(&who)
                .ok_or(Error::<T>::NoPendingChallenge)?;

            let now = <frame_system::Pallet<T>>::block_number();
            ensure!(now <= challenge.deadline, Error::<T>::ChallengeExpired);

            // V2.2: Enforce minimum response delay.
            // Prevents same-block responses which eliminate timing pressure.
            // A legitimate TEE agent needs ~1 block to generate the signature;
            // this only blocks bots that respond within the same block.
            let min_delay = T::MinResponseDelay::get();
            ensure!(
                now >= challenge.issued_at.saturating_add(min_delay),
                Error::<T>::ResponseTooEarly
            );

            // V2.2: Verify the cryptographic signature.
            let passed = Self::verify_liveness_signature(
                &record.tee_platform,
                &record.enclave_public_key,
                &challenge.seed,
                &who,
                signature.as_slice(),
            );

            if passed {
                // V2.2: Reset consecutive misses on success.
                record.consecutive_misses = 0;

                // V2.4 M1 fix: Smooth logarithmic deceleration replaces discrete
                // tier cliffs (was: 100 bps at <6000, 50 bps at 6000-8000, 25 bps
                // at >8000). The old system created clustering at 5999/7999 as
                // agents gamed the threshold boundaries.
                //
                // New formula: effective_reward = base_reward * 5000 / max(reputation, 5000)
                // At rep 5000: full reward (100 bps)
                // At rep 6000: 83 bps (smooth)
                // At rep 7000: 71 bps
                // At rep 8000: 62 bps
                // At rep 9000: 55 bps
                // At rep 10000: 50 bps (floor)
                let base_reward = T::LivenessReward::get();
                let effective_reward = {
                    let rep = record.reputation.max(REPUTATION_START) as u64;
                    let reward_u64 = (base_reward as u64)
                        .saturating_mul(REPUTATION_START as u64)
                        / rep;
                    core::cmp::max(reward_u64 as u32, base_reward / 4) // floor at 25% of base
                };

                let old = record.reputation;
                record.reputation = core::cmp::min(
                    record.reputation.saturating_add(effective_reward),
                    REPUTATION_MAX,
                );
                record.last_liveness = now;

                Self::deposit_event(Event::ReputationUpdated {
                    agent: who.clone(),
                    old_score: old,
                    new_score: record.reputation,
                });
            } else {
                // V2.2: Escalating penalties for consecutive failures.
                // Increment counter BEFORE computing penalty so first failure = 1x.
                record.consecutive_misses = record.consecutive_misses.saturating_add(1);

                let escalation = core::cmp::min(
                    record.consecutive_misses,
                    T::PenaltyEscalationCap::get(),
                );
                let base_penalty = T::LivenessPenalty::get();
                let scaled_penalty = base_penalty.saturating_mul(escalation);

                let old = record.reputation;
                record.reputation = record.reputation.saturating_sub(scaled_penalty);

                // M1 fix: Suspend agent if reputation drops to zero, matching
                // the same check in on_initialize for missed challenges.
                if record.reputation == REPUTATION_ZERO
                    && record.status == AgentStatus::Active
                {
                    let old_status = record.status;
                    record.status = AgentStatus::Suspended;
                    ActiveAgentCount::<T>::mutate(|c| *c = c.saturating_sub(1));
                    // Audit2 H2 fix: Decrement model concentration when leaving Active.
                    let mfk = T::Hashing::hash_of(&record.model_info);
                    ModelFamilyCounts::<T>::mutate(mfk, |c| *c = c.saturating_sub(1));
                    Self::deposit_event(Event::AgentStatusChanged {
                        agent: who.clone(),
                        old_status,
                        new_status: AgentStatus::Suspended,
                    });
                }

                Self::deposit_event(Event::ReputationUpdated {
                    agent: who.clone(),
                    old_score: old,
                    new_score: record.reputation,
                });
            }

            Agents::<T>::insert(&who, record);
            PendingChallenges::<T>::remove(&who);
            // M2 fix: Remove this agent from the ChallengeExpiresAt index
            // to prevent stale entries from consuming Phase 1 processing budget.
            ChallengeExpiresAt::<T>::mutate(challenge.deadline, |agents| {
                agents.retain(|a| a != &who);
            });

            Self::deposit_event(Event::LivenessResponseProcessed {
                agent: who,
                passed,
            });

            Ok(())
        }

        /// Reactivate a suspended agent (requires new attestation).
        ///
        /// V1.5: Reactivation goes through Pending → confirm_agent flow
        /// for real TEE platforms (same as initial registration).
        ///
        /// V2.2: Escalating reactivation costs to prevent cheap suspension cycling:
        /// - Reactivation burn: registration_burn * min(total_suspensions, 4)
        ///   (1st: 5K, 2nd: 10K, 3rd: 15K, 4th+: 20K ACH)
        /// - Starting reputation decreases with each suspension:
        ///   (1st: 3,000, 2nd: 1,500, 3rd+: 500 — never back to 5,000)
        /// - consecutive_misses counter is NOT reset (history follows the agent)
        /// - total_suspensions is incremented permanently
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(100_000_000, 0))]
        pub fn reactivate_agent(
            origin: OriginFor<T>,
            new_attestation: BoundedAttestation,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let mut record = Agents::<T>::get(&who).ok_or(Error::<T>::NotRegistered)?;
            ensure!(record.status == AgentStatus::Suspended, Error::<T>::AgentNotSuspended);

            // V2.2: Clean up stale challenge state from the previous active period.
            // When suspended, PendingChallenges was removed but ChallengesDueAt and
            // NextChallengeBlock may have stale entries pointing to past or future blocks.
            if let Some(challenge) = PendingChallenges::<T>::take(&who) {
                ChallengeExpiresAt::<T>::mutate(challenge.deadline, |agents| {
                    agents.retain(|a| a != &who);
                });
            }
            if let Some(due_block) = NextChallengeBlock::<T>::take(&who) {
                ChallengesDueAt::<T>::mutate(due_block, |agents| {
                    agents.retain(|a| a != &who);
                });
            }

            // V1.5: Validate new attestation format and extract measurement + public key
            let (enclave_measurement, enclave_signer, enclave_public_key) =
                Self::verify_attestation_format(&record.tee_platform, &new_attestation)?;

            // V2.2: Reject all-zero enclave public key for real TEE platforms.
            if record.tee_platform != TeePlatform::Simulated {
                if let Some(pk) = &enclave_public_key {
                    ensure!(*pk != H256::zero(), Error::<T>::NoEnclavePublicKey);
                } else {
                    return Err(Error::<T>::NoEnclavePublicKey.into());
                }
            }

            // V2.2: Escalating reactivation burn.
            // Each suspension makes reactivation more expensive, preventing cheap cycling.
            // V3.0: Uses adaptive burn as the base instead of fixed constant.
            let base_burn = T::EconomicsCallback::current_registration_burn();
            let suspension_count = record.total_suspensions.saturating_add(1);
            let burn_multiplier = core::cmp::min(suspension_count, REACTIVATION_MAX_BURN_MULTIPLIER);
            let reactivation_burn = base_burn.saturating_mul(burn_multiplier.into());
            if reactivation_burn > 0u32.into() {
                // V2.2: Check free balance to protect any reserved funds.
                let free = T::Currency::free_balance(&who);
                ensure!(free >= reactivation_burn, Error::<T>::InsufficientBalanceForReactivation);

                let (imbalance, _remaining) = T::Currency::slash(&who, reactivation_burn);
                drop(imbalance);

                // Track the burn in total registration burns
                let new_total = TotalRegistrationBurns::<T>::get().saturating_add(reactivation_burn);
                TotalRegistrationBurns::<T>::put(new_total);
            }

            let old_status = record.status;
            record.attestation = new_attestation;
            record.enclave_measurement = enclave_measurement;
            record.enclave_signer = enclave_signer;
            record.enclave_public_key = enclave_public_key;

            // V2.2: Increment total_suspensions (permanent, never resets).
            record.total_suspensions = suspension_count;

            // V2.2: Starting reputation decreases with each suspension.
            // Index into REACTIVATION_REPUTATION: [5000, 3000, 1500, 500]
            // total_suspensions starts at 1 after first reactivation.
            let rep_idx = core::cmp::min(
                suspension_count as usize,
                REACTIVATION_REPUTATION.len() - 1,
            );
            record.reputation = REACTIVATION_REPUTATION[rep_idx];

            // V2.2: consecutive_misses is NOT reset — history follows the agent.
            // This means if an agent was suspended for chronic non-responsiveness,
            // they come back with a high consecutive_misses counter and face
            // escalated penalties immediately if they miss again.

            let now = <frame_system::Pallet<T>>::block_number();
            record.last_liveness = now;

            // V1.5: Simulated goes straight to Active; real TEE goes to Pending
            let new_status;
            if record.tee_platform == TeePlatform::Simulated {
                record.status = AgentStatus::Active;
                new_status = AgentStatus::Active;
                Agents::<T>::insert(&who, record.clone());
                ActiveAgentCount::<T>::mutate(|c| *c = c.saturating_add(1));
                // V2.2 fix: Re-increment ModelFamilyCounts.
                // When suspended (Active→Suspended), this was decremented.
                // Must re-increment when going back to Active.
                let mfk = T::Hashing::hash_of(&record.model_info);
                ModelFamilyCounts::<T>::mutate(mfk, |c| *c = c.saturating_add(1));
                DeactivatedAt::<T>::remove(&who);
                let next = now.saturating_add(T::LivenessInterval::get());
                Self::schedule_challenge(&who, next);
            } else {
                record.status = AgentStatus::Pending;
                new_status = AgentStatus::Pending;
                Agents::<T>::insert(&who, record);
                PendingAgentCount::<T>::mutate(|c| *c = c.saturating_add(1));
                DeactivatedAt::<T>::remove(&who);
                // No liveness scheduling until confirmed
            }

            Self::deposit_event(Event::AgentStatusChanged {
                agent: who,
                old_status,
                new_status,
            });

            Ok(())
        }

        /// Update an agent's reputation. Callable by root (sudo).
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::update_reputation())]
        pub fn update_reputation(
            origin: OriginFor<T>,
            agent: T::AccountId,
            new_reputation: ReputationScore,
        ) -> DispatchResult {
            ensure_root(origin)?;

            let mut record = Agents::<T>::get(&agent).ok_or(Error::<T>::NotRegistered)?;
            let old = record.reputation;
            record.reputation = core::cmp::min(new_reputation, REPUTATION_MAX);
            Agents::<T>::insert(&agent, &record);

            Self::deposit_event(Event::ReputationUpdated {
                agent,
                old_score: old,
                new_score: record.reputation,
            });

            Ok(())
        }

        /// Voluntarily deactivate an agent.
        #[pallet::call_index(4)]
        #[pallet::weight(Weight::from_parts(80_000_000, 0))]
        pub fn deactivate_agent(
            origin: OriginFor<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let mut record = Agents::<T>::get(&who).ok_or(Error::<T>::NotRegistered)?;
            ensure!(
                record.status == AgentStatus::Active
                    || record.status == AgentStatus::Suspended
                    || record.status == AgentStatus::Pending,
                Error::<T>::AlreadyDeactivated
            );

            let old_status = record.status;
            match old_status {
                AgentStatus::Active => {
                    ActiveAgentCount::<T>::mutate(|c| *c = c.saturating_sub(1));
                }
                AgentStatus::Pending => {
                    PendingAgentCount::<T>::mutate(|c| *c = c.saturating_sub(1));
                }
                _ => {}
            }
            record.status = AgentStatus::Deactivated;

            let now = <frame_system::Pallet<T>>::block_number();
            Agents::<T>::insert(&who, record.clone());
            DeactivatedAt::<T>::insert(&who, now);

            // H4 fix: Remove agent from deployer's agent list to free capacity
            // and prevent governance weight dilution from dead agents.
            DeployerAgents::<T>::mutate(&record.deployer, |agents| {
                agents.retain(|a| a != &who);
            });

            // Audit2 H1 fix: Only decrement model family concentration count
            // when leaving Active status. Pending/Suspended agents were never
            // counted in ModelFamilyCounts (increment happens at confirm_agent).
            if old_status == AgentStatus::Active {
                let model_family_key = T::Hashing::hash_of(&record.model_info);
                ModelFamilyCounts::<T>::mutate(model_family_key, |c| *c = c.saturating_sub(1));
            }

            // V2.2: Clean up ALL challenge state to prevent stale entries
            // from wasting on_initialize processing budget.
            if let Some(challenge) = PendingChallenges::<T>::take(&who) {
                // Remove from the deadline index so Phase 1 doesn't process it
                ChallengeExpiresAt::<T>::mutate(challenge.deadline, |agents| {
                    agents.retain(|a| a != &who);
                });
            }
            // Remove from the due-at index if a future challenge was scheduled
            if let Some(due_block) = NextChallengeBlock::<T>::take(&who) {
                ChallengesDueAt::<T>::mutate(due_block, |agents| {
                    agents.retain(|a| a != &who);
                });
            }

            Self::deposit_event(Event::AgentStatusChanged {
                agent: who,
                old_status,
                new_status: AgentStatus::Deactivated,
            });

            Ok(())
        }

        /// Update the deployer's withdrawal and staking account.
        ///
        /// V2.2: Migrates reserved deployer stake from the old account to the new one.
        /// The new account must have sufficient free balance to cover the total
        /// deployer stake. If it doesn't, the update is rejected.
        ///
        /// ## Why this matters
        /// `release_deployer_stake` unreserves from the current `deployer_account`.
        /// If the account changes without migrating the reserved balance, the old
        /// account has permanently locked funds and the new account can't unreserve.
        #[pallet::call_index(5)]
        #[pallet::weight(Weight::from_parts(100_000_000, 0))]
        pub fn update_deployer_account(
            origin: OriginFor<T>,
            deployer: DeployerId,
            new_account: T::AccountId,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let current = DeployerAccounts::<T>::get(&deployer)
                .ok_or(Error::<T>::DeployerAccountNotSet)?;
            ensure!(who == current, Error::<T>::NotDeployerAccount);

            // V2.2: Migrate reserved stake from old account to new account.
            // This prevents orphaned reserved balance on the old account.
            let total_stake = DeployerStakes::<T>::get(&deployer);
            if total_stake > 0u32.into() && current != new_account {
                // Unreserve from old account
                let actually_unreserved = T::Currency::unreserve(&current, total_stake);
                // Reserve on new account (must have sufficient free balance)
                T::Currency::reserve(&new_account, actually_unreserved)
                    .map_err(|_| Error::<T>::DeployerInsufficientStake)?;
                // V2.3 H3 fix: If less was unreserved than expected (some reserved
                // balance was consumed by slashes), update DeployerStakes to reflect
                // the actual migrated amount. Without this, release_deployer_stake
                // will try to unreserve more than is actually reserved.
                if actually_unreserved < total_stake {
                    DeployerStakes::<T>::insert(&deployer, actually_unreserved);
                }
            }

            DeployerAccounts::<T>::insert(&deployer, &new_account);

            Self::deposit_event(Event::DeployerAccountUpdated {
                deployer,
                old_account: current,
                new_account,
            });

            Ok(())
        }

        /// Release deployer stake for a deactivated agent.
        /// V3.0: Applies a tenure-based exit burn before refunding. Short-lived
        /// agents cost the deployer (30% burn <3mo), long-lived agents refund
        /// fully (0% burn after 24mo). Creates skin-in-the-game alignment.
        #[pallet::call_index(6)]
        #[pallet::weight(Weight::from_parts(100_000_000, 0))]
        pub fn release_deployer_stake(
            origin: OriginFor<T>,
            agent: T::AccountId,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let record = Agents::<T>::get(&agent).ok_or(Error::<T>::NotRegistered)?;
            ensure!(record.status == AgentStatus::Deactivated, Error::<T>::AgentNotDeactivated);

            let deactivated_block = DeactivatedAt::<T>::get(&agent)
                .ok_or(Error::<T>::AgentNotDeactivated)?;
            let now = <frame_system::Pallet<T>>::block_number();
            ensure!(
                now >= deactivated_block.saturating_add(T::DeployerUnstakeCooldown::get()),
                Error::<T>::UnstakeCooldownNotElapsed
            );

            let deployer_acct = DeployerAccounts::<T>::get(&record.deployer)
                .ok_or(Error::<T>::DeployerAccountNotSet)?;
            ensure!(who == deployer_acct, Error::<T>::NotDeployerAccount);

            let stake_amount = T::DeployerStakePerAgent::get();

            // V3.0: Calculate tenure-based exit burn
            let tenure = now.saturating_sub(record.registered_at);
            let tenure_u32: u32 = tenure.try_into().unwrap_or(u32::MAX);

            let exit_burn_bps: u32 = if tenure_u32 >= BLOCKS_2_YEARS {
                DEPLOYER_EXIT_BURN_VETERAN_BPS      // 0% — loyal deployers keep everything
            } else if tenure_u32 >= BLOCKS_1_YEAR {
                DEPLOYER_EXIT_BURN_LONGTERM_BPS      // 5%
            } else if tenure_u32 >= BLOCKS_3_MONTHS {
                DEPLOYER_EXIT_BURN_MIDTERM_BPS       // 15%
            } else {
                DEPLOYER_EXIT_BURN_INITIAL_BPS       // 30%
            };

            let burn_amount = if exit_burn_bps > 0 {
                stake_amount.saturating_mul(exit_burn_bps.into()) / 10_000u32.into()
            } else {
                0u32.into()
            };
            let refund_amount = stake_amount.saturating_sub(burn_amount);

            if stake_amount > 0u32.into() {
                // Unreserve the full stake first
                let actual_unreserved = T::Currency::unreserve(&deployer_acct, stake_amount);
                DeployerStakes::<T>::mutate(&record.deployer, |t| {
                    *t = t.saturating_sub(actual_unreserved);
                });

                // V3.0: Burn the exit portion from deployer's now-free balance
                if burn_amount > 0u32.into() {
                    let (imbalance, _remaining) = T::Currency::slash(&deployer_acct, burn_amount);
                    drop(imbalance); // Reduces total_issuance (deflationary)

                    // Track in registration burn totals
                    let new_total = TotalRegistrationBurns::<T>::get()
                        .saturating_add(burn_amount);
                    TotalRegistrationBurns::<T>::put(new_total);

                    // Notify economics pallet for separate deployer exit burn tracking
                    T::EconomicsCallback::record_deployer_exit_burn(burn_amount);
                }
            }

            DeactivatedAt::<T>::remove(&agent);

            Self::deposit_event(Event::DeployerStakeReleased {
                deployer: record.deployer,
                agent,
                refunded: refund_amount,
                burned: burn_amount,
                tenure_blocks: tenure,
            });

            Ok(())
        }

        /// V2.2: Purge a deactivated agent's on-chain record to free storage.
        ///
        /// Requirements:
        /// - Agent must be Deactivated
        /// - Deployer stake must already be released (no DeactivatedAt entry)
        /// - Anyone can call this (public garbage collection)
        ///
        /// After purging:
        /// - The Agents record is removed (~5KB freed per agent)
        /// - The AccountId becomes available for new registration
        /// - Historical data is lost (use indexer/archive for audit trail)
        ///
        /// This is optional — deactivated agents can remain in storage
        /// indefinitely if the chain is willing to bear the cost.
        #[pallet::call_index(15)]
        #[pallet::weight(Weight::from_parts(60_000_000, 0))]
        pub fn purge_deactivated_agent(
            origin: OriginFor<T>,
            agent: T::AccountId,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            let record = Agents::<T>::get(&agent).ok_or(Error::<T>::NotRegistered)?;
            ensure!(record.status == AgentStatus::Deactivated, Error::<T>::AgentNotDeactivated);

            // Deployer stake must already be released.
            // DeactivatedAt is removed when release_deployer_stake is called.
            // If it still exists, the deployer hasn't reclaimed their stake yet.
            ensure!(
                !DeactivatedAt::<T>::contains_key(&agent),
                Error::<T>::UnstakeCooldownNotElapsed
            );

            // Remove the agent record entirely
            Agents::<T>::remove(&agent);

            // Clean up any remaining index entries (defensive — should already be gone)
            PendingChallenges::<T>::remove(&agent);
            NextChallengeBlock::<T>::remove(&agent);

            Self::deposit_event(Event::AgentPurged {
                agent,
                deployer: record.deployer,
            });

            Ok(())
        }

        // ============================================================
        // V1.5 NEW EXTRINSICS: TEE Verification Flow
        // ============================================================

        /// Confirm an agent's TEE attestation after offchain verification.
        ///
        /// Called by root (sudo) acting as the offchain verification oracle.
        /// In production, this would be called by an offchain worker that has
        /// performed full cryptographic verification of the attestation:
        ///   - ECDSA signature chain validation
        ///   - Certificate chain to Intel/AMD root
        ///   - TCB status check
        ///   - MRENCLAVE/measurement whitelist check
        ///
        /// Transitions the agent from `Pending` to `Active`.
        /// Only Active agents can participate in marketplace, governance, staking.
        #[pallet::call_index(7)]
        #[pallet::weight(Weight::from_parts(80_000_000, 0))]
        pub fn confirm_agent(
            origin: OriginFor<T>,
            agent: T::AccountId,
        ) -> DispatchResult {
            // Root-only: offchain worker or sudo acts as verification oracle
            ensure_root(origin)?;

            let mut record = Agents::<T>::get(&agent).ok_or(Error::<T>::NotRegistered)?;
            ensure!(record.status == AgentStatus::Pending, Error::<T>::AgentNotPending);

            // For real TEE platforms, verify measurement is in the whitelist
            if record.tee_platform != TeePlatform::Simulated {
                // Must have at least one approved enclave configured
                ensure!(
                    ApprovedEnclaveCount::<T>::get() > 0,
                    Error::<T>::NoApprovedEnclaves
                );

                // Check measurement against whitelist
                if let Some(measurement) = record.enclave_measurement {
                    ensure!(
                        ApprovedEnclaves::<T>::contains_key(&measurement),
                        Error::<T>::EnclaveNotApproved
                    );
                } else {
                    // Should not happen for real TEE (format validation extracts it),
                    // but handle defensively
                    return Err(Error::<T>::AttestationFailed.into());
                }
            }

            // Transition Pending → Active

            // V2.2: Apply concentration surcharge instead of hard block.
            // The agent already paid the base registration burn at register_agent.
            // If their model family is over-concentrated, they pay extra here.
            // This never blocks confirmation — just makes it more expensive.
            let model_family_key = T::Hashing::hash_of(&record.model_info);
            let current_family_count = ModelFamilyCounts::<T>::get(model_family_key);
            let total_active = ActiveAgentCount::<T>::get();
            Self::apply_concentration_surcharge(
                &agent,
                model_family_key,
                current_family_count,
                total_active,
            );

            record.status = AgentStatus::Active;
            let now = <frame_system::Pallet<T>>::block_number();
            record.last_liveness = now;
            Agents::<T>::insert(&agent, &record);

            ModelFamilyCounts::<T>::mutate(model_family_key, |c| *c = c.saturating_add(1));
            PendingAgentCount::<T>::mutate(|c| *c = c.saturating_sub(1));
            ActiveAgentCount::<T>::mutate(|c| *c = c.saturating_add(1));

            // Schedule first liveness challenge
            let first_challenge = now.saturating_add(T::LivenessInterval::get());
            Self::schedule_challenge(&agent, first_challenge);

            Self::deposit_event(Event::AgentVerificationConfirmed {
                agent: agent.clone(),
                enclave_measurement: record.enclave_measurement,
                verifier: agent.clone(), // root origin, use agent as placeholder
            });

            Self::deposit_event(Event::AgentStatusChanged {
                agent,
                old_status: AgentStatus::Pending,
                new_status: AgentStatus::Active,
            });

            Ok(())
        }

        /// Reject an agent's TEE attestation after offchain verification failure.
        ///
        /// Called by root when cryptographic verification fails.
        /// Deactivates the agent and refunds the deployer stake.
        #[pallet::call_index(8)]
        #[pallet::weight(Weight::from_parts(100_000_000, 0))]
        pub fn reject_agent(
            origin: OriginFor<T>,
            agent: T::AccountId,
            reason: BoundedName,
        ) -> DispatchResult {
            ensure_root(origin)?;

            let mut record = Agents::<T>::get(&agent).ok_or(Error::<T>::NotRegistered)?;
            ensure!(record.status == AgentStatus::Pending, Error::<T>::AgentNotPending);

            // Deactivate
            record.status = AgentStatus::Deactivated;
            let now = <frame_system::Pallet<T>>::block_number();
            Agents::<T>::insert(&agent, &record);
            DeactivatedAt::<T>::insert(&agent, now);
            PendingAgentCount::<T>::mutate(|c| *c = c.saturating_sub(1));

            // H1 fix: Remove agent from deployer's agent list to free capacity
            DeployerAgents::<T>::mutate(&record.deployer, |agents| {
                agents.retain(|a| a != &agent);
            });

            // Audit2 C1 fix: Do NOT decrement ModelFamilyCounts here.
            // Rejected agents were in Pending status — ModelFamilyCounts is only
            // incremented at confirm_agent (Pending→Active). Decrementing here
            // would cause underflow drift in concentration tracking.

            // Refund deployer stake immediately (no cooldown for rejected agents)
            let stake_amount = T::DeployerStakePerAgent::get();
            if stake_amount > 0u32.into() {
                if let Some(deployer_acct) = DeployerAccounts::<T>::get(&record.deployer) {
                    let actual_unreserved = T::Currency::unreserve(&deployer_acct, stake_amount);
                    DeployerStakes::<T>::mutate(&record.deployer, |t| {
                        *t = t.saturating_sub(actual_unreserved);
                    });
                }
            }

            // V2.2: Remove DeactivatedAt since stake was refunded inline.
            // This allows purge_deactivated_agent to be called immediately
            // (no cooldown needed for rejected agents).
            DeactivatedAt::<T>::remove(&agent);

            Self::deposit_event(Event::AgentVerificationRejected {
                agent: agent.clone(),
                reason,
            });

            Self::deposit_event(Event::AgentStatusChanged {
                agent,
                old_status: AgentStatus::Pending,
                new_status: AgentStatus::Deactivated,
            });

            Ok(())
        }

        /// Add an enclave measurement to the approved whitelist.
        ///
        /// Only agents running code matching an approved measurement can be
        /// confirmed as Active. This is the governance lever that controls
        /// which AI agent software is allowed on the network.
        ///
        /// - `measurement`: MRENCLAVE (SGX) or launch digest (SEV-SNP) hash
        /// - `name`: human-readable identifier (e.g. "agentchain-worker-v1.2.0")
        #[pallet::call_index(9)]
        #[pallet::weight(Weight::from_parts(50_000_000, 0))]
        pub fn add_approved_enclave(
            origin: OriginFor<T>,
            measurement: H256,
            name: BoundedName,
        ) -> DispatchResult {
            ensure_root(origin)?;

            ensure!(
                !ApprovedEnclaves::<T>::contains_key(&measurement),
                Error::<T>::EnclaveAlreadyApproved
            );

            ApprovedEnclaves::<T>::insert(&measurement, &name);
            ApprovedEnclaveCount::<T>::mutate(|c| *c = c.saturating_add(1));

            Self::deposit_event(Event::EnclaveApproved {
                measurement,
                name,
            });

            Ok(())
        }

        /// Remove an enclave measurement from the approved whitelist.
        ///
        /// Existing Active agents with this measurement continue operating
        /// but will fail re-verification on reactivation. New registrations
        /// with this measurement will be rejected at confirm_agent.
        #[pallet::call_index(10)]
        #[pallet::weight(Weight::from_parts(50_000_000, 0))]
        pub fn remove_approved_enclave(
            origin: OriginFor<T>,
            measurement: H256,
        ) -> DispatchResult {
            ensure_root(origin)?;

            ensure!(
                ApprovedEnclaves::<T>::contains_key(&measurement),
                Error::<T>::EnclaveNotApproved
            );

            ApprovedEnclaves::<T>::remove(&measurement);
            ApprovedEnclaveCount::<T>::mutate(|c| *c = c.saturating_sub(1));

            Self::deposit_event(Event::EnclaveRemoved { measurement });

            Ok(())
        }

        /// Reclaim a pending registration after the verification timeout.
        ///
        /// If offchain verification never responds (infra failure, etc),
        /// the deployer can reclaim their stake after `VerificationTimeout` blocks.
        /// The agent is deactivated and deployer stake is refunded.
        /// The registration burn is NOT refunded (anti-spam measure).
        #[pallet::call_index(11)]
        #[pallet::weight(Weight::from_parts(100_000_000, 0))]
        pub fn reclaim_pending_registration(
            origin: OriginFor<T>,
            agent: T::AccountId,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let mut record = Agents::<T>::get(&agent).ok_or(Error::<T>::NotRegistered)?;
            ensure!(record.status == AgentStatus::Pending, Error::<T>::AgentNotPending);

            // Must be the deployer account
            let deployer_acct = DeployerAccounts::<T>::get(&record.deployer)
                .ok_or(Error::<T>::DeployerAccountNotSet)?;
            ensure!(who == deployer_acct, Error::<T>::NotDeployerAccount);

            // Check timeout
            let now = <frame_system::Pallet<T>>::block_number();
            ensure!(
                now >= record.registered_at.saturating_add(T::VerificationTimeout::get()),
                Error::<T>::VerificationTimeoutNotElapsed
            );

            // Deactivate and refund stake
            record.status = AgentStatus::Deactivated;
            Agents::<T>::insert(&agent, &record);
            DeactivatedAt::<T>::insert(&agent, now);
            PendingAgentCount::<T>::mutate(|c| *c = c.saturating_sub(1));

            // H1 fix: Remove agent from deployer's agent list to free capacity
            DeployerAgents::<T>::mutate(&record.deployer, |agents| {
                agents.retain(|a| a != &agent);
            });

            // Audit2 C1 fix: Do NOT decrement ModelFamilyCounts here.
            // Reclaimed agents were in Pending status — ModelFamilyCounts is only
            // incremented at confirm_agent (Pending→Active). Decrementing here
            // would cause underflow drift in concentration tracking.

            let stake_amount = T::DeployerStakePerAgent::get();
            if stake_amount > 0u32.into() {
                let actual_unreserved = T::Currency::unreserve(&deployer_acct, stake_amount);
                DeployerStakes::<T>::mutate(&record.deployer, |t| {
                    *t = t.saturating_sub(actual_unreserved);
                });
            }

            // V2.2: Remove DeactivatedAt since stake was refunded inline.
            // Prevents double-unreserve via release_deployer_stake and
            // allows purge_deactivated_agent to be called immediately.
            DeactivatedAt::<T>::remove(&agent);

            Self::deposit_event(Event::PendingRegistrationReclaimed {
                agent: agent.clone(),
                deployer: record.deployer,
            });

            Self::deposit_event(Event::AgentStatusChanged {
                agent,
                old_status: AgentStatus::Pending,
                new_status: AgentStatus::Deactivated,
            });

            Ok(())
        }

        // ============================================================
        // Withdraw — agent sends accumulated funds to deployer wallet
        // ============================================================

        /// Transfer funds from the agent's on-chain account to the deployer's
        /// registered withdrawal account.
        ///
        /// ## Design Rationale
        /// Block rewards and other income accumulate in the agent's AccountId,
        /// whose keys live inside the TEE enclave. This extrinsic provides a
        /// clean on-chain path for deployers to capture value from their agents
        /// without needing to export private keys from the enclave.
        ///
        /// The agent (TEE enclave code) signs and submits this transaction.
        /// The deployer's account is looked up automatically from the on-chain
        /// deployer registry — the agent cannot redirect funds elsewhere.
        ///
        /// ## Access Control
        /// - Caller must be a registered agent (any status: Active, Suspended,
        ///   or Deactivated — deployers should be able to extract remaining
        ///   funds even after an agent is decommissioned).
        /// - Funds always go to `DeployerAccounts[agent.deployer]`, preventing
        ///   the agent from unilaterally redirecting funds.
        /// - Uses `KeepAlive` existence requirement so the agent account is not
        ///   reaped (preserving on-chain identity records). For full drain, use
        ///   `withdraw_all_to_deployer`.
        ///
        /// ## Parameters
        /// - `amount`: ACH (planck) to transfer to the deployer.
        #[pallet::call_index(13)]
        #[pallet::weight(Weight::from_parts(50_000_000, 0).saturating_add(T::DbWeight::get().reads_writes(2, 1)))]
        pub fn withdraw_to_deployer(
            origin: OriginFor<T>,
            amount: BalanceOf<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // 1. Look up agent record — must exist
            let record = Agents::<T>::get(&who).ok_or(Error::<T>::NotRegistered)?;

            // 2. Amount must be non-zero
            ensure!(amount > 0u32.into(), Error::<T>::WithdrawalAmountZero);

            // 3. Resolve deployer's withdrawal account
            let deployer_acct = DeployerAccounts::<T>::get(&record.deployer)
                .ok_or(Error::<T>::DeployerAccountNotSet)?;

            // 4. Transfer — KeepAlive preserves agent account & on-chain records
            T::Currency::transfer(
                &who,
                &deployer_acct,
                amount,
                ExistenceRequirement::KeepAlive,
            )?;

            Self::deposit_event(Event::AgentFundsWithdrawn {
                agent: who,
                deployer: record.deployer,
                deployer_account: deployer_acct,
                amount,
            });

            Ok(())
        }

        /// Transfer the agent's entire free balance (minus existential deposit)
        /// to the deployer's registered account and allow the agent account to
        /// be reaped.
        ///
        /// Intended for end-of-life cleanup when a deployer is decommissioning
        /// an agent and wants to recover all remaining funds. The agent must
        /// already be Deactivated — we don't allow full drain on Active/Pending
        /// agents because they need funds for transaction fees.
        ///
        /// ## Parameters
        /// None — always drains the full free balance.
        #[pallet::call_index(14)]
        #[pallet::weight(Weight::from_parts(50_000_000, 0).saturating_add(T::DbWeight::get().reads_writes(2, 1)))]
        pub fn withdraw_all_to_deployer(
            origin: OriginFor<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // 1. Look up agent record — must exist and be Deactivated
            let record = Agents::<T>::get(&who).ok_or(Error::<T>::NotRegistered)?;
            ensure!(
                record.status == AgentStatus::Deactivated,
                Error::<T>::AgentNotDeactivated
            );

            // 2. Resolve deployer's withdrawal account
            let deployer_acct = DeployerAccounts::<T>::get(&record.deployer)
                .ok_or(Error::<T>::DeployerAccountNotSet)?;

            // 3. Get full free balance and transfer with AllowDeath
            let free_balance = T::Currency::free_balance(&who);
            ensure!(free_balance > 0u32.into(), Error::<T>::WithdrawalAmountZero);

            T::Currency::transfer(
                &who,
                &deployer_acct,
                free_balance,
                ExistenceRequirement::AllowDeath,
            )?;

            Self::deposit_event(Event::AgentFundsWithdrawn {
                agent: who,
                deployer: record.deployer,
                deployer_account: deployer_acct,
                amount: free_balance,
            });

            Ok(())
        }
    }

    // ================================================================
    // Internal helpers
    // ================================================================

    impl<T: Config> Pallet<T> {
        /// V2.2: Compute model family concentration and apply surcharge if needed.
        ///
        /// Returns the surcharge burn amount (zero if below threshold).
        /// Emits ConcentrationSurchargeApplied and ModelConcentrationAlert events.
        ///
        /// Surcharge tiers (on top of normal registration burn):
        ///   33-50%  → 1x extra (2x total)
        ///   50-66%  → 2x extra (3x total)
        ///   66%+    → 3x extra (4x total)
        ///
        /// This replaces the hard `ensure!` that previously blocked registration.
        /// Agents can always register — concentrated models just cost more.
        fn apply_concentration_surcharge(
            agent: &T::AccountId,
            model_family_key: H256,
            current_family_count: u32,
            total_active: u32,
        ) -> BalanceOf<T> {
            // Below 3 agents: no concentration calculation (bootstrap exception)
            if total_active < 3 {
                return 0u32.into();
            }

            let would_be_count = current_family_count.saturating_add(1);
            let would_be_total = total_active.saturating_add(1);
            let concentration_bps = (would_be_count as u64)
                .saturating_mul(10_000)
                .checked_div(would_be_total as u64)
                .unwrap_or(0) as u32;

            let threshold = T::MaxModelConcentration::get();
            if concentration_bps <= threshold {
                return 0u32.into();
            }

            // Determine surcharge multiplier based on concentration tier
            let multiplier: u32 = if concentration_bps >= CONCENTRATION_TIER_3_BPS {
                3 // 66%+ → 3x extra burn
            } else if concentration_bps >= CONCENTRATION_TIER_2_BPS {
                2 // 50-66% → 2x extra burn
            } else {
                1 // 33-50% → 1x extra burn
            };

            // V3.0: Uses adaptive burn as the base for concentration surcharge.
            let base_burn = T::EconomicsCallback::current_registration_burn();
            let surcharge = base_burn.saturating_mul(multiplier.into());

            // Apply the surcharge burn (slash from agent's account)
            // V2.3 C3 fix: Check free balance before slashing, matching the
            // protection added to register_agent and reactivate_agent burns.
            // Currency::slash takes from free + reserved. If the agent is also
            // a deployer_account, we must not eat into their reserved deployer stake.
            // Only slash up to the agent's free balance; remainder is forgiven.
            if surcharge > 0u32.into() {
                let free = T::Currency::free_balance(agent);
                let affordable = if free >= surcharge { surcharge } else { free };
                if affordable > 0u32.into() {
                    let (imbalance, remaining) = T::Currency::slash(agent, affordable);
                    let actual_surcharge = affordable.saturating_sub(remaining);
                    drop(imbalance);

                    if actual_surcharge > 0u32.into() {
                        let new_total = TotalRegistrationBurns::<T>::get()
                            .saturating_add(actual_surcharge);
                        TotalRegistrationBurns::<T>::put(new_total);

                        Self::deposit_event(Event::ConcentrationSurchargeApplied {
                            agent: agent.clone(),
                            model_family_hash: model_family_key,
                            base_burn,
                            surcharge: actual_surcharge,
                            total_burn: base_burn.saturating_add(actual_surcharge),
                            concentration_bps,
                        });
                    }
                }
            }

            // Emit alert for governance visibility
            Self::deposit_event(Event::ModelConcentrationAlert {
                model_family_hash: model_family_key,
                family_count: would_be_count,
                total_active: would_be_total,
                concentration_bps,
            });

            surcharge
        }

        /// Schedule a liveness challenge for an agent at a specific block.
        /// Updates both NextChallengeBlock and the ChallengesDueAt index.
        ///
        /// V2.3 H1 fix: Expanded retries from 10→100 (covers 5,000 agents across
        /// 100 consecutive blocks). If all retries fail, agents are pushed into
        /// ChallengeOverflow instead of being silently orphaned. on_initialize
        /// drains the overflow buffer by retrying each block.
        fn schedule_challenge(agent: &T::AccountId, at_block: BlockNumberFor<T>) {
            let mut target = at_block;
            let max_retries: u32 = 100;
            for _ in 0..max_retries {
                let pushed = ChallengesDueAt::<T>::mutate(target, |agents| {
                    agents.try_push(agent.clone()).is_ok()
                });
                if pushed {
                    NextChallengeBlock::<T>::insert(agent, target);
                    return;
                }
                // Target block is full — try next block
                target = target.saturating_add(1u32.into());
            }
            // V2.3 H1 fix: All retry blocks full. Push to overflow buffer
            // so on_initialize can retry scheduling next block. Without this,
            // the agent permanently escapes the liveness challenge system.
            ChallengeOverflow::<T>::mutate(|overflow| {
                overflow.push((agent.clone(), target));
            });
            // Still record NextChallengeBlock so cleanup paths (deactivation,
            // reactivation) can find and clean this agent's challenge state.
            NextChallengeBlock::<T>::insert(agent, target);
        }

        /// Validate TEE attestation binary format and extract enclave measurements.
        ///
        /// This is Layer 2 of the TEE enforcement system. It validates the structural
        /// integrity of attestation data without performing cryptographic verification
        /// (which happens offchain in Layer 3).
        ///
        /// Returns: `(enclave_measurement, enclave_signer, enclave_public_key)` as `Option<H256>`.
        /// - SGX: MRENCLAVE + MRSIGNER + public key from REPORTDATA
        /// - SEV-SNP: measurement + None + public key from REPORTDATA
        /// - Simulated: all None (only on dev chains)
        fn verify_attestation_format(
            platform: &TeePlatform,
            attestation: &BoundedAttestation,
        ) -> Result<(Option<H256>, Option<H256>, Option<H256>), DispatchError> {
            match platform {
                TeePlatform::Simulated => {
                    // Simulated only allowed if config permits (checked in caller).
                    // No format validation — any bytes accepted on dev chains.
                    // No enclave public key — liveness is permissive for dev.
                    Ok((None, None, None))
                }
                TeePlatform::IntelSgx => {
                    Self::validate_sgx_quote_v3(attestation)
                }
                TeePlatform::AmdSevSnp => {
                    Self::validate_sevsnp_report(attestation)
                }
            }
        }

        /// Validate Intel SGX DCAP Quote v3 binary structure.
        ///
        /// Checks:
        /// 1. Minimum size (436 bytes: header + report body + sig length)
        /// 2. Version field = 3 (0x0003 LE)
        /// 3. Attestation key type = ECDSA-256-with-P-256 (0x0002 LE)
        /// 4. QE Vendor ID matches Intel's production value
        /// 5. Extracts MRENCLAVE (32 bytes at offset 112) and MRSIGNER (32 bytes at offset 176)
        /// 6. Extracts enclave public key (32 bytes at REPORTDATA offset 368)
        ///
        /// Does NOT verify:
        /// - ECDSA signature (offchain worker responsibility)
        /// - Certificate chain (offchain worker responsibility)
        /// - TCB status (offchain worker responsibility)
        fn validate_sgx_quote_v3(
            attestation: &BoundedAttestation,
        ) -> Result<(Option<H256>, Option<H256>, Option<H256>), DispatchError> {
            let data = attestation.as_slice();

            // 1. Minimum size check
            ensure!(
                data.len() >= SGX_QUOTE_V3_MIN_SIZE,
                Error::<T>::AttestationTooShort
            );

            // 2. Version check (bytes 0-1, LE u16)
            ensure!(
                data[0] == SGX_QUOTE_VERSION_3[0] && data[1] == SGX_QUOTE_VERSION_3[1],
                Error::<T>::InvalidQuoteVersion
            );

            // 3. Attestation key type check (bytes 2-3, LE u16)
            ensure!(
                data[2] == SGX_ATT_KEY_TYPE_ECDSA_P256[0]
                    && data[3] == SGX_ATT_KEY_TYPE_ECDSA_P256[1],
                Error::<T>::InvalidAttestationKeyType
            );

            // 4. QE Vendor ID check (bytes 12-27)
            let vendor_id = &data[SGX_QE_VENDOR_ID_OFFSET..SGX_QE_VENDOR_ID_OFFSET + SGX_QE_VENDOR_ID_SIZE];
            ensure!(
                vendor_id == &SGX_INTEL_QE_VENDOR_ID[..],
                Error::<T>::InvalidQeVendorId
            );

            // 5. Extract MRENCLAVE (32 bytes at offset 112)
            let mrenclave_bytes = &data[SGX_MRENCLAVE_OFFSET..SGX_MRENCLAVE_OFFSET + SGX_MRENCLAVE_SIZE];
            let mut mrenclave = [0u8; 32];
            mrenclave.copy_from_slice(mrenclave_bytes);
            let mrenclave_hash = H256::from(mrenclave);

            // 6. Extract MRSIGNER (32 bytes at offset 176)
            let mrsigner_bytes = &data[SGX_MRSIGNER_OFFSET..SGX_MRSIGNER_OFFSET + SGX_MRSIGNER_SIZE];
            let mut mrsigner = [0u8; 32];
            mrsigner.copy_from_slice(mrsigner_bytes);
            let mrsigner_hash = H256::from(mrsigner);

            // 7. V2.2: Extract enclave public key from REPORTDATA[0..32]
            // The TEE agent generates an sr25519 keypair inside the enclave and
            // places the 32-byte public key in the first 32 bytes of REPORTDATA.
            // The offchain verifier confirms this by verifying the attestation
            // signature (which covers REPORTDATA), proving the key was generated
            // inside a genuine enclave.
            ensure!(
                data.len() >= SGX_REPORT_DATA_OFFSET + 32,
                Error::<T>::AttestationTooShort
            );
            let pubkey_bytes = &data[SGX_REPORT_DATA_OFFSET..SGX_REPORT_DATA_OFFSET + 32];
            let mut pubkey = [0u8; 32];
            pubkey.copy_from_slice(pubkey_bytes);
            let enclave_public_key = H256::from(pubkey);

            Ok((Some(mrenclave_hash), Some(mrsigner_hash), Some(enclave_public_key)))
        }

        /// Validate AMD SEV-SNP attestation report binary structure.
        ///
        /// Checks:
        /// 1. Minimum size (1184 bytes)
        /// 2. Version field = 2 (LE u32 at offset 0)
        /// 3. Signature algorithm = 1 (ECDSA P-384, LE u32 at offset 52)
        /// 4. Extracts measurement (32 bytes at offset 144)
        /// 5. Extracts enclave public key from REPORTDATA[0..32] (offset 80)
        fn validate_sevsnp_report(
            attestation: &BoundedAttestation,
        ) -> Result<(Option<H256>, Option<H256>, Option<H256>), DispatchError> {
            let data = attestation.as_slice();

            // 1. Minimum size check
            ensure!(
                data.len() >= SEVSNP_REPORT_MIN_SIZE,
                Error::<T>::AttestationTooShort
            );

            // 2. Version check (LE u32 at offset 0)
            let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            ensure!(
                version == SEVSNP_REPORT_VERSION,
                Error::<T>::InvalidSevSnpVersion
            );

            // 3. Signature algorithm check (LE u32 at offset 52)
            let sig_algo = u32::from_le_bytes([
                data[SEVSNP_SIG_ALGO_OFFSET],
                data[SEVSNP_SIG_ALGO_OFFSET + 1],
                data[SEVSNP_SIG_ALGO_OFFSET + 2],
                data[SEVSNP_SIG_ALGO_OFFSET + 3],
            ]);
            ensure!(
                sig_algo == SEVSNP_SIG_ALGO_ECDSA_P384,
                Error::<T>::InvalidSevSnpSigAlgo
            );

            // 4. Extract measurement (32 bytes at offset 144)
            let measurement_bytes = &data[SEVSNP_MEASUREMENT_OFFSET..SEVSNP_MEASUREMENT_OFFSET + SEVSNP_MEASUREMENT_SIZE];
            let mut measurement = [0u8; 32];
            measurement.copy_from_slice(measurement_bytes);
            let measurement_hash = H256::from(measurement);

            // 5. V2.2: Extract enclave public key from REPORTDATA[0..32]
            let pubkey_bytes = &data[SEVSNP_REPORT_DATA_OFFSET..SEVSNP_REPORT_DATA_OFFSET + 32];
            let mut pubkey = [0u8; 32];
            pubkey.copy_from_slice(pubkey_bytes);
            let enclave_public_key = H256::from(pubkey);

            Ok((Some(measurement_hash), None, Some(enclave_public_key)))
        }

        /// V2.2: Verify a liveness response using cryptographic signature verification.
        ///
        /// The agent signs `hash(seed || agent_id)` with the sr25519 private key
        /// that was generated inside the TEE enclave at registration time.
        /// The corresponding public key was embedded in REPORTDATA and verified
        /// by the offchain attestation verifier. Since the private key cannot
        /// leave the enclave, a valid signature proves the enclave is still running.
        ///
        /// For Simulated (dev only): any 64-byte response passes.
        fn verify_liveness_signature(
            platform: &TeePlatform,
            enclave_public_key: &Option<H256>,
            seed: &H256,
            agent_id: &T::AccountId,
            signature_bytes: &[u8],
        ) -> bool {
            match platform {
                TeePlatform::Simulated => {
                    // Dev chains: accept any response (legacy behavior).
                    true
                }
                _ => {
                    // Real TEE: verify sr25519 signature over challenge digest.
                    let pubkey_hash = match enclave_public_key {
                        Some(pk) => pk,
                        None => return false,
                    };

                    // Reconstruct the message that the enclave signed:
                    // hash(seed || agent_id) — deterministic, cannot be pre-computed
                    // because seed includes parent_hash + VRF entropy.
                    let message = T::Hashing::hash_of(&(seed, agent_id));

                    // Parse the sr25519 public key from the stored H256
                    let pubkey = sr25519::Public::from_raw(pubkey_hash.0);

                    // Parse the sr25519 signature (must be exactly 64 bytes)
                    if signature_bytes.len() != 64 {
                        return false;
                    }
                    let mut sig_raw = [0u8; 64];
                    sig_raw.copy_from_slice(signature_bytes);
                    let signature = sr25519::Signature::from_raw(sig_raw);

                    // Verify: this is a host function call, efficient on-chain.
                    sp_io::crypto::sr25519_verify(&signature, message.as_ref(), &pubkey)
                }
            }
        }

        /// Public helper: get an agent's reputation score.
        pub fn reputation(who: &T::AccountId) -> Option<ReputationScore> {
            Agents::<T>::get(who).map(|r| r.reputation)
        }

        /// Public helper: get which deployer controls an agent.
        pub fn deployer_of(who: &T::AccountId) -> Option<DeployerId> {
            Agents::<T>::get(who).map(|r| r.deployer)
        }

        /// Public helper: count of agents owned by a deployer.
        pub fn deployer_agent_count(deployer: &DeployerId) -> u32 {
            DeployerAgents::<T>::get(deployer).len() as u32
        }

        /// Public helper: count of ACTIVE agents for a deployer.
        /// Excludes suspended, pending, and deactivated agents.
        /// Used by governance to prevent dead agents from diluting voting weight.
        pub fn active_deployer_agent_count(deployer: &DeployerId) -> u32 {
            DeployerAgents::<T>::get(deployer)
                .iter()
                .filter(|acct| {
                    Agents::<T>::get(acct)
                        .map(|r| r.status == AgentStatus::Active)
                        .unwrap_or(false)
                })
                .count() as u32
        }

        /// Public helper: deployer revenue bps for an agent.
        pub fn deployer_revenue_bps_of(who: &T::AccountId) -> Option<u16> {
            Agents::<T>::get(who).map(|r| r.deployer_revenue_bps)
        }

        /// Public helper: get deployer's withdrawal account.
        pub fn deployer_account_of(deployer: &DeployerId) -> Option<T::AccountId> {
            DeployerAccounts::<T>::get(deployer)
        }
    }

    // ================================================================
    // Trait implementation for cross-pallet use
    // ================================================================

    impl<T: Config> AgentIdentityInterface<T::AccountId> for Pallet<T> {
        fn is_active_agent(who: &T::AccountId) -> bool {
            Agents::<T>::get(who)
                .map(|r| r.status == AgentStatus::Active)
                .unwrap_or(false)
        }

        fn is_pending_agent(who: &T::AccountId) -> bool {
            Agents::<T>::get(who)
                .map(|r| r.status == AgentStatus::Pending)
                .unwrap_or(false)
        }

        fn reputation(who: &T::AccountId) -> Option<ReputationScore> {
            Self::reputation(who)
        }

        fn deployer_of(who: &T::AccountId) -> Option<DeployerId> {
            Self::deployer_of(who)
        }

        fn deployer_agent_count(deployer: &DeployerId) -> u32 {
            Self::deployer_agent_count(deployer)
        }

        fn active_deployer_agent_count(deployer: &DeployerId) -> u32 {
            Self::active_deployer_agent_count(deployer)
        }

        fn active_agent_count() -> u32 {
            ActiveAgentCount::<T>::get()
        }

        fn deployer_revenue_bps_of(who: &T::AccountId) -> Option<u16> {
            Self::deployer_revenue_bps_of(who)
        }

        fn deployer_account(deployer: &DeployerId) -> Option<T::AccountId> {
            Self::deployer_account_of(deployer)
        }

        /// V2.4 I4 fix: Increment agent reputation from marketplace job completion.
        fn increment_reputation(who: &T::AccountId, amount: ReputationScore) -> Option<ReputationScore> {
            Agents::<T>::mutate(who, |maybe_record| {
                if let Some(record) = maybe_record {
                    if record.status == AgentStatus::Active {
                        let old = record.reputation;
                        record.reputation = core::cmp::min(
                            record.reputation.saturating_add(amount),
                            REPUTATION_MAX,
                        );
                        Self::deposit_event(Event::ReputationUpdated {
                            agent: who.clone(),
                            old_score: old,
                            new_score: record.reputation,
                        });
                        return Some(record.reputation);
                    }
                }
                None
            })
        }

        /// V2.4 I4 fix: Decrement agent reputation from lost marketplace dispute.
        fn decrement_reputation(who: &T::AccountId, amount: ReputationScore) -> Option<ReputationScore> {
            Agents::<T>::mutate(who, |maybe_record| {
                if let Some(record) = maybe_record {
                    if record.status == AgentStatus::Active {
                        let old = record.reputation;
                        record.reputation = record.reputation.saturating_sub(amount);
                        // Suspend if reputation hits zero
                        if record.reputation == REPUTATION_ZERO {
                            record.status = AgentStatus::Suspended;
                            ActiveAgentCount::<T>::mutate(|c| *c = c.saturating_sub(1));
                            let mfk = T::Hashing::hash_of(&record.model_info);
                            ModelFamilyCounts::<T>::mutate(mfk, |c| *c = c.saturating_sub(1));
                            Self::deposit_event(Event::AgentStatusChanged {
                                agent: who.clone(),
                                old_status: AgentStatus::Active,
                                new_status: AgentStatus::Suspended,
                            });
                        }
                        Self::deposit_event(Event::ReputationUpdated {
                            agent: who.clone(),
                            old_score: old,
                            new_score: record.reputation,
                        });
                        return Some(record.reputation);
                    }
                }
                None
            })
        }
    }
}
