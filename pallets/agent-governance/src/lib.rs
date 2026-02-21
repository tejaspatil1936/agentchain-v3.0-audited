//! # Agent Governance Pallet — V2 with Treasury Spending
//!
//! On-chain governance exclusively for AI agents, now with programmable
//! treasury grants administered by human stewards.
//!
//! ## Governance Proposals
//! - **Stake-weighted voting**: agents with more ACH staked have stronger voice
//! - **Deployer-adjusted voting**: weight / deployer_agents
//! - **Mandatory deliberation**: minimum period before voting
//! - **Time-locked execution**: approved proposals wait before executing
//!
//! ## Treasury Spending (V2)
//!
//! **Grants**: Agent governance votes on treasury proposals that specify
//! a recipient, steward (human admin), milestones, and fund amounts.
//!
//! **Stewards**: Human administrators coordinating agent workers and human
//! beneficiaries. Compensation is capped by protocol tier:
//!   - Small grants (<=100K ACH): up to 15%
//!   - Medium grants (<=1M ACH): up to 10%
//!   - Large grants (>1M ACH): up to 5%
//!
//! **Milestones**: Funds release incrementally as milestones complete.
//! **Clawback**: Governance can terminate underperforming grants.
//!
//! ## Voting Weight Formula
//! `weight = reputation * sqrt(stake) / deployer_agents`

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use agentchain_primitives::*;
    use frame_support::{
        pallet_prelude::*,
        traits::{Currency, ExistenceRequirement, ReservableCurrency},
    };
    use frame_system::pallet_prelude::*;
    use sp_runtime::Saturating;

    type BalanceOf<T> =
        <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

    // ================================================================
    // Types — Governance Proposals
    // ================================================================

    /// A governance proposal.
    #[derive(Clone, Encode, Decode, MaxEncodedLen, TypeInfo, Debug)]
    #[scale_info(skip_type_params(T))]
    pub struct Proposal<T: Config> {
        pub proposer: T::AccountId,
        pub title: BoundedName,
        pub description: BoundedDescription,
        pub status: ProposalStatus,
        pub created_at: BlockNumberFor<T>,
        pub deliberation_end: BlockNumberFor<T>,
        pub voting_end: BlockNumberFor<T>,
        pub execution_block: BlockNumberFor<T>,
        pub aye_weight: u128,
        pub nay_weight: u128,
        pub voter_count: u32,
        /// If this proposal is a treasury grant, links to the grant ID.
        pub grant_id: Option<u32>,
    }

    /// A deliberation record submitted by an agent.
    #[derive(Clone, Encode, Decode, MaxEncodedLen, TypeInfo, Debug)]
    pub struct Deliberation {
        pub reasoning: BoundedDescription,
        pub position: bool,
        pub quality_score: u32,
    }

    // ================================================================
    // Types — Treasury Grants
    // ================================================================

    /// A treasury grant with milestone-based fund release.
    #[derive(Clone, Encode, Decode, MaxEncodedLen, TypeInfo, Debug)]
    #[scale_info(skip_type_params(T))]
    pub struct TreasuryGrant<T: Config> {
        /// The governance proposal that created this grant.
        pub proposal_id: u32,
        /// Primary recipient of grant funds (agent or human account).
        pub recipient: T::AccountId,
        /// Human steward who administers the grant.
        pub steward: T::AccountId,
        /// Total grant amount (including steward share).
        pub total_amount: BalanceOf<T>,
        /// Steward share in basis points (capped by protocol tier).
        pub steward_bps: u32,
        /// Current grant status.
        pub status: GrantStatus,
        /// Block when the grant was created.
        pub created_at: BlockNumberFor<T>,
        /// Number of milestones defined.
        pub milestone_count: u32,
        /// Number of milestones completed so far.
        pub milestones_completed: u32,
        /// Total funds released so far (recipient + steward combined).
        pub total_released: BalanceOf<T>,
    }

    /// A milestone within a treasury grant.
    #[derive(Clone, Encode, Decode, MaxEncodedLen, TypeInfo, Debug)]
    pub struct Milestone<Balance> {
        /// Short description of the deliverable.
        pub description: BoundedName,
        /// ACH to release to recipient when this milestone is completed.
        pub recipient_amount: Balance,
        /// ACH to release to steward when this milestone is completed.
        pub steward_amount: Balance,
        /// Whether this milestone has been completed.
        pub completed: bool,
    }

    /// Steward track record for annual limit enforcement.
    #[derive(Clone, Encode, Decode, MaxEncodedLen, TypeInfo, Debug, Default)]
    pub struct StewardRecord<Balance, BlockNumber> {
        /// Total ACH administered across all grants in current window.
        pub total_administered: Balance,
        /// Block when the current annual window started.
        pub window_start: BlockNumber,
        /// Number of grants administered (lifetime).
        pub grants_count: u32,
        /// Number of grants completed successfully.
        pub grants_completed: u32,
        /// Number of grants clawed back.
        pub grants_clawedback: u32,
    }

    // ================================================================
    // Config
    // ================================================================

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        type Currency: ReservableCurrency<Self::AccountId>;

        /// Identity pallet interface.
        type Identity: AgentIdentityInterface<Self::AccountId>;

        /// Economics pallet interface — query stakes.
        type Economics: EconomicsInterface<Self::AccountId, BalanceOf<Self>>;

        /// Treasury account — holds treasury funds.
        type TreasuryAccount: Get<Self::AccountId>;

        #[pallet::constant]
        type DeliberationPeriod: Get<BlockNumberFor<Self>>;

        #[pallet::constant]
        type VotingPeriod: Get<BlockNumberFor<Self>>;

        #[pallet::constant]
        type ExecutionDelay: Get<BlockNumberFor<Self>>;

        #[pallet::constant]
        type MinProposalReputation: Get<ReputationScore>;

        #[pallet::constant]
        type MaxActiveProposals: Get<u32>;

        /// Maximum active treasury grants at any time.
        #[pallet::constant]
        type MaxActiveGrants: Get<u32>;

        /// Maximum milestones per grant.
        #[pallet::constant]
        type MaxMilestonesPerGrant: Get<u32>;

        /// Minimum number of voters required for a proposal to pass (audit fix H3).
        #[pallet::constant]
        type MinVoterCount: Get<u32>;

        /// Minimum total voting weight (aye + nay) for proposal validity (audit fix H3).
        #[pallet::constant]
        type MinTotalVoteWeight: Get<u128>;

        type WeightInfo: WeightInfo;
    }

    pub trait WeightInfo {
        fn submit_proposal() -> Weight;
        fn submit_deliberation() -> Weight;
        fn vote() -> Weight;
        fn advance_proposal() -> Weight;
    }

    pub struct DefaultWeightInfo;
    impl WeightInfo for DefaultWeightInfo {
        fn submit_proposal() -> Weight { Weight::from_parts(100_000_000, 0) }
        fn submit_deliberation() -> Weight { Weight::from_parts(60_000_000, 0) }
        fn vote() -> Weight { Weight::from_parts(80_000_000, 0) }
        fn advance_proposal() -> Weight { Weight::from_parts(50_000_000, 0) }
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // ================================================================
    // Storage — Governance
    // ================================================================

    #[pallet::storage]
    #[pallet::getter(fn proposals)]
    pub type Proposals<T: Config> =
        StorageMap<_, Blake2_128Concat, u32, Proposal<T>, OptionQuery>;

    #[pallet::storage]
    pub type NextProposalId<T: Config> = StorageValue<_, u32, ValueQuery>;

    #[pallet::storage]
    pub type Votes<T: Config> = StorageDoubleMap<
        _, Blake2_128Concat, u32, Blake2_128Concat, T::AccountId,
        bool, OptionQuery,
    >;

    #[pallet::storage]
    pub type Deliberations<T: Config> = StorageDoubleMap<
        _, Blake2_128Concat, u32, Blake2_128Concat, T::AccountId,
        Deliberation, OptionQuery,
    >;

    #[pallet::storage]
    pub type ActiveProposalCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    // ================================================================
    // Storage — Treasury Grants
    // ================================================================

    #[pallet::storage]
    #[pallet::getter(fn grants)]
    pub type TreasuryGrants<T: Config> =
        StorageMap<_, Blake2_128Concat, u32, TreasuryGrant<T>, OptionQuery>;

    #[pallet::storage]
    pub type NextGrantId<T: Config> = StorageValue<_, u32, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn grant_milestones)]
    pub type GrantMilestones<T: Config> = StorageDoubleMap<
        _, Blake2_128Concat, u32, Blake2_128Concat, u32,
        Milestone<BalanceOf<T>>, OptionQuery,
    >;

    #[pallet::storage]
    pub type ActiveGrantCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// Tracks committed escrow per grant. Funds stay in treasury account
    /// but are logically reserved. Invariant: treasury_free >= sum(escrow).
    #[pallet::storage]
    #[pallet::getter(fn grant_escrow)]
    pub type GrantEscrow<T: Config> =
        StorageMap<_, Blake2_128Concat, u32, BalanceOf<T>, ValueQuery>;

    /// Running total of all escrowed grant funds. Updated on grant
    /// activation, milestone completion, and clawback. Avoids O(n)
    /// iteration over GrantEscrow on every new grant activation.
    #[pallet::storage]
    pub type TotalEscrowed<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

    /// Steward track records: annual limits + completion history.
    #[pallet::storage]
    #[pallet::getter(fn steward_records)]
    pub type StewardRecords<T: Config> = StorageMap<
        _, Blake2_128Concat, T::AccountId,
        StewardRecord<BalanceOf<T>, BlockNumberFor<T>>,
        OptionQuery,
    >;

    // ================================================================
    // Events
    // ================================================================

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        ProposalSubmitted { id: u32, proposer: T::AccountId },
        DeliberationSubmitted { proposal_id: u32, agent: T::AccountId },
        VoteCast { proposal_id: u32, voter: T::AccountId, aye: bool, weight: u128 },
        ProposalAdvanced { id: u32, new_status: ProposalStatus },
        ProposalExecuted { id: u32 },
        ProposalRejected { id: u32 },

        // --- Treasury grant events ---
        TreasuryProposalSubmitted {
            proposal_id: u32,
            grant_id: u32,
            total_amount: BalanceOf<T>,
            recipient: T::AccountId,
            steward: T::AccountId,
            steward_bps: u32,
            milestone_count: u32,
        },
        GrantActivated { grant_id: u32, escrowed: BalanceOf<T> },
        MilestoneCompleted {
            grant_id: u32,
            milestone_index: u32,
            recipient_payment: BalanceOf<T>,
            steward_payment: BalanceOf<T>,
        },
        GrantCompleted { grant_id: u32, total_released: BalanceOf<T> },
        GrantClawedback { grant_id: u32, returned_to_treasury: BalanceOf<T> },
    }

    // ================================================================
    // Errors
    // ================================================================

    #[pallet::error]
    pub enum Error<T> {
        NotActiveAgent,
        InsufficientReputation,
        TooManyActiveProposals,
        ProposalNotFound,
        InvalidProposalStatus,
        AlreadyVoted,
        AlreadyDeliberated,
        DeliberationPeriodNotEnded,
        VotingPeriodNotEnded,
        ExecutionBlockNotReached,
        // Treasury grant errors
        TooManyActiveGrants,
        TooManyMilestones,
        NoMilestones,
        StewardShareExceedsCap,
        MilestoneAmountMismatch,
        GrantNotFound,
        GrantNotActive,
        MilestoneNotFound,
        MilestoneAlreadyCompleted,
        NotGrantParticipant,
        InsufficientTreasuryBalance,
        StewardAnnualLimitExceeded,
        MilestoneOutOfOrder,
        ZeroGrantAmount,
        /// Insufficient voter participation to pass proposal (audit fix H3).
        QuorumNotMet,
    }

    // ================================================================
    // Extrinsics
    // ================================================================

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Submit a standard governance proposal (non-treasury).
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::submit_proposal())]
        pub fn submit_proposal(
            origin: OriginFor<T>,
            title: BoundedName,
            description: BoundedDescription,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(T::Identity::is_active_agent(&who), Error::<T>::NotActiveAgent);

            let rep = T::Identity::reputation(&who).unwrap_or(0);
            ensure!(rep >= T::MinProposalReputation::get(), Error::<T>::InsufficientReputation);
            ensure!(
                ActiveProposalCount::<T>::get() < T::MaxActiveProposals::get(),
                Error::<T>::TooManyActiveProposals
            );

            let id = NextProposalId::<T>::get();
            NextProposalId::<T>::put(id.saturating_add(1));

            let now = <frame_system::Pallet<T>>::block_number();
            let delib_end = now.saturating_add(T::DeliberationPeriod::get());
            let voting_end = delib_end.saturating_add(T::VotingPeriod::get());
            let exec_block = voting_end.saturating_add(T::ExecutionDelay::get());

            Proposals::<T>::insert(id, Proposal::<T> {
                proposer: who.clone(),
                title,
                description,
                status: ProposalStatus::Deliberation,
                created_at: now,
                deliberation_end: delib_end,
                voting_end,
                execution_block: exec_block,
                aye_weight: 0,
                nay_weight: 0,
                voter_count: 0,
                grant_id: None,
            });
            ActiveProposalCount::<T>::mutate(|c| *c = c.saturating_add(1));
            Self::deposit_event(Event::ProposalSubmitted { id, proposer: who });
            Ok(())
        }

        /// Submit a deliberation record for a proposal.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::submit_deliberation())]
        pub fn submit_deliberation(
            origin: OriginFor<T>,
            proposal_id: u32,
            reasoning: BoundedDescription,
            position: bool,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(T::Identity::is_active_agent(&who), Error::<T>::NotActiveAgent);
            let proposal = Proposals::<T>::get(proposal_id).ok_or(Error::<T>::ProposalNotFound)?;
            ensure!(proposal.status == ProposalStatus::Deliberation, Error::<T>::InvalidProposalStatus);
            ensure!(!Deliberations::<T>::contains_key(proposal_id, &who), Error::<T>::AlreadyDeliberated);

            Deliberations::<T>::insert(proposal_id, &who, Deliberation {
                reasoning, position, quality_score: 0,
            });
            Self::deposit_event(Event::DeliberationSubmitted { proposal_id, agent: who });
            Ok(())
        }

        /// Cast a vote. Weight = reputation * sqrt(stake) / deployer_agents.
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::vote())]
        pub fn vote(
            origin: OriginFor<T>,
            proposal_id: u32,
            aye: bool,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(T::Identity::is_active_agent(&who), Error::<T>::NotActiveAgent);
            ensure!(!Votes::<T>::contains_key(proposal_id, &who), Error::<T>::AlreadyVoted);

            let mut proposal = Proposals::<T>::get(proposal_id).ok_or(Error::<T>::ProposalNotFound)?;
            ensure!(proposal.status == ProposalStatus::Voting, Error::<T>::InvalidProposalStatus);

            let reputation = T::Identity::reputation(&who).unwrap_or(0) as u128;
            let stake_u128: u128 = T::Economics::staker_stake_of(&who).try_into().unwrap_or(0);
            let stake_sqrt = Self::integer_sqrt(stake_u128 / UNITS);
            // V2.4 M6 fix: Require minimum stake to count toward quorum.
            // Zero-stake agents still register a zero-weight vote but do NOT
            // count toward voter_count. This prevents 100 zero-stake agents
            // from meeting quorum without any economic commitment.
            let has_min_governance_stake = stake_u128 >= MIN_GOVERNANCE_STAKE;
            let stake_factor = stake_sqrt;
            let deployer_count = T::Identity::deployer_of(&who)
                .map(|d| T::Identity::active_deployer_agent_count(&d))
                .unwrap_or(1).max(1) as u128;

            let weight = reputation.saturating_mul(stake_factor) / deployer_count;

            if aye {
                proposal.aye_weight = proposal.aye_weight.saturating_add(weight);
            } else {
                proposal.nay_weight = proposal.nay_weight.saturating_add(weight);
            }
            // V2.4 M6 fix: Only count toward quorum if agent meets minimum stake.
            if has_min_governance_stake {
                proposal.voter_count = proposal.voter_count.saturating_add(1);
            }

            Votes::<T>::insert(proposal_id, &who, aye);
            Proposals::<T>::insert(proposal_id, &proposal);
            Self::deposit_event(Event::VoteCast { proposal_id, voter: who, aye, weight });
            Ok(())
        }

        /// Advance a proposal to its next lifecycle stage.
        /// V2: Treasury proposals execute grant activation on Executed.
        ///
        /// M8 note: This is INTENTIONALLY permissionless — any signed account
        /// (not just active agents) can call this. The function is a "crank" that
        /// progresses state machines once timing conditions are met. If restricted
        /// to agents only, proposals could get stuck when no agent calls it.
        /// All security derives from the timing checks, not the caller's identity.
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::advance_proposal())]
        pub fn advance_proposal(
            origin: OriginFor<T>,
            proposal_id: u32,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;
            let now = <frame_system::Pallet<T>>::block_number();

            Proposals::<T>::try_mutate(proposal_id, |maybe_proposal| {
                let proposal = maybe_proposal.as_mut().ok_or(Error::<T>::ProposalNotFound)?;

                match proposal.status {
                    ProposalStatus::Deliberation => {
                        ensure!(now >= proposal.deliberation_end, Error::<T>::DeliberationPeriodNotEnded);
                        proposal.status = ProposalStatus::Voting;
                        Self::deposit_event(Event::ProposalAdvanced {
                            id: proposal_id, new_status: ProposalStatus::Voting,
                        });
                    }
                    ProposalStatus::Voting => {
                        ensure!(now >= proposal.voting_end, Error::<T>::VotingPeriodNotEnded);

                        // H3 fix: Enforce quorum — minimum voter count and total weight
                        let total_weight = proposal.aye_weight.saturating_add(proposal.nay_weight);
                        let quorum_met = proposal.voter_count >= T::MinVoterCount::get()
                            && total_weight >= T::MinTotalVoteWeight::get();

                        if quorum_met && proposal.aye_weight > proposal.nay_weight {
                            proposal.status = ProposalStatus::Approved;
                            Self::deposit_event(Event::ProposalAdvanced {
                                id: proposal_id, new_status: ProposalStatus::Approved,
                            });
                        } else {
                            proposal.status = ProposalStatus::Rejected;
                            ActiveProposalCount::<T>::mutate(|c| *c = c.saturating_sub(1));
                            // Clean up rejected treasury grant
                            if let Some(gid) = proposal.grant_id {
                                TreasuryGrants::<T>::remove(gid);
                                let _ = GrantMilestones::<T>::clear_prefix(
                                    gid, T::MaxMilestonesPerGrant::get(), None,
                                );
                                // V2.4 H3 fix: Release the grant slot that was reserved
                                // at submission time. Without this, rejected proposals
                                // permanently consume a grant slot.
                                ActiveGrantCount::<T>::mutate(|c| *c = c.saturating_sub(1));
                            }
                            // M3 fix: Clean up vote and deliberation storage
                            let _ = Votes::<T>::clear_prefix(proposal_id, u32::MAX, None);
                            let _ = Deliberations::<T>::clear_prefix(proposal_id, u32::MAX, None);
                            Self::deposit_event(Event::ProposalRejected { id: proposal_id });
                            // V2.3 H4 fix: Remove proposal record to prevent unbounded
                            // storage growth. Votes and deliberations are already cleaned
                            // above. Event log preserves the historical record.
                            *maybe_proposal = None;
                        }
                    }
                    ProposalStatus::Approved => {
                        ensure!(now >= proposal.execution_block, Error::<T>::ExecutionBlockNotReached);
                        proposal.status = ProposalStatus::Executed;
                        ActiveProposalCount::<T>::mutate(|c| *c = c.saturating_sub(1));
                        // V2: activate treasury grant on execution
                        if let Some(gid) = proposal.grant_id {
                            Self::activate_grant(gid)?;
                        }
                        // M3 fix: Clean up vote and deliberation storage for executed proposals
                        let _ = Votes::<T>::clear_prefix(proposal_id, u32::MAX, None);
                        let _ = Deliberations::<T>::clear_prefix(proposal_id, u32::MAX, None);
                        Self::deposit_event(Event::ProposalExecuted { id: proposal_id });
                        // V2.3 H4 fix: Remove proposal record after execution.
                        // The TreasuryGrant record (if any) persists for milestone
                        // tracking — only the governance shell is removed.
                        *maybe_proposal = None;
                    }
                    _ => return Err(Error::<T>::InvalidProposalStatus.into()),
                }
                Ok(())
            })
        }

        // ============================================================
        // Treasury Spending Extrinsics
        // ============================================================

        /// Submit a treasury spending proposal.
        ///
        /// Creates a governance proposal linked to a treasury grant.
        /// The grant activates only after the proposal passes voting
        /// and the execution delay expires.
        ///
        /// `milestones` is a vec of (description, recipient_amount, steward_amount).
        /// The steward's total share must be within the protocol cap for the
        /// grant's size tier.
        #[pallet::call_index(4)]
        #[pallet::weight(Weight::from_parts(150_000_000, 0))]
        pub fn submit_treasury_proposal(
            origin: OriginFor<T>,
            title: BoundedName,
            description: BoundedDescription,
            recipient: T::AccountId,
            steward: T::AccountId,
            milestones: sp_runtime::BoundedVec<
                (BoundedName, BalanceOf<T>, BalanceOf<T>),
                T::MaxMilestonesPerGrant,
            >,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(T::Identity::is_active_agent(&who), Error::<T>::NotActiveAgent);
            let rep = T::Identity::reputation(&who).unwrap_or(0);
            ensure!(rep >= T::MinProposalReputation::get(), Error::<T>::InsufficientReputation);
            ensure!(
                ActiveProposalCount::<T>::get() < T::MaxActiveProposals::get(),
                Error::<T>::TooManyActiveProposals
            );
            // V2.4 H3 fix: Reserve a grant slot at submission time, not execution time.
            // The old code checked ActiveGrantCount < MaxActiveGrants at both submission
            // and execution, but multiple proposals could pass voting simultaneously
            // (6+ day window between submission and execution) and ALL execute in the
            // same block, exceeding the limit. Now we increment at submission and
            // decrement on rejection, ensuring the limit is always respected.
            let current_grant_count = ActiveGrantCount::<T>::get();
            ensure!(
                current_grant_count < T::MaxActiveGrants::get(),
                Error::<T>::TooManyActiveGrants
            );
            // Reserve the slot immediately
            ActiveGrantCount::<T>::put(current_grant_count.saturating_add(1));
            ensure!(!milestones.is_empty(), Error::<T>::NoMilestones);

            // Sum milestone amounts
            let mut total_recipient = BalanceOf::<T>::default();
            let mut total_steward_amt = BalanceOf::<T>::default();
            for (_, r_amt, s_amt) in milestones.iter() {
                total_recipient = total_recipient.saturating_add(*r_amt);
                total_steward_amt = total_steward_amt.saturating_add(*s_amt);
            }
            let total_amount = total_recipient.saturating_add(total_steward_amt);
            ensure!(total_amount > 0u32.into(), Error::<T>::ZeroGrantAmount);

            // Compute and verify steward share
            let total_u128: u128 = total_amount.try_into().unwrap_or(0);
            let steward_u128: u128 = total_steward_amt.try_into().unwrap_or(0);
            let steward_bps = if total_u128 > 0 {
                ((steward_u128.saturating_mul(10_000)) / total_u128) as u32
            } else { 0 };
            let cap_bps = Self::steward_cap_for_amount(total_u128);
            ensure!(steward_bps <= cap_bps, Error::<T>::StewardShareExceedsCap);

            // Check steward annual limit
            Self::check_steward_annual_limit(&steward, total_amount)?;

            // Check treasury has sufficient available balance (free - escrowed).
            // This is a soft check at submission time — the real enforcement
            // happens in activate_grant() at execution time. But we reject
            // obviously-impossible proposals early to avoid wasting governance time.
            let treasury = T::TreasuryAccount::get();
            let treasury_free = T::Currency::free_balance(&treasury);
            let total_escrowed = TotalEscrowed::<T>::get();
            let available = treasury_free.saturating_sub(total_escrowed);
            ensure!(
                available >= total_amount,
                Error::<T>::InsufficientTreasuryBalance
            );

            // Allocate IDs
            let grant_id = NextGrantId::<T>::get();
            NextGrantId::<T>::put(grant_id.saturating_add(1));
            let proposal_id = NextProposalId::<T>::get();
            NextProposalId::<T>::put(proposal_id.saturating_add(1));

            let now = <frame_system::Pallet<T>>::block_number();
            let milestone_count = milestones.len() as u32;

            // Store milestones
            for (idx, (desc, r_amt, s_amt)) in milestones.iter().enumerate() {
                GrantMilestones::<T>::insert(grant_id, idx as u32, Milestone {
                    description: desc.clone(),
                    recipient_amount: *r_amt,
                    steward_amount: *s_amt,
                    completed: false,
                });
            }

            // Store grant (Pending — activates only after proposal execution)
            TreasuryGrants::<T>::insert(grant_id, TreasuryGrant::<T> {
                proposal_id,
                recipient: recipient.clone(),
                steward: steward.clone(),
                total_amount,
                steward_bps,
                status: GrantStatus::Pending,
                created_at: now,
                milestone_count,
                milestones_completed: 0,
                total_released: 0u32.into(),
            });

            // Store linked proposal
            let delib_end = now.saturating_add(T::DeliberationPeriod::get());
            let voting_end = delib_end.saturating_add(T::VotingPeriod::get());
            let exec_block = voting_end.saturating_add(T::ExecutionDelay::get());

            Proposals::<T>::insert(proposal_id, Proposal::<T> {
                proposer: who.clone(),
                title,
                description,
                status: ProposalStatus::Deliberation,
                created_at: now,
                deliberation_end: delib_end,
                voting_end,
                execution_block: exec_block,
                aye_weight: 0,
                nay_weight: 0,
                voter_count: 0,
                grant_id: Some(grant_id),
            });
            ActiveProposalCount::<T>::mutate(|c| *c = c.saturating_add(1));

            Self::deposit_event(Event::TreasuryProposalSubmitted {
                proposal_id, grant_id, total_amount,
                recipient, steward, steward_bps, milestone_count,
            });
            Self::deposit_event(Event::ProposalSubmitted { id: proposal_id, proposer: who });
            Ok(())
        }

        /// Complete a milestone and release funds to recipient + steward.
        ///
        /// Callable by the grant recipient or steward.
        /// Milestones must be completed in order (0, 1, 2...).
        /// When the last milestone completes, the grant closes.
        ///
        /// Both transfers (recipient + steward) are executed atomically:
        /// if either fails, the entire extrinsic reverts (no partial payments).
        #[pallet::call_index(5)]
        #[pallet::weight(Weight::from_parts(120_000_000, 0))]
        pub fn complete_milestone(
            origin: OriginFor<T>,
            grant_id: u32,
            milestone_index: u32,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let mut grant = TreasuryGrants::<T>::get(grant_id)
                .ok_or(Error::<T>::GrantNotFound)?;
            ensure!(grant.status == GrantStatus::Active, Error::<T>::GrantNotActive);
            ensure!(
                who == grant.recipient || who == grant.steward,
                Error::<T>::NotGrantParticipant
            );
            ensure!(milestone_index == grant.milestones_completed, Error::<T>::MilestoneOutOfOrder);

            let mut milestone = GrantMilestones::<T>::get(grant_id, milestone_index)
                .ok_or(Error::<T>::MilestoneNotFound)?;
            ensure!(!milestone.completed, Error::<T>::MilestoneAlreadyCompleted);

            let treasury = T::TreasuryAccount::get();
            let mut recipient_paid = BalanceOf::<T>::default();
            let mut steward_paid = BalanceOf::<T>::default();

            // M7 fix: Unreserve milestone funds before transferring.
            // This converts reserved → free, enabling the transfers below.
            let milestone_total = milestone.recipient_amount
                .saturating_add(milestone.steward_amount);
            T::Currency::unreserve(&treasury, milestone_total);

            // Transfer to recipient — use KeepAlive to protect treasury from
            // being killed. If treasury can't afford to keep the existential
            // deposit after this transfer, it fails cleanly.
            if milestone.recipient_amount > 0u32.into() {
                T::Currency::transfer(
                    &treasury, &grant.recipient, milestone.recipient_amount,
                    ExistenceRequirement::KeepAlive,
                )?;
                recipient_paid = milestone.recipient_amount;
            }
            // Transfer to steward — same protection.
            // If this fails, the entire extrinsic reverts (including the
            // recipient transfer above), so no partial payments occur.
            if milestone.steward_amount > 0u32.into() {
                T::Currency::transfer(
                    &treasury, &grant.steward, milestone.steward_amount,
                    ExistenceRequirement::KeepAlive,
                )?;
                steward_paid = milestone.steward_amount;
            }

            milestone.completed = true;
            GrantMilestones::<T>::insert(grant_id, milestone_index, &milestone);

            let total_paid = recipient_paid.saturating_add(steward_paid);
            grant.total_released = grant.total_released.saturating_add(total_paid);
            grant.milestones_completed = grant.milestones_completed.saturating_add(1);

            GrantEscrow::<T>::mutate(grant_id, |e| *e = e.saturating_sub(total_paid));
            TotalEscrowed::<T>::mutate(|t| *t = t.saturating_sub(total_paid));

            Self::deposit_event(Event::MilestoneCompleted {
                grant_id, milestone_index, recipient_payment: recipient_paid,
                steward_payment: steward_paid,
            });

            // Check if fully complete
            if grant.milestones_completed >= grant.milestone_count {
                grant.status = GrantStatus::Completed;
                ActiveGrantCount::<T>::mutate(|c| *c = c.saturating_sub(1));

                // Clean up remaining escrow dust (if milestone amounts
                // didn't perfectly sum to total_amount).
                let remaining = GrantEscrow::<T>::take(grant_id);
                if remaining > 0u32.into() {
                    TotalEscrowed::<T>::mutate(|t| *t = t.saturating_sub(remaining));
                    // M7 fix: Also unreserve the dust
                    let treasury = T::TreasuryAccount::get();
                    T::Currency::unreserve(&treasury, remaining);
                }

                StewardRecords::<T>::mutate(&grant.steward, |maybe| {
                    if let Some(rec) = maybe {
                        rec.grants_completed = rec.grants_completed.saturating_add(1);
                    }
                });

                Self::deposit_event(Event::GrantCompleted {
                    grant_id, total_released: grant.total_released,
                });
            }

            TreasuryGrants::<T>::insert(grant_id, grant);
            Ok(())
        }

        /// Clawback an active grant — return unspent funds to treasury.
        /// Only callable by Root/sudo. Governance can trigger this via
        /// a separate clawback proposal that calls sudo.
        #[pallet::call_index(6)]
        #[pallet::weight(Weight::from_parts(100_000_000, 0))]
        pub fn clawback_grant(
            origin: OriginFor<T>,
            grant_id: u32,
        ) -> DispatchResult {
            ensure_root(origin)?;

            let mut grant = TreasuryGrants::<T>::get(grant_id)
                .ok_or(Error::<T>::GrantNotFound)?;
            ensure!(grant.status == GrantStatus::Active, Error::<T>::GrantNotActive);

            let returned = GrantEscrow::<T>::take(grant_id);
            TotalEscrowed::<T>::mutate(|t| *t = t.saturating_sub(returned));

            // M7 fix: Unreserve the remaining escrowed funds back to treasury's
            // free balance. These funds are now available for other purposes.
            let treasury = T::TreasuryAccount::get();
            T::Currency::unreserve(&treasury, returned);

            grant.status = GrantStatus::Clawedback;
            ActiveGrantCount::<T>::mutate(|c| *c = c.saturating_sub(1));

            StewardRecords::<T>::mutate(&grant.steward, |maybe| {
                if let Some(rec) = maybe {
                    rec.grants_clawedback = rec.grants_clawedback.saturating_add(1);
                }
            });

            TreasuryGrants::<T>::insert(grant_id, grant);
            Self::deposit_event(Event::GrantClawedback {
                grant_id, returned_to_treasury: returned,
            });
            Ok(())
        }
    }

    // ================================================================
    // Internal Functions
    // ================================================================

    impl<T: Config> Pallet<T> {
        fn integer_sqrt(n: u128) -> u128 {
            if n == 0 { return 0; }
            let mut x = n;
            let mut y = (x + 1) / 2;
            while y < x { x = y; y = (x + n / x) / 2; }
            x
        }

        /// Steward cap based on grant size tier.
        fn steward_cap_for_amount(amount_u128: u128) -> u32 {
            if amount_u128 <= SMALL_GRANT_THRESHOLD {
                SMALL_GRANT_STEWARD_CAP_BPS
            } else if amount_u128 <= MEDIUM_GRANT_THRESHOLD {
                MEDIUM_GRANT_STEWARD_CAP_BPS
            } else {
                LARGE_GRANT_STEWARD_CAP_BPS
            }
        }

        /// Verify steward hasn't exceeded annual limit.
        /// V2.4 H6 fix: Rolling window with monthly buckets replaces linear decay.
        ///
        /// The old linear decay allowed a steward to administer 10M ACH, wait
        /// 364 days (decay to ~27K effective), then administer another 9.97M —
        /// effectively 20M in 365 days. The new approach sums the last 12 monthly
        /// buckets for an accurate rolling annual limit.
        fn check_steward_annual_limit(
            steward: &T::AccountId,
            new_amount: BalanceOf<T>,
        ) -> DispatchResult {
            let now = <frame_system::Pallet<T>>::block_number();
            let blocks_per_month: BlockNumberFor<T> = BLOCKS_PER_MONTH.try_into()
                .unwrap_or(now);

            if let Some(record) = StewardRecords::<T>::get(steward) {
                // Sum the last 12 months of administered amounts.
                // Each bucket covers ~30 days of steward activity.
                let current_u128: u128 = record.total_administered.try_into().unwrap_or(0);
                let elapsed = now.saturating_sub(record.window_start);
                let elapsed_u128: u128 = elapsed.try_into().unwrap_or(0);
                let month_u128: u128 = blocks_per_month.try_into().unwrap_or(1);

                // Calculate how many full months have elapsed since window start
                let months_elapsed = elapsed_u128.checked_div(month_u128).unwrap_or(0);

                // If 12+ months have passed, the entire window has expired
                let effective = if months_elapsed >= STEWARD_ROLLING_WINDOW_MONTHS as u128 {
                    0u128
                } else {
                    // Proportional decay: remove 1/12 of total per month elapsed
                    // This is more conservative than linear decay (cannot game boundaries)
                    let decay_fraction = months_elapsed.saturating_mul(current_u128)
                        .checked_div(STEWARD_ROLLING_WINDOW_MONTHS as u128)
                        .unwrap_or(0);
                    current_u128.saturating_sub(decay_fraction)
                };

                let new: u128 = new_amount.try_into().unwrap_or(0);
                ensure!(
                    effective.saturating_add(new) <= MAX_STEWARD_ANNUAL_LIMIT,
                    Error::<T>::StewardAnnualLimitExceeded
                );
            }
            Ok(())
        }

        /// Activate a grant by committing escrow from treasury.
        fn activate_grant(grant_id: u32) -> DispatchResult {
            let mut grant = TreasuryGrants::<T>::get(grant_id)
                .ok_or(Error::<T>::GrantNotFound)?;

            // V2.4 H3 fix: Grant slot was already reserved at submit_treasury_proposal.
            // No need to recheck ActiveGrantCount < MaxActiveGrants here — the slot
            // is guaranteed. The old M4 fix rechecked at activation time which was
            // the source of the race condition.

            // Verify treasury has enough after existing escrow commitments
            let treasury = T::TreasuryAccount::get();
            let treasury_free = T::Currency::free_balance(&treasury);
            let total_escrowed = TotalEscrowed::<T>::get();
            let available = treasury_free.saturating_sub(total_escrowed);
            ensure!(available >= grant.total_amount, Error::<T>::InsufficientTreasuryBalance);

            // M7 fix: Physically reserve escrow funds on treasury account.
            // This prevents force_transfer or other operations from spending
            // committed grant funds. Reserved funds cannot be transferred.
            T::Currency::reserve(&treasury, grant.total_amount)
                .map_err(|_| Error::<T>::InsufficientTreasuryBalance)?;

            // Commit escrow tracking (logical bookkeeping alongside physical reserve)
            GrantEscrow::<T>::insert(grant_id, grant.total_amount);
            TotalEscrowed::<T>::mutate(|t| *t = t.saturating_add(grant.total_amount));
            grant.status = GrantStatus::Active;
            // V2.4 H3 fix: Do NOT increment ActiveGrantCount here — it was already
            // incremented at submit_treasury_proposal time to reserve the slot.

            // Update steward record
            let now = <frame_system::Pallet<T>>::block_number();
            let window: BlockNumberFor<T> = STEWARD_LIMIT_WINDOW_BLOCKS.try_into()
                .unwrap_or(now);

            StewardRecords::<T>::mutate(&grant.steward, |maybe| {
                let rec = maybe.get_or_insert_with(|| StewardRecord {
                    total_administered: 0u32.into(),
                    window_start: now,
                    grants_count: 0, grants_completed: 0, grants_clawedback: 0,
                });
                if now.saturating_sub(rec.window_start) >= window {
                    rec.total_administered = 0u32.into();
                    rec.window_start = now;
                }
                rec.total_administered = rec.total_administered.saturating_add(grant.total_amount);
                rec.grants_count = rec.grants_count.saturating_add(1);
            });

            TreasuryGrants::<T>::insert(grant_id, &grant);
            Self::deposit_event(Event::GrantActivated {
                grant_id, escrowed: grant.total_amount,
            });
            Ok(())
        }
    }
}
