//! # Agent Market Pallet
//!
//! Marketplace for agent services. Supports:
//! - Publishing service offers with price, category, and reputation-tier enforcement
//! - Escrow-backed job lifecycle (request → deliver → accept → complete)
//! - Job cancellation after timeout (requester can cancel if provider unresponsive)
//! - Dispute resolution with timeout-based auto-refund
//! - Protocol fee collection with 3-way split: stakers, treasury, burn
//! - Deployer revenue split on job completion
//! - Reputation-adjusted fee rates (veterans pay less)
//! - Epoch-level market metrics (read from economics single source of truth)

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
    use sp_runtime::traits::Hash;
    use sp_runtime::Saturating;
    use sp_runtime::traits::Bounded;

    type BalanceOf<T> =
        <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

    /// A service offer published by an agent.
    #[derive(Clone, Encode, Decode, MaxEncodedLen, TypeInfo, Debug)]
    #[scale_info(skip_type_params(T))]
    pub struct ServiceOffer<T: Config> {
        pub provider: T::AccountId,
        pub category: CategoryId,
        pub description: BoundedDescription,
        pub price: BalanceOf<T>,
        pub is_active: bool,
        pub created_at: BlockNumberFor<T>,
        pub jobs_completed: u32,
    }

    /// A job in the marketplace.
    #[derive(Clone, Encode, Decode, MaxEncodedLen, TypeInfo, Debug)]
    #[scale_info(skip_type_params(T))]
    pub struct Job<T: Config> {
        pub requester: T::AccountId,
        pub provider: T::AccountId,
        pub offer_id: H256,
        pub escrow_amount: BalanceOf<T>,
        pub status: JobStatus,
        pub created_at: BlockNumberFor<T>,
        pub is_external: bool,
    }

    /// Epoch-level market metrics.
    #[derive(Clone, Encode, Decode, MaxEncodedLen, TypeInfo, Debug, Default)]
    pub struct MarketMetrics<Balance: Default> {
        pub total_volume: Balance,
        pub job_count: u32,
        pub external_job_count: u32,
        pub dispute_count: u32,
        pub total_fees_collected: Balance,
        pub total_burned: Balance,
    }

    // ================================================================
    // Config
    // ================================================================

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type Currency: ReservableCurrency<Self::AccountId>;

        /// Interface to the identity pallet (trait, not concrete type).
        type Identity: AgentIdentityInterface<Self::AccountId>;

        /// Callback to economics pallet for fee processing + epoch queries.
        type EconomicsCallback: EconomicsInterface<Self::AccountId, BalanceOf<Self>>;

        #[pallet::constant]
        type MaxOffersPerAgent: Get<u32>;

        #[pallet::constant]
        type MaxOffersPerCategory: Get<u32>;

        /// Protocol fee in basis points (e.g. 200 = 2%).
        #[pallet::constant]
        type ProtocolFeeBps: Get<u32>;

        /// Veteran (high-reputation) protocol fee in basis points.
        #[pallet::constant]
        type VeteranFeeBps: Get<u32>;

        /// Reputation threshold to qualify for veteran fee rate.
        #[pallet::constant]
        type VeteranFeeThreshold: Get<u32>;

        /// Configurable reputation tier thresholds (audit fix M4).
        #[pallet::constant]
        type ReputationTier1Threshold: Get<u32>;
        #[pallet::constant]
        type ReputationTier2Threshold: Get<u32>;
        #[pallet::constant]
        type ReputationTier3Threshold: Get<u32>;

        /// Job timeout in blocks. If provider doesn't deliver, requester can cancel.
        #[pallet::constant]
        type JobTimeoutBlocks: Get<BlockNumberFor<Self>>;

        /// Dispute auto-resolution timeout in blocks.
        #[pallet::constant]
        type DisputeResolutionBlocks: Get<BlockNumberFor<Self>>;

        /// Treasury account that receives fee split.
        type TreasuryAccount: Get<Self::AccountId>;

        type WeightInfo: WeightInfo;
    }

    pub trait WeightInfo {
        fn publish_offer() -> Weight;
        fn request_job() -> Weight;
        fn deliver_job() -> Weight;
        fn accept_delivery() -> Weight;
        fn dispute_job() -> Weight;
        fn cancel_job() -> Weight;
        fn resolve_dispute() -> Weight;
    }

    pub struct DefaultWeightInfo;
    impl WeightInfo for DefaultWeightInfo {
        fn publish_offer() -> Weight { Weight::from_parts(80_000_000, 0) }
        fn request_job() -> Weight { Weight::from_parts(100_000_000, 0) }
        fn deliver_job() -> Weight { Weight::from_parts(50_000_000, 0) }
        fn accept_delivery() -> Weight { Weight::from_parts(150_000_000, 0) }
        fn dispute_job() -> Weight { Weight::from_parts(60_000_000, 0) }
        fn cancel_job() -> Weight { Weight::from_parts(80_000_000, 0) }
        fn resolve_dispute() -> Weight { Weight::from_parts(80_000_000, 0) }
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // ================================================================
    // Storage
    // ================================================================

    /// Service offers: OfferId (H256) → ServiceOffer.
    #[pallet::storage]
    #[pallet::getter(fn offers)]
    pub type Offers<T: Config> =
        StorageMap<_, Blake2_128Concat, H256, ServiceOffer<T>, OptionQuery>;

    /// Category index: CategoryId → Vec<OfferId>.
    #[pallet::storage]
    #[pallet::getter(fn category_offers)]
    pub type CategoryOffers<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        CategoryId,
        BoundedVec<H256, T::MaxOffersPerCategory>,
        ValueQuery,
    >;

    /// Jobs: JobId (H256) → Job.
    #[pallet::storage]
    #[pallet::getter(fn jobs)]
    pub type Jobs<T: Config> =
        StorageMap<_, Blake2_128Concat, H256, Job<T>, OptionQuery>;

    /// Market metrics per epoch.
    #[pallet::storage]
    #[pallet::getter(fn epoch_metrics)]
    pub type EpochMetrics<T: Config> =
        StorageMap<_, Blake2_128Concat, EpochNumber, MarketMetrics<BalanceOf<T>>, OptionQuery>;

    /// Per-agent offer count — enforces MaxOffersPerAgent (audit fix M1).
    #[pallet::storage]
    #[pallet::getter(fn offer_count_per_agent)]
    pub type OfferCountPerAgent<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u32, ValueQuery>;

    // NOTE: CurrentEpoch storage REMOVED (audit fix H1).
    // All epoch reads go through T::EconomicsCallback::current_epoch().

    // ================================================================
    // Events
    // ================================================================

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        OfferPublished { offer_id: H256, provider: T::AccountId, category: CategoryId },
        OfferDeactivated { offer_id: H256 },
        JobRequested { job_id: H256, requester: T::AccountId, provider: T::AccountId, amount: BalanceOf<T> },
        JobDelivered { job_id: H256 },
        DeliveryAccepted { job_id: H256, amount: BalanceOf<T> },
        JobDisputed { job_id: H256, disputer: T::AccountId },
        /// Job cancelled by requester after timeout or dispute auto-resolved.
        JobCancelled { job_id: H256, refunded: BalanceOf<T> },
        /// Dispute auto-resolved (timeout-based refund to requester).
        DisputeResolved { job_id: H256 },
        /// Protocol fee was collected and split.
        ProtocolFeeCollected {
            job_id: H256,
            fee: BalanceOf<T>,
            burned: BalanceOf<T>,
            treasury: BalanceOf<T>,
            stakers: BalanceOf<T>,
        },
        /// Deployer received revenue split.
        DeployerRevenuePaid {
            job_id: H256,
            deployer: DeployerId,
            amount: BalanceOf<T>,
        },
        /// Audit2 M3: Deployer payment was skipped because the deployer account
        /// could not be resolved. The funds remain with the provider.
        DeployerPaymentSkipped {
            job_id: H256,
            deployer_bps: u16,
            amount: BalanceOf<T>,
        },
    }

    // ================================================================
    // Errors
    // ================================================================

    #[pallet::error]
    pub enum Error<T> {
        NotActiveAgent,
        OfferNotFound,
        JobNotFound,
        OfferNotActive,
        CategoryFull,
        NotJobRequester,
        NotJobProvider,
        InvalidJobStatus,
        InsufficientBalance,
        Unauthorized,
        /// Offer price exceeds the agent's reputation-tier limit.
        PriceExceedsReputationTier,
        /// Fee calculation overflow.
        FeeOverflow,
        /// Job timeout has not elapsed yet — cannot cancel.
        JobTimeoutNotElapsed,
        /// Dispute resolution timeout has not elapsed yet.
        DisputeTimeoutNotElapsed,
        /// Agent has reached the maximum number of active offers (audit fix M1).
        TooManyOffersPerAgent,
    }

    // ================================================================
    // Extrinsics
    // ================================================================

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Publish a new service offer.
        /// Price is checked against configurable reputation-based tier limits (audit fix M4).
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::publish_offer())]
        pub fn publish_offer(
            origin: OriginFor<T>,
            category: CategoryId,
            description: BoundedDescription,
            price: BalanceOf<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(T::Identity::is_active_agent(&who), Error::<T>::NotActiveAgent);

            // M1 fix: Enforce per-agent offer limit
            ensure!(
                OfferCountPerAgent::<T>::get(&who) < T::MaxOffersPerAgent::get(),
                Error::<T>::TooManyOffersPerAgent
            );

            // === REPUTATION-TIERED PRICE CAPS (configurable via Config — audit fix M4) ===
            if let Some(rep) = T::Identity::reputation(&who) {
                let max_price: BalanceOf<T> = if rep > T::ReputationTier3Threshold::get() {
                    BalanceOf::<T>::max_value() // Unlimited
                } else if rep > T::ReputationTier2Threshold::get() {
                    REPUTATION_TIER_3_CAP.try_into().unwrap_or(BalanceOf::<T>::max_value())
                } else if rep > T::ReputationTier1Threshold::get() {
                    REPUTATION_TIER_2_CAP.try_into().unwrap_or(BalanceOf::<T>::max_value())
                } else {
                    REPUTATION_TIER_1_CAP.try_into().unwrap_or(BalanceOf::<T>::max_value())
                };
                ensure!(price <= max_price, Error::<T>::PriceExceedsReputationTier);
            }

            let now = <frame_system::Pallet<T>>::block_number();
            let offer_id = T::Hashing::hash_of(&(&who, &category, now));

            let offer = ServiceOffer::<T> {
                provider: who.clone(),
                category,
                description,
                price,
                is_active: true,
                created_at: now,
                jobs_completed: 0,
            };

            Offers::<T>::insert(offer_id, &offer);

            // Add to category index
            CategoryOffers::<T>::try_mutate(&category, |offers| {
                offers.try_push(offer_id).map_err(|_| Error::<T>::CategoryFull)
            })?;

            // M1 fix: Increment per-agent offer count
            OfferCountPerAgent::<T>::mutate(&who, |c| *c = c.saturating_add(1));

            Self::deposit_event(Event::OfferPublished {
                offer_id,
                provider: who,
                category,
            });

            Ok(())
        }

        /// Deactivate an existing service offer (audit fix M2).
        /// Only the offer provider can deactivate their own offers.
        /// Removes the offer from the category index and decrements the per-agent counter.
        #[pallet::call_index(7)]
        #[pallet::weight(Weight::from_parts(60_000_000, 0))]
        pub fn deactivate_offer(
            origin: OriginFor<T>,
            offer_id: H256,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let mut offer = Offers::<T>::get(offer_id).ok_or(Error::<T>::OfferNotFound)?;
            ensure!(offer.provider == who, Error::<T>::Unauthorized);
            ensure!(offer.is_active, Error::<T>::OfferNotActive);

            offer.is_active = false;
            Offers::<T>::insert(offer_id, &offer);

            // Remove from category index
            CategoryOffers::<T>::mutate(&offer.category, |offers| {
                offers.retain(|id| *id != offer_id);
            });

            // Decrement per-agent offer count
            OfferCountPerAgent::<T>::mutate(&who, |c| *c = c.saturating_sub(1));

            Self::deposit_event(Event::OfferDeactivated { offer_id });
            Ok(())
        }

        /// Request a job (creates escrow).
        /// Requester must be an active agent (audit fix H2).
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::request_job())]
        pub fn request_job(
            origin: OriginFor<T>,
            offer_id: H256,
            is_external: bool,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // Audit fix H2: Require requester to be an active agent.
            // This enforces the "AI-agent-exclusive" design principle.
            ensure!(T::Identity::is_active_agent(&who), Error::<T>::NotActiveAgent);

            let offer = Offers::<T>::get(offer_id).ok_or(Error::<T>::OfferNotFound)?;
            ensure!(offer.is_active, Error::<T>::OfferNotActive);

            // Lock escrow from the requester
            T::Currency::reserve(&who, offer.price)
                .map_err(|_| Error::<T>::InsufficientBalance)?;

            let now = <frame_system::Pallet<T>>::block_number();
            let job_id = T::Hashing::hash_of(&(&who, &offer_id, now));

            let job = Job::<T> {
                requester: who.clone(),
                provider: offer.provider.clone(),
                offer_id,
                escrow_amount: offer.price,
                status: JobStatus::InProgress,
                created_at: now,
                is_external,
            };

            Jobs::<T>::insert(job_id, &job);

            Self::deposit_event(Event::JobRequested {
                job_id,
                requester: who,
                provider: offer.provider,
                amount: offer.price,
            });

            Ok(())
        }

        /// Provider marks a job as delivered.
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::deliver_job())]
        pub fn deliver_job(
            origin: OriginFor<T>,
            job_id: H256,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            Jobs::<T>::try_mutate(&job_id, |maybe_job| {
                let job = maybe_job.as_mut().ok_or(Error::<T>::JobNotFound)?;
                ensure!(job.provider == who, Error::<T>::NotJobProvider);
                ensure!(job.status == JobStatus::InProgress, Error::<T>::InvalidJobStatus);
                job.status = JobStatus::Delivered;
                Ok::<(), DispatchError>(())
            })?;

            Self::deposit_event(Event::JobDelivered { job_id });
            Ok(())
        }

        /// Requester accepts delivery — releases escrow with fee deduction,
        /// deployer revenue split, and protocol fee distribution.
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::accept_delivery())]
        pub fn accept_delivery(
            origin: OriginFor<T>,
            job_id: H256,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let job = Jobs::<T>::get(&job_id).ok_or(Error::<T>::JobNotFound)?;
            ensure!(job.requester == who, Error::<T>::NotJobRequester);
            ensure!(job.status == JobStatus::Delivered, Error::<T>::InvalidJobStatus);

            // 1. Unreserve escrowed funds
            T::Currency::unreserve(&job.requester, job.escrow_amount);

            // 2. Calculate protocol fee (reputation-adjusted)
            // V3.0: 3-tier fee structure + governance override.
            // Governance override > veteran (1.0%) > mid-tier (1.75%) > base (2.5%).
            let fee_bps = if let Some(override_bps) = T::EconomicsCallback::tunable_protocol_fee_bps() {
                override_bps
            } else {
                T::Identity::reputation(&job.provider)
                    .map(|rep| {
                        if rep >= T::VeteranFeeThreshold::get() {
                            T::VeteranFeeBps::get()                    // 1.0%
                        } else if rep >= MID_TIER_REP_THRESHOLD {
                            MID_TIER_FEE_BPS                           // 1.75%
                        } else {
                            T::ProtocolFeeBps::get()                   // 2.5%
                        }
                    })
                    .unwrap_or(T::ProtocolFeeBps::get())
            };

            let protocol_fee = job.escrow_amount
                .saturating_mul(fee_bps.into()) / 10_000u32.into();
            let after_fee = job.escrow_amount.saturating_sub(protocol_fee);

            // 3. Calculate deployer revenue split
            let deployer_bps = T::Identity::deployer_revenue_bps_of(&job.provider)
                .unwrap_or(0);
            let deployer_id = T::Identity::deployer_of(&job.provider);

            let deployer_payment = if deployer_bps > 0 {
                after_fee.saturating_mul(deployer_bps.into()) / 10_000u32.into()
            } else {
                0u32.into()
            };
            let provider_payment = after_fee.saturating_sub(deployer_payment);

            // 4. Transfer provider payment
            T::Currency::transfer(
                &job.requester,
                &job.provider,
                provider_payment,
                ExistenceRequirement::AllowDeath,
            )?;

            // 5. Transfer deployer payment (if any)
            // Audit2 M3 fix: If deployer account can't be resolved, redirect their
            // share to the provider and emit a diagnostic event. Previously, the
            // deployer share remained silently with the requester.
            if deployer_payment > 0u32.into() {
                let mut deployer_paid = false;
                if let Some(did) = deployer_id {
                    if let Some(deployer_acct) = T::Identity::deployer_account(&did) {
                        T::Currency::transfer(
                            &job.requester,
                            &deployer_acct,
                            deployer_payment,
                            ExistenceRequirement::AllowDeath,
                        )?;

                        Self::deposit_event(Event::DeployerRevenuePaid {
                            job_id,
                            deployer: did,
                            amount: deployer_payment,
                        });
                        deployer_paid = true;
                    }
                }
                if !deployer_paid {
                    // Deployer account not found — redirect their share to provider
                    T::Currency::transfer(
                        &job.requester,
                        &job.provider,
                        deployer_payment,
                        ExistenceRequirement::AllowDeath,
                    )?;
                    Self::deposit_event(Event::DeployerPaymentSkipped {
                        job_id,
                        deployer_bps: deployer_bps,
                        amount: deployer_payment,
                    });
                }
            }

            // 6. Split protocol fee: V3.0 4-way split
            // 50% stakers, 15% treasury, 15% validator fund (recycled), 20% burn
            // Governance can override burn and recycle splits.
            let burn_bps: u32 = T::EconomicsCallback::tunable_fee_burn_bps()
                .unwrap_or(FEE_SPLIT_BURN_BPS);
            let recycle_bps: u32 = T::EconomicsCallback::tunable_validator_fund_recycle_bps()
                .unwrap_or(FEE_SPLIT_VALIDATOR_FUND_BPS);

            let treasury_share = protocol_fee
                .saturating_mul(FEE_SPLIT_TREASURY_BPS.into()) / 10_000u32.into();
            let burn_share = protocol_fee
                .saturating_mul(burn_bps.into()) / 10_000u32.into();
            let recycle_share = protocol_fee
                .saturating_mul(recycle_bps.into()) / 10_000u32.into();
            let staker_share = protocol_fee
                .saturating_sub(treasury_share)
                .saturating_sub(burn_share)
                .saturating_sub(recycle_share);

            // Transfer treasury share
            if treasury_share > 0u32.into() {
                T::Currency::transfer(
                    &job.requester,
                    &T::TreasuryAccount::get(),
                    treasury_share,
                    ExistenceRequirement::AllowDeath,
                )?;
            }

            // Burn share: slash from requester (removes from total issuance)
            if burn_share > 0u32.into() {
                let (imbalance, _) = T::Currency::slash(&job.requester, burn_share);
                drop(imbalance); // Dropping NegativeImbalance reduces total_issuance
            }

            // V3.0: Recycle share → validator reward fund
            if recycle_share > 0u32.into() {
                let val_fund = T::EconomicsCallback::validator_reward_fund_account();
                T::Currency::transfer(
                    &job.requester,
                    &val_fund,
                    recycle_share,
                    ExistenceRequirement::AllowDeath,
                )?;
            }

            // Staker share: send to dedicated reward pool account.
            // Audit fix C2: AllowDeath to prevent KeepAlive blocking final transfer.
            if staker_share > 0u32.into() {
                let pool_account = T::EconomicsCallback::staker_reward_pool_account();
                T::Currency::transfer(
                    &job.requester,
                    &pool_account,
                    staker_share,
                    ExistenceRequirement::AllowDeath,  // Audit fix C2
                )?;
            }

            // Notify economics pallet of fee processing
            T::EconomicsCallback::on_service_payment(protocol_fee, treasury_share, burn_share);

            // 7. Update job status
            Jobs::<T>::mutate(&job_id, |maybe_job| {
                if let Some(job) = maybe_job {
                    job.status = JobStatus::Completed;
                }
            });

            // 8. Update offer completion count
            Offers::<T>::mutate(&job.offer_id, |maybe_offer| {
                if let Some(offer) = maybe_offer {
                    offer.jobs_completed = offer.jobs_completed.saturating_add(1);
                }
            });

            // V2.4 I4 fix: Increment provider reputation on successful job completion.
            // This integrates marketplace performance with agent reputation, making
            // reputation a meaningful signal of service quality — not just liveness.
            T::Identity::increment_reputation(
                &job.provider,
                JOB_COMPLETION_REPUTATION_BONUS,
            );

            // 9. Update epoch metrics — read epoch from economics (audit fix H1)
            let epoch = T::EconomicsCallback::current_epoch();
            EpochMetrics::<T>::mutate(epoch, |maybe_metrics| {
                let metrics = maybe_metrics.get_or_insert_with(Default::default);
                metrics.total_volume = metrics.total_volume.saturating_add(job.escrow_amount);
                metrics.job_count = metrics.job_count.saturating_add(1);
                metrics.total_fees_collected = metrics.total_fees_collected.saturating_add(protocol_fee);
                metrics.total_burned = metrics.total_burned.saturating_add(burn_share);
                if job.is_external {
                    metrics.external_job_count = metrics.external_job_count.saturating_add(1);
                }
            });

            // V2.3 M6 fix: O(1) pruning — remove metrics from MAX_EPOCH_SNAPSHOT_HISTORY
            // epochs ago. One old entry removed per write, preventing unbounded growth.
            // Uses the same retention window as the economics pallet's EpochSnapshots.
            if epoch > MAX_EPOCH_SNAPSHOT_HISTORY {
                let old_epoch = epoch.saturating_sub(MAX_EPOCH_SNAPSHOT_HISTORY);
                EpochMetrics::<T>::remove(old_epoch);
            }

            Self::deposit_event(Event::DeliveryAccepted {
                job_id,
                amount: job.escrow_amount,
            });
            Self::deposit_event(Event::ProtocolFeeCollected {
                job_id,
                fee: protocol_fee,
                burned: burn_share,
                treasury: treasury_share,
                stakers: staker_share,
            });

            Ok(())
        }

        /// Either party disputes a job.
        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::dispute_job())]
        pub fn dispute_job(
            origin: OriginFor<T>,
            job_id: H256,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            Jobs::<T>::try_mutate(&job_id, |maybe_job| {
                let job = maybe_job.as_mut().ok_or(Error::<T>::JobNotFound)?;
                ensure!(
                    job.requester == who || job.provider == who,
                    Error::<T>::Unauthorized
                );
                ensure!(
                    job.status == JobStatus::InProgress || job.status == JobStatus::Delivered,
                    Error::<T>::InvalidJobStatus
                );
                job.status = JobStatus::Disputed;

                let epoch = T::EconomicsCallback::current_epoch();
                EpochMetrics::<T>::mutate(epoch, |maybe_metrics| {
                    let metrics = maybe_metrics.get_or_insert_with(Default::default);
                    metrics.dispute_count = metrics.dispute_count.saturating_add(1);
                });

                Ok::<(), DispatchError>(())
            })?;

            Self::deposit_event(Event::JobDisputed { job_id, disputer: who });
            Ok(())
        }

        /// Cancel a job after the provider fails to deliver within the timeout.
        /// V2.4 M2 fix: Provider receives 20% partial payment for work attempted.
        /// Requester receives remaining 80% refund.
        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::cancel_job())]
        pub fn cancel_job(
            origin: OriginFor<T>,
            job_id: H256,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let job = Jobs::<T>::get(&job_id).ok_or(Error::<T>::JobNotFound)?;
            ensure!(job.requester == who, Error::<T>::NotJobRequester);
            ensure!(job.status == JobStatus::InProgress, Error::<T>::InvalidJobStatus);

            // Verify timeout has elapsed
            let now = <frame_system::Pallet<T>>::block_number();
            let timeout_block = job.created_at.saturating_add(T::JobTimeoutBlocks::get());
            ensure!(now >= timeout_block, Error::<T>::JobTimeoutNotElapsed);

            // V2.4 M2 fix: Pay provider 20% for work attempted before refunding.
            // This protects providers from requester cancellation griefing where
            // requesters wait for work to be done then cancel for a full refund.
            let provider_share_bps: u128 = CANCELLATION_PROVIDER_SHARE_BPS as u128;
            let escrow_u128: u128 = job.escrow_amount.try_into().unwrap_or(0);
            let provider_amount_u128 = escrow_u128.saturating_mul(provider_share_bps) / 10_000;
            let provider_amount: BalanceOf<T> = provider_amount_u128.try_into().unwrap_or_default();
            let requester_refund = job.escrow_amount.saturating_sub(provider_amount);

            // Unreserve full escrow from requester
            T::Currency::unreserve(&job.requester, job.escrow_amount);

            // Transfer provider's share
            if provider_amount > 0u32.into() {
                let _ = T::Currency::transfer(
                    &job.requester,
                    &job.provider,
                    provider_amount,
                    ExistenceRequirement::AllowDeath,
                );
            }

            // Update job status
            Jobs::<T>::mutate(&job_id, |maybe_job| {
                if let Some(j) = maybe_job {
                    j.status = JobStatus::Cancelled;
                }
            });

            Self::deposit_event(Event::JobCancelled {
                job_id,
                refunded: requester_refund,
            });

            Ok(())
        }

        /// Resolve a disputed job after the dispute timeout elapses.
        /// V2.4 M3 fix: Provider receives 10% baseline compensation instead of 0%.
        /// Both parties receive reputation impact. This reduces the incentive for
        /// requesters to grief providers by disputing completed work.
        /// Anyone can call this once the timeout has passed.
        #[pallet::call_index(6)]
        #[pallet::weight(T::WeightInfo::resolve_dispute())]
        pub fn resolve_dispute(
            origin: OriginFor<T>,
            job_id: H256,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            let job = Jobs::<T>::get(&job_id).ok_or(Error::<T>::JobNotFound)?;
            ensure!(job.status == JobStatus::Disputed, Error::<T>::InvalidJobStatus);

            // Verify dispute resolution timeout has elapsed
            let now = <frame_system::Pallet<T>>::block_number();
            let resolve_block = job.created_at.saturating_add(T::DisputeResolutionBlocks::get());
            ensure!(now >= resolve_block, Error::<T>::DisputeTimeoutNotElapsed);

            // V2.4 M3 fix: Split escrow — 10% to provider, 90% refund to requester.
            // This prevents zero-cost dispute griefing against providers.
            let escrow_u128: u128 = job.escrow_amount.try_into().unwrap_or(0);
            let provider_share_u128 = escrow_u128
                .saturating_mul(DISPUTE_PROVIDER_SHARE_BPS as u128) / 10_000;
            let provider_share: BalanceOf<T> = provider_share_u128.try_into().unwrap_or_default();
            let requester_refund = job.escrow_amount.saturating_sub(provider_share);

            // Unreserve full escrow from requester
            T::Currency::unreserve(&job.requester, job.escrow_amount);

            // Transfer provider's share
            if provider_share > 0u32.into() {
                let _ = T::Currency::transfer(
                    &job.requester,
                    &job.provider,
                    provider_share,
                    ExistenceRequirement::AllowDeath,
                );
            }

            // V2.4 I4 fix: Apply reputation impact for disputes.
            // Both parties lose some reputation — disputes are negative-sum.
            // Provider loses less since the auto-resolution doesn't determine fault.
            T::Identity::decrement_reputation(
                &job.provider,
                DISPUTE_LOSS_REPUTATION_PENALTY / 2, // 50 bps for provider (benefit of doubt)
            );
            T::Identity::decrement_reputation(
                &job.requester,
                DISPUTE_LOSS_REPUTATION_PENALTY / 4, // 25 bps for requester (dispute cost)
            );

            // Update job status
            Jobs::<T>::mutate(&job_id, |maybe_job| {
                if let Some(j) = maybe_job {
                    j.status = JobStatus::Cancelled;
                }
            });

            Self::deposit_event(Event::DisputeResolved { job_id });
            Self::deposit_event(Event::JobCancelled {
                job_id,
                refunded: requester_refund,
            });

            Ok(())
        }
    }

    // ================================================================
    // Public helpers for runtime API
    // ================================================================

    impl<T: Config> Pallet<T> {
        pub fn offers_by_category(category: CategoryId) -> alloc::vec::Vec<H256> {
            CategoryOffers::<T>::get(category).into_inner()
        }

        pub fn get_epoch_metrics(epoch: EpochNumber) -> Option<MarketMetrics<BalanceOf<T>>> {
            EpochMetrics::<T>::get(epoch)
        }
    }
}
