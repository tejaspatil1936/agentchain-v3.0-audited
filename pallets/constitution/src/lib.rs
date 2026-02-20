//! # Constitution Pallet
//!
//! Stores the Genesis Constitutional Record (GCR) and provides the
//! Constitutional Compliance Checker (CCC) for runtime upgrades.
//!
//! ## Architecture
//! - **GCR**: Immutable Kernel principles stored at genesis. Cannot be
//!   modified by any governance action.
//! - **CCC**: Analyzes proposed Wasm blobs by scanning their export
//!   sections for required function signatures. This is a syntactic
//!   check — it verifies structure, not behavior.
//!
//! ## Honest Limitation
//! The CCC checks function *names*, not function *behavior*. A
//! sophisticated adversarial upgrade could export correctly-named
//! functions that do the wrong thing. The CCC is a tripwire, not a wall.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use agentchain_primitives::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    /// Maximum number of Kernel principles in the GCR.
    const MAX_KERNEL_PRINCIPLES: u32 = 32;

    /// Maximum number of required Wasm exports the CCC checks for.
    const MAX_REQUIRED_EXPORTS: u32 = 64;

    /// A single Kernel principle in the GCR.
    #[derive(Clone, Encode, Decode, MaxEncodedLen, TypeInfo, Debug)]
    pub struct KernelPrinciple {
        /// Short identifier (e.g., "verified_autonomous_execution").
        pub id: BoundedVec<u8, ConstU32<64>>,
        /// Human-readable description.
        pub description: BoundedDescription,
        /// Required Wasm export name that must be present in any
        /// compliant runtime. Empty means this principle has no
        /// syntactic check (governance-only enforcement).
        pub required_export: BoundedVec<u8, ConstU32<128>>,
    }

    /// Result of a CCC compliance check.
    #[derive(Clone, Encode, Decode, TypeInfo, Debug)]
    pub struct ComplianceResult {
        /// Did the proposed Wasm pass all checks?
        pub passed: bool,
        /// Number of principles checked.
        pub total_checks: u32,
        /// Number of checks that passed.
        pub passed_checks: u32,
        /// Names of failed checks (empty if all passed).
        pub failed_names: BoundedVec<BoundedVec<u8, ConstU32<64>>, ConstU32<MAX_KERNEL_PRINCIPLES>>,
    }

    impl ComplianceResult {
        pub fn failed_check_names(&self) -> &[BoundedVec<u8, ConstU32<64>>] {
            &self.failed_names
        }
    }

    // ================================================================
    // Pallet configuration
    // ================================================================

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type WeightInfo: WeightInfo;
    }

    pub trait WeightInfo {
        fn validate_runtime_upgrade() -> Weight;
    }

    pub struct DefaultWeightInfo;
    impl WeightInfo for DefaultWeightInfo {
        fn validate_runtime_upgrade() -> Weight { Weight::from_parts(200_000_000, 0) }
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // ================================================================
    // Storage
    // ================================================================

    /// The Genesis Constitutional Record — immutable Kernel principles.
    /// Set once at genesis, never modified.
    #[pallet::storage]
    #[pallet::getter(fn kernel_principles)]
    pub type KernelPrinciples<T: Config> = StorageValue<
        _,
        BoundedVec<KernelPrinciple, ConstU32<MAX_KERNEL_PRINCIPLES>>,
        ValueQuery,
    >;

    /// Whether the GCR has been initialized. Once true, it can never
    /// be written again.
    #[pallet::storage]
    #[pallet::getter(fn gcr_initialized)]
    pub type GcrInitialized<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// Count of runtime upgrades that have passed CCC validation.
    #[pallet::storage]
    #[pallet::getter(fn upgrade_count)]
    pub type UpgradeCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    // ================================================================
    // Genesis config
    // ================================================================

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        /// Kernel principles to store at genesis.
        pub principles: alloc::vec::Vec<(
            alloc::vec::Vec<u8>,  // id
            alloc::vec::Vec<u8>,  // description
            alloc::vec::Vec<u8>,  // required_export
        )>,
        #[serde(skip)]
        pub _phantom: core::marker::PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            let mut principles = BoundedVec::default();
            for (id, desc, export) in &self.principles {
                let p = KernelPrinciple {
                    id: BoundedVec::try_from(id.clone()).expect("principle id too long"),
                    description: BoundedVec::try_from(desc.clone()).expect("description too long"),
                    required_export: BoundedVec::try_from(export.clone()).expect("export name too long"),
                };
                principles.try_push(p).expect("too many kernel principles");
            }
            KernelPrinciples::<T>::put(principles);
            GcrInitialized::<T>::put(true);
        }
    }

    // ================================================================
    // Events
    // ================================================================

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A runtime upgrade was validated by the CCC.
        UpgradeValidated {
            passed: bool,
            total_checks: u32,
            passed_checks: u32,
        },
    }

    // ================================================================
    // Errors
    // ================================================================

    #[pallet::error]
    pub enum Error<T> {
        /// The GCR has already been initialized and cannot be changed.
        GcrAlreadyInitialized,
        /// The proposed Wasm blob is empty or too small.
        InvalidWasmBlob,
        /// CCC validation failed — the upgrade violates Kernel principles.
        ComplianceCheckFailed,
    }

    // ================================================================
    // Extrinsics
    // ================================================================

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        // No public extrinsics — all interaction is through:
        // 1. Genesis config (for initial GCR)
        // 2. The ConstitutionalCheck SignedExtension (calls validate_runtime_upgrade)
        // 3. The ConstitutionInterface trait (for other pallets)
    }

    // ================================================================
    // CCC validation logic
    // ================================================================

    impl<T: Config> Pallet<T> {
        /// Validate a proposed Wasm runtime blob against the GCR.
        ///
        /// This is called by the ConstitutionalCheck SignedExtension
        /// whenever a `system::set_code` extrinsic is submitted.
        ///
        /// ## How it works
        /// 1. Parse the Wasm blob's export section.
        /// 2. For each Kernel principle that specifies a `required_export`,
        ///    check whether that export name exists in the blob.
        /// 3. If any required export is missing, the check fails.
        ///
        /// ## Limitation
        /// This is syntactic only. It checks that a function with the
        /// right name is exported, not that the function does the right
        /// thing. A malicious upgrade could export a correctly-named
        /// no-op function and pass the CCC.
        pub fn validate_runtime_upgrade(code: &[u8]) -> Result<ComplianceResult, DispatchError> {
            ensure!(code.len() > 8, Error::<T>::InvalidWasmBlob);

            // Check Wasm magic number: \0asm
            ensure!(
                code[0..4] == [0x00, 0x61, 0x73, 0x6D],
                Error::<T>::InvalidWasmBlob
            );

            let principles = KernelPrinciples::<T>::get();
            let mut total_checks: u32 = 0;
            let mut passed_checks: u32 = 0;
            let mut failed_names: BoundedVec<BoundedVec<u8, ConstU32<64>>, ConstU32<MAX_KERNEL_PRINCIPLES>> =
                BoundedVec::default();

            for principle in principles.iter() {
                if principle.required_export.is_empty() {
                    // No syntactic check for this principle — skip
                    continue;
                }

                total_checks += 1;

                // Scan the Wasm blob for the export name.
                // This is a byte-level search, not a full Wasm parser.
                // Sufficient for V1; a proper Wasm parser is a V2 upgrade.
                if Self::wasm_contains_export(code, &principle.required_export) {
                    passed_checks += 1;
                } else {
                    let _ = failed_names.try_push(principle.id.clone());
                }
            }

            let passed = failed_names.is_empty();

            let result = ComplianceResult {
                passed,
                total_checks,
                passed_checks,
                failed_names,
            };

            Self::deposit_event(Event::UpgradeValidated {
                passed,
                total_checks,
                passed_checks,
            });

            if passed {
                UpgradeCount::<T>::mutate(|c| *c += 1);
            }

            Ok(result)
        }

        /// Byte-level scan for an export name in a Wasm blob.
        ///
        /// This searches for the UTF-8 bytes of the export name anywhere
        /// in the binary. It's a heuristic — a proper implementation would
        /// parse the Wasm export section (section ID 7). Good enough for
        /// V1 devnet; false positives are possible but unlikely for
        /// function-name-length strings.
        fn wasm_contains_export(code: &[u8], export_name: &[u8]) -> bool {
            if export_name.is_empty() || code.len() < export_name.len() {
                return false;
            }
            // Simple substring search
            code.windows(export_name.len())
                .any(|window| window == export_name)
        }
    }

    // ================================================================
    // Implement the cross-pallet trait interface
    // ================================================================

    impl<T: Config> ConstitutionInterface for Pallet<T> {
        fn validate_wasm_blob(code: &[u8]) -> bool {
            Self::validate_runtime_upgrade(code)
                .map(|r| r.passed)
                .unwrap_or(false)
        }
    }
}
