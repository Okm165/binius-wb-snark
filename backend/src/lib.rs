use binius_circuits::builder::ConstraintSystemBuilder;
use binius_core::{constraint_system, fiat_shamir::HasherChallenger, tower::CanonicalTowerFamily};
use binius_field::{arch::OptimalUnderlier, BinaryField128b, BinaryField1b, BinaryField8b};
use binius_hal::make_portable_backend;
use binius_hash::{GroestlDigestCompression, GroestlHasher};
use binius_math::DefaultEvaluationDomainFactory;
use groestl_crypto::Groestl256;
use utils::set_panic_hook;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

pub mod sha2;
pub mod sha3;
pub mod utils;

const LOG_SIZE: usize = 7;

const LOG_INV_RATE: usize = 1;
const SECURITY_BITS: usize = 100;

#[wasm_bindgen]
pub fn run_sha2(input_values: JsValue) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let allocator = bumpalo::Bump::new();
    let mut builder =
        ConstraintSystemBuilder::<OptimalUnderlier, BinaryField128b>::new_with_witness(&allocator);

    let input: Vec<u8> = input_values
        .as_string()
        .ok_or_else(|| JsValue::from("Input must be a valid hex string"))
        .and_then(|f| {
            hex::decode(f).map_err(|e| JsValue::from(format!("Failed to decode hex input: {e}")))
        })?;

    let output: Vec<u8> = sha2::trace_gen::<_, _, BinaryField1b>(&mut builder, input, LOG_SIZE)
        .map_err(|e| JsValue::from(format!("Failed to generate trace for SHA-2: {e}")))?
        .into_iter()
        .flat_map(|f| f.to_be_bytes())
        .collect();

    let witness = builder
        .take_witness()
        .expect("Builder was not properly initialized with a witness");
    let constraint_system = builder
        .build()
        .map_err(|e| JsValue::from(format!("Failed to build constraint system: {e}")))?;

    let domain_factory = DefaultEvaluationDomainFactory::default();
    let backend = make_portable_backend();

    let proof = constraint_system::prove::<
        OptimalUnderlier,
        CanonicalTowerFamily,
        BinaryField8b,
        _,
        _,
        GroestlHasher<BinaryField128b>,
        GroestlDigestCompression<BinaryField8b>,
        HasherChallenger<Groestl256>,
        _,
    >(
        &constraint_system,
        LOG_INV_RATE,
        SECURITY_BITS,
        witness,
        &domain_factory,
        &backend,
    )
    .map_err(|e| JsValue::from(format!("Proof generation failed: {e}")))?;

    constraint_system::verify::<
        OptimalUnderlier,
        CanonicalTowerFamily,
        _,
        _,
        GroestlHasher<BinaryField128b>,
        GroestlDigestCompression<BinaryField8b>,
        HasherChallenger<Groestl256>,
    >(
        &constraint_system.no_base_constraints(),
        LOG_INV_RATE,
        SECURITY_BITS,
        &domain_factory,
        vec![],
        proof,
    )
    .map_err(|e| JsValue::from(format!("Verification failed: {e}")))?;

    serde_wasm_bindgen::to_value(&hex::encode(output))
        .map_err(|e| JsValue::from(format!("Failed to serialize output: {e}")))
}

#[wasm_bindgen]
pub fn run_sha3(input_values: JsValue) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let allocator = bumpalo::Bump::new();
    let mut builder =
        ConstraintSystemBuilder::<OptimalUnderlier, BinaryField128b>::new_with_witness(&allocator);

    let input: Vec<u8> = input_values
        .as_string()
        .ok_or_else(|| JsValue::from("Input must be a valid hex string"))
        .and_then(|f| {
            hex::decode(f).map_err(|e| JsValue::from(format!("Failed to decode hex input: {e}")))
        })?;

    let output: Vec<u8> = sha3::trace_gen::<_, _, BinaryField1b>(&mut builder, input, LOG_SIZE)
        .map_err(|e| JsValue::from(format!("Failed to generate trace for SHA-3: {e}")))?
        .into_iter()
        .flat_map(|f| f.to_be_bytes())
        .collect();

    let witness = builder
        .take_witness()
        .expect("Builder was not properly initialized with a witness");
    let constraint_system = builder
        .build()
        .map_err(|e| JsValue::from(format!("Failed to build constraint system: {e}")))?;

    let domain_factory = DefaultEvaluationDomainFactory::default();
    let backend = make_portable_backend();

    let proof = constraint_system::prove::<
        OptimalUnderlier,
        CanonicalTowerFamily,
        BinaryField8b,
        _,
        _,
        GroestlHasher<BinaryField128b>,
        GroestlDigestCompression<BinaryField8b>,
        HasherChallenger<Groestl256>,
        _,
    >(
        &constraint_system,
        LOG_INV_RATE,
        SECURITY_BITS,
        witness,
        &domain_factory,
        &backend,
    )
    .map_err(|e| JsValue::from(format!("Proof generation failed: {e}")))?;

    constraint_system::verify::<
        OptimalUnderlier,
        CanonicalTowerFamily,
        _,
        _,
        GroestlHasher<BinaryField128b>,
        GroestlDigestCompression<BinaryField8b>,
        HasherChallenger<Groestl256>,
    >(
        &constraint_system.no_base_constraints(),
        LOG_INV_RATE,
        SECURITY_BITS,
        &domain_factory,
        vec![],
        proof,
    )
    .map_err(|e| JsValue::from(format!("Verification failed: {e}")))?;

    serde_wasm_bindgen::to_value(&hex::encode(output))
        .map_err(|e| JsValue::from(format!("Failed to serialize output: {e}")))
}
