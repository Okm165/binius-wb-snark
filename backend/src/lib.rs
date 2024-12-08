use binius_circuits::builder::ConstraintSystemBuilder;
use binius_core::{
    constraint_system, fiat_shamir::HasherChallenger, oracle::OracleId, tower::CanonicalTowerFamily,
};
use binius_field::{
    arch::OptimalUnderlier, as_packed_field::PackScalar, underlier::UnderlierType, BinaryField128b,
    BinaryField1b, BinaryField64b, BinaryField8b, ExtensionField, TowerField,
};
use binius_hal::make_portable_backend;
use binius_hash::{GroestlDigestCompression, GroestlHasher};
use binius_math::DefaultEvaluationDomainFactory;
use bytemuck::Pod;
use groestl_crypto::Groestl256;
use std::{array, convert::TryInto, num::ParseIntError};
use wasm_bindgen::prelude::*;

const STATE_SIZE: usize = 25;
const LOG_INV_RATE: usize = 1;
const SECURITY_BITS: usize = 100;
const LOG_ROWS_PER_PERMUTATION: usize = 6;

#[wasm_bindgen]
pub fn run(input_values: JsValue) -> Result<JsValue, JsValue> {
    set_panic_hook();

    // Parse input
    let values: [u64; STATE_SIZE] = serde_wasm_bindgen::from_value::<Vec<String>>(input_values)?
        .into_iter()
        .map(|f| f.parse::<u64>())
        .collect::<Result<Vec<u64>, ParseIntError>>()
        .map_err(|e: ParseIntError| JsValue::from(format!("Failed to parse input value {}", e)))?
        .try_into()
        .map_err(|_| JsValue::from(format!("Input must have exactly {} elements.", STATE_SIZE)))?;

    let log_size = LOG_ROWS_PER_PERMUTATION + 1; // Make the row count pow of 2 ( we calculate same keccak twice )
    let allocator = bumpalo::Bump::new();
    let mut builder =
        ConstraintSystemBuilder::<OptimalUnderlier, BinaryField128b>::new_with_witness(&allocator);

    let input_oracles = load_input::<_, _, BinaryField1b>(&mut builder, "input", values, log_size);
    let state_out =
        binius_circuits::keccakf::keccakf(&mut builder, input_oracles, log_size).unwrap();
    let output = extract_output::<_, _, BinaryField1b>(&mut builder, state_out);

    let witness = builder
        .take_witness()
        .expect("builder created with witness");
    let constraint_system = builder.build().unwrap();

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
    .map_err(|e| format!("Proof generation failed: {}", e))?;

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
    .map_err(|e| format!("Verification failed: {}", e))?;

    Ok(serde_wasm_bindgen::to_value(
        &output.map(|f| f.to_string()),
    )?)
}

pub fn load_input<U, F, FS>(
    builder: &mut ConstraintSystemBuilder<U, F>,
    name: impl ToString,
    values: [u64; STATE_SIZE],
    log_size: usize,
) -> [usize; STATE_SIZE]
where
    U: UnderlierType + Pod + PackScalar<F> + PackScalar<FS>,
    F: TowerField + ExtensionField<FS>,
    FS: TowerField,
{
    let oracle_ids = builder.add_committed_multiple(name, log_size, FS::TOWER_LEVEL);
    let witness = builder.witness().unwrap();

    oracle_ids.iter().zip(values).for_each(|(oracle, value)| {
        witness
            .new_column::<FS>(*oracle)
            .as_mut_slice::<u64>()
            .fill(value);
    });

    oracle_ids
}

pub fn extract_output<U, F, FS>(
    builder: &mut ConstraintSystemBuilder<U, F>,
    state: [OracleId; STATE_SIZE],
) -> [u64; STATE_SIZE]
where
    U: UnderlierType + Pod + PackScalar<F> + PackScalar<BinaryField1b> + PackScalar<BinaryField64b>,
    F: TowerField,
    <U as PackScalar<BinaryField64b>>::Packed: Pod,
{
    let witness = builder.witness().unwrap();

    let mut state_out = state.map(|id| witness.get::<BinaryField1b>(id).unwrap());
    let state_out_u64 = state_out
        .iter_mut()
        .map(|col| col.as_slice::<u64>())
        .collect::<Vec<_>>();
    array::from_fn(|xy| state_out_u64[xy][0])
}

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}
