use anyhow::Ok;
use binius_circuits::builder::ConstraintSystemBuilder;
use binius_core::{constraint_system, fiat_shamir::HasherChallenger, tower::CanonicalTowerFamily};
use binius_field::{arch::OptimalUnderlier, BinaryField128b, BinaryField1b, BinaryField8b};
use binius_hal::make_portable_backend;
use binius_hash::{GroestlDigestCompression, GroestlHasher};
use binius_math::DefaultEvaluationDomainFactory;
use groestl_crypto::Groestl256;
use std::convert::TryInto;

pub mod sha2;
pub mod sha3;
pub mod utils;

const LOG_INV_RATE: usize = 1;
const SECURITY_BITS: usize = 100;

pub fn main() -> anyhow::Result<()> {
    let log_size = 7;
    let allocator = bumpalo::Bump::new();
    let mut builder =
        ConstraintSystemBuilder::<OptimalUnderlier, BinaryField128b>::new_with_witness(&allocator);

    let input: Vec<u64> = hex::decode("aaccaa")?
        .chunks(8)
        .map(|chunk| {
            u64::from_le_bytes(
                chunk
                    .iter()
                    .cloned()
                    .chain(std::iter::repeat(0))
                    .take(8)
                    .collect::<Vec<u8>>()
                    .try_into()
                    .unwrap(),
            )
        })
        .collect();

    let output: Vec<u8> = sha2::trace_gen::<_, _, BinaryField1b>(&mut builder, input, log_size)
        .unwrap()
        .into_iter()
        .flat_map(|f| f.to_be_bytes())
        .collect();

    println!("{:?}", output);

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
    )?;

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
    )?;

    Ok(())
}
