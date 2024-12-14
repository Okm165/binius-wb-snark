use crate::utils::{extract_output, load_input};
use binius_circuits::{
    builder::ConstraintSystemBuilder,
    sha256::{u32const_repeating, INIT},
};
use binius_core::oracle::OracleId;
use binius_field::{
    as_packed_field::PackScalar, underlier::UnderlierType, BinaryField1b, BinaryField64b,
    ExtensionField, TowerField,
};
use bytemuck::Pod;
use std::convert::TryInto;

const CHUNK_SIZE: usize = 16;

pub fn trace_gen<U, F, FS>(
    builder: &mut ConstraintSystemBuilder<U, F>,
    input: Vec<u64>,
    log_size: usize,
) -> Result<Vec<u64>, anyhow::Error>
where
    U: UnderlierType
        + Pod
        + PackScalar<F>
        + PackScalar<BinaryField1b>
        + PackScalar<BinaryField64b>
        + PackScalar<FS>,
    F: TowerField + ExtensionField<FS>,
    <U as PackScalar<BinaryField64b>>::Packed: Pod,
    FS: TowerField,
{
    let input_oracles = load_input::<_, _, BinaryField1b>(builder, "input", input, log_size);
    let state = sha2::<_, _, BinaryField1b>(builder, input_oracles.to_vec(), log_size).unwrap();
    Ok(extract_output::<_, _, BinaryField1b, 8>(builder, state).to_vec())
}

pub fn sha2<U, F, FS>(
    builder: &mut ConstraintSystemBuilder<U, F>,
    mut input: Vec<OracleId>,
    log_size: usize,
) -> Result<[OracleId; 8], anyhow::Error>
where
    U: UnderlierType + Pod + PackScalar<F> + PackScalar<BinaryField1b> + PackScalar<FS>,
    F: TowerField + ExtensionField<FS>,
    FS: TowerField,
{
    input.extend((0..CHUNK_SIZE - input.len() % CHUNK_SIZE).map(|_| {
        let oracle = builder.add_committed("input_padding", log_size, FS::TOWER_LEVEL);
        builder
            .witness()
            .unwrap()
            .new_column::<FS>(oracle)
            .as_mut_slice::<u64>()
            .fill(0);
        oracle
    }));

    let mut state = INIT.map(|val| u32const_repeating(log_size, builder, val, "INIT").unwrap());
    for chunk in input.chunks_exact(CHUNK_SIZE) {
        state = binius_circuits::sha256::sha256(
            builder,
            state,
            (*chunk).try_into().unwrap(),
            log_size,
        )?;
    }
    Ok(state)
}
