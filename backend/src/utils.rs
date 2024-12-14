use binius_circuits::builder::ConstraintSystemBuilder;
use binius_core::oracle::OracleId;
use binius_field::{
    as_packed_field::PackScalar, underlier::UnderlierType, BinaryField1b, BinaryField64b,
    ExtensionField, TowerField,
};
use bytemuck::Pod;
use std::array;

pub fn load_input<U, F, FS>(
    builder: &mut ConstraintSystemBuilder<U, F>,
    name: impl ToString,
    values: Vec<u8>,
    log_size: usize,
) -> Vec<usize>
where
    U: UnderlierType + Pod + PackScalar<F> + PackScalar<FS>,
    F: TowerField + ExtensionField<FS>,
    FS: TowerField,
{
    values
        .into_iter()
        .map(|f| {
            let oracle = builder.add_committed(name.to_string(), log_size, FS::TOWER_LEVEL);
            builder
                .witness()
                .unwrap()
                .new_column::<FS>(oracle)
                .as_mut_slice::<u8>()
                .fill(f);
            oracle
        })
        .collect()
}

pub fn extract_output<U, F, FS, const SIZE: usize>(
    builder: &mut ConstraintSystemBuilder<U, F>,
    state: [OracleId; SIZE],
) -> [u64; SIZE]
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
