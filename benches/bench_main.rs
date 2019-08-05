// use brontide::BrontideBuilder;
// use criterion::black_box;
// use criterion::criterion_group;
use criterion::criterion_main;
// use criterion::Criterion;
//
mod benchmarks;

//TODO need a create random brontide function.
//TODO need a crate random key function.
//TODO need a create random data function. -> For this we could use packets or blocks, and just
//generate random encoded data from them.

//Should be iter batched TODO
// fn brontide_write_size_benchmark(c: &mut Criterion) {
//     static KB: usize = 1024;

//     c.bench_function_over_inputs(
//         "brontide write size",
//         |b, &size| {
//             b.iter_with_setup(
//                 || BrontideBuilder::new([1; 32]).build(),
//                 |mut v| v.write(black_box(vec![0_u8; size])),
//             )
//         },
//         vec![KB * 1, KB * 2, KB * 100, KB * 200, KB * 500, KB * 1000],
//     );
// }

// criterion_group!(benches, criterion_benchmark);
// criterion_group!(benches, brontide_write_benchmark);
// criterion_group!(benches, brontide_write_size_benchmark);
criterion_main! {
    benchmarks::brontide_write::benches
}
