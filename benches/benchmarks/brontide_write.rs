use brontide::BrontideBuilder;
use criterion::black_box;
use criterion::criterion_group;
use criterion::Criterion;

//Should be iter batched TODO
fn brontide_write_benchmark(c: &mut Criterion) {
    c.bench_function("brontide write", |b| {
        b.iter_with_setup(
            || BrontideBuilder::new([1; 32]).build(),
            |mut v| v.write(black_box("hello".as_bytes().to_vec())),
        );
    });
}

criterion_group!(benches, brontide_write_benchmark);
