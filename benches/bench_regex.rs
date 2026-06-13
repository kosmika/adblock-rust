use criterion::*;

use fancy_regex::Regex;

fn bench_simple_regexes(c: &mut Criterion) {
    let mut group = c.benchmark_group("regex");

    let pattern = "?/static/adv/foobar/asd?q=1";

    let rules = [
        Regex::new(r"(?:[^\\w\\d\\._%-])/static/ad-").unwrap(),
        Regex::new(r"(?:[^\\w\\d\\._%-])/static/ad/.*").unwrap(),
        Regex::new(r"(?:[^\\w\\d\\._%-])/static/ads/.*").unwrap(),
        Regex::new(r"(?:[^\\w\\d\\._%-])/static/adv/.*").unwrap(),
    ];

    group.bench_function("list", move |b| {
        b.iter(|| {
            for rule in rules.iter() {
                std::hint::black_box(rule.is_match(pattern).unwrap_or(false));
            }
        })
    });

    group.finish();
}

fn bench_joined_regex(c: &mut Criterion) {
    let mut group = c.benchmark_group("regex");

    let pattern = "?/static/adv/foobar/asd?q=1";

    let rule = Regex::new(
        r"(?:(?:[^\\w\\d\\._%-])/static/ad-)|(?:(?:[^\\w\\d\\._%-])/static/ad/.*)|(?:(?:[^\\w\\d\\._%-])/static/ads/.*)|(?:(?:[^\\w\\d\\._%-])/static/adv/.*)",
    )
    .unwrap();

    group.bench_function("joined", move |b| {
        b.iter(|| std::hint::black_box(rule.is_match(pattern).unwrap_or(false)))
    });

    group.finish();
}

criterion_group!(benches, bench_simple_regexes, bench_joined_regex);
criterion_main!(benches);
