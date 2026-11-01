
use hickory_resolver::TokioResolver;
use hickory_resolver::lookup::Lookup;

fn test_resolver() {
    let _ = TokioResolver::tokio();
}

fn test_lookup(l: Lookup) {
    let _ = l.record_iter();
}
