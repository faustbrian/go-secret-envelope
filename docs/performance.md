# Performance

The maintained `BenchmarkServiceRoundTrip` exercises one 1 KiB encrypt and
decrypt round trip, including service construction, envelope construction,
AES-256-GCM encryption and decryption, copying, and best-effort data-key
zeroization. It uses an in-memory recording provider and deterministic nonce
bytes, so it does **not** measure keyring wrapping, entropy-source behavior,
AWS KMS latency, network transport, SDK retries, credential resolution, or
application persistence.

Run the benchmark directly with allocation reporting:

```sh
go test -run '^$' -bench '^BenchmarkServiceRoundTrip$' -benchmem .
```

The complete `make check` contract also runs this benchmark with the
repository's bounded gate settings.

For useful comparisons, run repeated samples on the same host with the same Go
version, CPU settings, payload shape, and benchmark duration. Record `ns/op`,
`B/op`, and `allocs/op`; use a statistical comparison such as `benchstat` when
evaluating a change. The repository does not publish a machine-independent
latency or allocation budget for this benchmark.

For capacity planning, benchmark the application's complete path with realistic
payload sizes and the selected provider. AWS KMS deployments must measure
provider latency, retry behavior, throttling, network conditions, and caller
deadlines separately from the bounded local cryptographic work. After a
provider succeeds, context cancellation cannot interrupt an injected nonce
read or local AES-GCM encryption or decryption.

Do not weaken authentication, input bounds, nonce uniqueness, key zeroization,
or redaction to improve a microbenchmark result.
