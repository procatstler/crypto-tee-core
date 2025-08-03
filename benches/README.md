# Benchmarks

This directory contains performance benchmarks for the CryptoTEE project.

## Running Benchmarks

### Basic benchmark run:
```bash
cargo bench
```

### Run with specific features:
```bash
cargo bench --features "simulator,simulator-samsung,simulator-apple,simulator-qualcomm"
```

### Save a baseline for comparison:
```bash
cargo bench -- --save-baseline my-baseline
```

### Compare against a baseline:
```bash
cargo bench -- --baseline my-baseline
```

## Benchmark Structure

- `performance_tests.rs` - Main performance benchmarks for key operations
- Each benchmark measures:
  - Key generation time
  - Signing performance
  - Verification performance
  - Attestation operations

## CI Integration

The CI system automatically:
1. Generates baseline benchmarks on the main branch
2. Compares PR benchmarks against the baseline
3. Reports any performance regressions
4. Stores historical benchmark data using GitHub Action Benchmark

## Interpreting Results

- **Time**: Lower is better
- **Throughput**: Higher is better
- **±**: Standard deviation (lower means more consistent performance)
- **Change**: Percentage change from baseline (negative is improvement)

### Performance Regression Thresholds

- **Warning**: 50% slower than baseline
- **Failure**: 200% slower than baseline (configured in CI)

## Adding New Benchmarks

1. Add benchmark functions to `performance_tests.rs`
2. Use the criterion macros:
   ```rust
   fn bench_new_operation(c: &mut Criterion) {
       c.bench_function("operation_name", |b| {
           b.iter(|| {
               // Your operation here
           });
       });
   }
   ```
3. Register in the criterion group at the bottom of the file