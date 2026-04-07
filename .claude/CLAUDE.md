# Claude Instructions for rs-soroban-env

This is the Soroban smart contract execution environment for the Stellar blockchain. It's a complex Rust project with multiple crates and unique approaches.

## General Guidelines

- **Ask before assuming**: This is a complex project with many unique approaches. If unsure whether a feature already exists based on initial search, or if unsure how something can be implemented, ask the user instead of making arbitrary decisions.

## Building and Testing

- **Use `cargo hack`**: Use `cargo hack build` and `cargo hack test` for builds and tests to easily cover all the projects in the workspace.
- **Testing is mandatory**: Testing the whole project with `cargo hack test` is mandatory before considering any change complete.
- Use `test-opt` profile when you need to run tests with optimized binary. Don't use `--release` unless explicitly requested, as it builds much slower.

### Updating Test Values

There are two kinds of updatable test values:

1. **`expect!` macro tests**: Updated by running tests with the `UPDATE_EXPECT` environment variable set:
   ```sh
   UPDATE_EXPECT=1 cargo hack test
   ```

2. **Observations**: Execution traces stored in JSON files under `soroban-env-host/observations/`. Update these with:
   ```sh
   make reobserve-tests
   ```

## Code Quality

- **Format code**: Always run `cargo fmt` after performing changes and before committing.
- **Descriptive commits**: Always commit changes with a descriptive commit message.

## Planning and Commits

- When creating plans, break them down by individual commits.
- When implementing plans, create commits as per the plan, optionally adding more commits if needed.

## Metering

Metering is mandatory on most operations to track resource usage:

- Use metered operations for all non-trivial data types (e.g., `metered_clone` instead of `clone`).
- As a rule of thumb, raw `clone` should not appear in the code unless guarded by `test`/`testutils` feature or recording mode.
   - A notable exception to the metered clones is `Rc::clone` - prefer using it explicitly when cloning `Rc`
   - Trivial data types (those that have `Copy` of course don't need clone metering)

## Error Handling

- **No unwraps/panics**: `unwrap()` and `panic!()` are generally prohibited. Return an appropriate error instead, typically via `host.err(...)`.
- **Invariant errors**: Conditions that would semantically be `assert!` should be conveyed as `InternalError`.
- **Strict invariant enforcement**: Don't handle edge cases that should "never appear" gracefully. Instead, return an internal error. Enforce invariants as strictly as possible.

## Spelling

Spell 'Wasm', not WASM.

## Project Structure

- `soroban-env-common/` - Common types and traits shared between guest and host
- `soroban-env-guest/` - Guest-side (Wasm) environment interface
- `soroban-env-host/` - Host-side environment implementation (main crate)
- `soroban-env-macros/` - Procedural macros for the environment
- `soroban-builtin-sdk-macros/` - Macros for builtin contracts
- `soroban-synth-wasm/` - Wasm synthesis utilities
- `soroban-simulation/` - Transaction simulation
- `soroban-bench-utils/` - Benchmarking utilities
- `soroban-test-wasms/` - Test Wasm contracts
