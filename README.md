# token-claims

A Rust library for ergonomic handling of JWT claims with strong typing and builder support.

## Features

- Generic `TokenClaims<T>` struct for custom or primitive claim types.
- Builder pattern for easy construction of claims.
- Support for both JSON and optional MessagePack serialization (via `msgpack` feature).
- Helper types for subject (`Subject<T>`), timestamp (`TimeStamp`), and JWT ID (`JWTID`).
- Custom error handling for token operations.
- Thoroughly tested with custom and primitive claim types.

## Example

```rust
use token_claims::{TokenClaimsBuilder, Subject, TimeStamp, JWTID};

#[derive(serde::Serialize, serde::Deserialize)]
struct MyClaims {
    username: String,
    admin: bool,
}

let claims = TokenClaimsBuilder::<MyClaims>::default()
    .sub(Subject::new(MyClaims {
        username: "alice".to_string(),
        admin: true,
    }))
    .exp(TimeStamp::from_now(3600))
    .iat(TimeStamp::from_now(0))
    .typ("access".to_string())
    .iss("issuer".to_string())
    .aud("audience".to_string())
    .jti(JWTID::new())
    .build()
    .unwrap();
```
