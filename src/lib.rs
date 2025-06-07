use derive_builder::Builder;
use jsonwebtoken;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

/// Represents the claims in a JWT token.
#[derive(Debug, Serialize, Deserialize, Clone, Builder)]
#[builder(pattern = "owned", setter(into), build_fn(error = "TokenError"))]
pub struct TokenClaims<T>
where
    T: Serialize + DeserializeOwned,
{
    #[cfg_attr(
        feature = "msgpack",
        serde(
            serialize_with = "serde_helpers::serialize_msgpack",
            deserialize_with = "serde_helpers::deserialize_msgpack"
        )
    )]
    #[cfg_attr(
        not(feature = "msgpack"),
        serde(
            serialize_with = "serde_helpers::serialize_json",
            deserialize_with = "serde_helpers::deserialize_json"
        )
    )]
    pub sub: Subject<T>, // Subject
    pub exp: TimeStamp, // Expiration time (Unix timestamp)
    pub iat: TimeStamp, // Issued at (Unix timestamp)
    pub typ: String,    // Type
    pub iss: String,    // Issuer
    pub aud: String,    // Audience
    pub jti: JWTID,     // JWT ID
}

impl<T> TokenClaims<T>
where
    T: Serialize + DeserializeOwned,
{
    /// Returns the subject of the token.
    pub fn sub(&self) -> &Subject<T> {
        &self.sub
    }
    /// Returns the expiration time of the token.
    pub fn exp(&self) -> TimeStamp {
        self.exp
    }
    /// Returns the issued-at time of the token.
    pub fn iat(&self) -> TimeStamp {
        self.iat
    }
    /// Returns the issuer of the token.
    pub fn iss(&self) -> &str {
        &self.iss
    }
    /// Returns the type of the token.
    pub fn typ(&self) -> &str {
        &self.typ
    }
    /// Returns the audience of the token.
    pub fn aud(&self) -> &str {
        &self.aud
    }
    /// Returns the JWT ID of the token.
    pub fn jti(&self) -> &JWTID {
        &self.jti
    }
}

/// Represents the subject of a JWT token.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Subject<T>(pub T);

impl<T> Subject<T> {
    pub fn new(sub: T) -> Self {
        Self(sub)
    }
    pub fn value(&self) -> &T {
        &self.0
    }
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> std::ops::Deref for Subject<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<T> std::ops::DerefMut for Subject<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Represents a timestamp in a JWT token.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TimeStamp(i64);

impl TimeStamp {
    /// Returns the current timestamp.
    pub fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }
    pub fn from_now(seconds: i64) -> Self {
        TimeStamp(Self::now() + seconds)
    }
    /// Creates a `TimeStamp` from a raw Unix timestamp.
    pub fn from_i64(timestamp: i64) -> Self {
        TimeStamp(timestamp)
    }
    /// Checks if the timestamp is expired.
    pub fn is_expired(&self) -> bool {
        self.0 < TimeStamp::now()
    }
    pub fn left_till(&self) -> i64 {
        self.0 - TimeStamp::now()
    }
    pub fn extend(&mut self, seconds: i64) {
        self.0 += seconds;
    }
    pub fn to_i64(&self) -> i64 {
        self.0
    }
}

impl From<i64> for TimeStamp {
    fn from(value: i64) -> Self {
        TimeStamp(value)
    }
}

impl<T> From<T> for Subject<T>
where
    T: Serialize + DeserializeOwned,
{
    fn from(value: T) -> Self {
        Subject::new(value)
    }
}

/// Custom error type for token-related operations.
#[derive(Error, Debug)]
pub enum TokenError {
    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),
    #[error("Invalid token format")]
    InvalidTokenFormat,
}

impl From<derive_builder::UninitializedFieldError> for TokenError {
    fn from(_: derive_builder::UninitializedFieldError) -> Self {
        TokenError::InvalidTokenFormat
    }
}

/// Represents a unique JWT ID (JTI).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JWTID(String);

impl JWTID {
    /// Creates a new unique JWT ID.
    pub fn new() -> Self {
        JWTID(uuid::Uuid::new_v4().to_string())
    }
    /// Creates a `JWTID` from a string.
    pub fn from_string(id: &str) -> Self {
        JWTID(id.to_string())
    }
    /// Converts the `JWTID` to a string.
    pub fn to_string(&self) -> String {
        self.0.clone()
    }
}
impl std::fmt::Display for JWTID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
#[cfg(feature = "msgpack")]
mod serde_helpers {
    use base64::{Engine as _, engine::general_purpose};
    use rmp_serde::{from_slice, to_vec};
    use serde::Deserialize;
    use serde::{Serialize, de::DeserializeOwned};

    pub fn serialize_msgpack<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Serialize,
        S: serde::Serializer,
    {
        let bytes = to_vec(value).map_err(serde::ser::Error::custom)?;
        let b64 = general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&b64)
    }

    pub fn deserialize_msgpack<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: DeserializeOwned,
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = general_purpose::STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)?;
        from_slice(&bytes).map_err(serde::de::Error::custom)
    }

    pub fn serialize_json<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Serialize,
        S: serde::Serializer,
    {
        let json_str = serde_json::to_string(value).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&json_str)
    }

    pub fn deserialize_json<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: DeserializeOwned,
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        serde_json::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(not(feature = "msgpack"))]
mod serde_helpers {
    use serde::Deserialize;
    use serde::{Serialize, de::DeserializeOwned};

    pub fn serialize_json<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Serialize,
        S: serde::Serializer,
    {
        let json_str = serde_json::to_string(value).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&json_str)
    }

    pub fn deserialize_json<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: DeserializeOwned,
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        serde_json::from_str(&s).map_err(serde::de::Error::custom)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
    struct CustomClaims {
        username: String,
        admin: bool,
    }

    #[test]
    fn test_token_encode_decode_custom_claims() {
        let claims = TokenClaimsBuilder::<CustomClaims>::default()
            .sub(Subject::new(CustomClaims {
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

        let secret = b"supersecretkey";
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(secret),
        )
        .unwrap();
        let mut validation = jsonwebtoken::Validation::default();
        validation.set_audience(&["audience"]);
        let decoded_claims: TokenClaims<CustomClaims> =
            jsonwebtoken::decode::<TokenClaims<CustomClaims>>(
                &token,
                &jsonwebtoken::DecodingKey::from_secret(secret),
                &validation,
            )
            .unwrap()
            .claims;

        assert_eq!(decoded_claims.sub().value(), claims.sub().value());
        assert_eq!(decoded_claims.typ(), claims.typ());
        assert_eq!(decoded_claims.iss(), claims.iss());
        assert_eq!(decoded_claims.aud(), claims.aud());
        assert_eq!(decoded_claims.jti().to_string(), claims.jti().to_string());
    }

    #[test]
    fn test_token_encode_decode_primitive_claims() {
        let claims = TokenClaimsBuilder::<u32>::default()
            .sub(Subject::new(42u32))
            .exp(TimeStamp::from_now(3600))
            .iat(TimeStamp::from_now(0))
            .typ("number".to_string())
            .iss("issuer".to_string())
            .aud("audience".to_string())
            .jti(JWTID::new())
            .build()
            .unwrap();

        let secret = b"anothersecret";
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(secret),
        )
        .unwrap();

        let mut validation = jsonwebtoken::Validation::default();
        validation.set_audience(&["audience"]);
        let decoded_claims: TokenClaims<u32> = jsonwebtoken::decode::<TokenClaims<u32>>(
            &token,
            &jsonwebtoken::DecodingKey::from_secret(secret),
            &validation,
        )
        .unwrap()
        .claims;

        assert_eq!(decoded_claims.sub().value(), claims.sub().value());
        assert_eq!(decoded_claims.typ(), claims.typ());
        assert_eq!(decoded_claims.iss(), claims.iss());
        assert_eq!(decoded_claims.aud(), claims.aud());
        assert_eq!(decoded_claims.jti().to_string(), claims.jti().to_string());
    }
}
