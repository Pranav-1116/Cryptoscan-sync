//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for the
//! HMAC family of algorithms using `RustCrypto`'s [`hmac`].

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};
use signature::{Signer, Verifier};

use crate::crypto::{JwtSigner, JwtVerifier};
use crate::errors::{ErrorKind, Result, new_error};
use crate::{Algorithm, AlgorithmFamily, DecodingKey, EncodingKey};

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;
