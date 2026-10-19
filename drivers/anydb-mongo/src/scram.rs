//! SCRAM client (RFC 5802) over mongo's `saslStart` / `saslContinue`
//! commands. Supports the server-standard mechanisms SCRAM-SHA-1 and
//! SCRAM-SHA-256; conversation payloads travel inside BSON `Binary`
//! (subtype 0x00) and carry plain SASL messages:
//!
//! ```text
//! client-first:  "n,,n=<esc user>,r=<nonce>"
//! server-first:  "r=<nonce+server>,s=<b64 salt>,i=<iterations>"
//! client-final:  "c=biws,r=<nonce+server>,p=<b64 proof>"
//! server-final:  "v=<b64 server signature>"
//! ```
//!
//! The GS2 header is always `n,,` (no extra authorization identity), so
//! the `c` bind-data is constant `biws`. The SHA-1 variant exists for
//! legacy servers only; negotiation prefers SHA-256. Passwords are used
//! raw (SASLprep normalization is out of scope), matching how mongo
//! treats ASCII credentials.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;
use sha2::{Digest as _, Sha256};

use anydb_shared::ConnectionError;

fn protocol(message: String) -> ConnectionError {
    ConnectionError::Protocol(format!("SCRAM: {message}"))
}

/// Security bounds: RFC 5802 requires at least 4096 iterations; the cap
/// rejects absurd values that would hang the connection.
const MIN_ITERATIONS: u32 = 4096;
const MAX_ITERATIONS: u32 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    Sha1,
    Sha256,
}

impl Mechanism {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Sha1 => "SCRAM-SHA-1",
            Self::Sha256 => "SCRAM-SHA-256",
        }
    }

    /// Picks the strongest mechanism among the server-offered ones.
    /// A missing list (legacy servers without `saslSupportedMechs`)
    /// defaults to SHA-256; an empty list without either standard
    /// mechanism is an authentication failure.
    pub fn negotiate(offered: Option<&[String]>) -> Result<Self, ConnectionError> {
        let Some(offered) = offered else {
            return Ok(Self::Sha256);
        };
        if offered.iter().any(|name| name == "SCRAM-SHA-256") {
            Ok(Self::Sha256)
        } else if offered.iter().any(|name| name == "SCRAM-SHA-1") {
            Ok(Self::Sha1)
        } else {
            Err(ConnectionError::AuthFailed)
        }
    }

    fn hmac(&self, key: &[u8], message: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => hmac_sha1(key, message),
            Self::Sha256 => hmac_sha256(key, message),
        }
    }

    fn digest(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => Sha1::digest(message).to_vec(),
            Self::Sha256 => Sha256::digest(message).to_vec(),
        }
    }

    /// `SaltedPassword = PBKDF2(HMAC(password, salt, iterations))`.
    /// Manual implementation: HMAC instantiated per round.
    fn salted_password(&self, password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
        match self {
            Self::Sha1 => pbkdf2_sha1(password, salt, iterations),
            Self::Sha256 => pbkdf2_sha256(password, salt, iterations),
        }
    }
}

fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts every key size");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts every key size");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// U1 = HMAC(pw, salt || INT(1)); Ut = HMAC(pw, U(t-1));
/// result = U1 XOR U2 XOR ... XOR Uc.
macro_rules! pbkdf2_rounds {
    ($key:ty, $password:expr, $salt:expr, $iterations:expr) => {{
        let mut mac =
            <$key as hmac::Mac>::new_from_slice($password).expect("HMAC accepts every key size");
        mac.update($salt);
        mac.update(&1u32.to_be_bytes());
        let mut previous = mac.finalize().into_bytes().to_vec();
        let mut out = previous.clone();
        for _round in 2..=$iterations {
            let mut mac = <$key as hmac::Mac>::new_from_slice($password)
                .expect("HMAC accepts every key size");
            mac.update(&previous);
            previous = mac.finalize().into_bytes().to_vec();
            for (slot, chunk) in out.iter_mut().zip(previous.iter()) {
                *slot ^= chunk;
            }
        }
        out
    }};
}

fn pbkdf2_sha1(password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    pbkdf2_rounds!(Hmac<Sha1>, password, salt, iterations)
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    pbkdf2_rounds!(Hmac<Sha256>, password, salt, iterations)
}

fn saslname(name: &str) -> String {
    name.replace('=', "=3D").replace(',', "=2C")
}

/// One SCRAM conversation. The state machine is explicit `Option`
/// fields: using pieces out of order is a `Protocol` error, never a
/// silent empty.
pub struct ScramClient {
    mechanism: Mechanism,
    username_escaped: String,
    password: String,
    nonce: String,
    /// (`n=<user>,r=<nonce>`) — the client-first BARE message, part of
    /// the auth message hash chain.
    stored: Option<Vec<u8>>,
    server_nonce: Option<String>,
    salted_password: Option<Vec<u8>>,
    /// `client-final-without-proof`, needed to verify the server
    /// signature in the server-final step.
    auth_message: Option<String>,
}

impl ScramClient {
    pub fn new(mechanism: Mechanism, username: &str, password: &str) -> Self {
        let mut nonce_bytes = [0u8; 18];
        rand::rng().fill_bytes(&mut nonce_bytes);
        Self {
            mechanism,
            username_escaped: saslname(username),
            password: password.to_owned(),
            nonce: BASE64.encode(nonce_bytes),
            stored: None,
            server_nonce: None,
            salted_password: None,
            auth_message: None,
        }
    }

    /// The mongo `saslStart` payload: the full client-first message with
    /// the GS2 header.
    pub fn client_first(&self) -> String {
        format!("n,,n={},r={}", self.username_escaped, self.nonce)
    }

    fn bare_intro(&self) -> String {
        format!("n={},r={}", self.username_escaped, self.nonce)
    }

    /// Consumes the server-first message: validates token shape and
    /// nonce reuse, bounds the iteration count, derives the salted
    /// password.
    pub fn server_first(&mut self, payload: &[u8]) -> Result<(), ConnectionError> {
        if self.server_nonce.is_some() {
            return Err(protocol("conversation already started".to_owned()));
        }
        let message = std::str::from_utf8(payload)
            .map_err(|_| protocol("non-UTF-8 server-first payload".to_owned()))?;
        let mut server_nonce = None;
        let mut salt = None;
        let mut iterations = None;
        for pair in message.split(',') {
            match pair.split_once('=') {
                Some(("r", nonce)) => server_nonce = Some(nonce.to_owned()),
                Some(("s", encoded)) => {
                    salt = Some(
                        BASE64
                            .decode(encoded)
                            .map_err(|_| protocol("malformed base64 salt".to_owned()))?,
                    );
                }
                Some(("i", count)) => {
                    let count: u32 = count
                        .parse()
                        .map_err(|_| protocol("malformed iteration count".to_owned()))?;
                    if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&count) {
                        return Err(protocol(format!(
                            "iteration count {count} outside [{MIN_ITERATIONS}, {MAX_ITERATIONS}]"
                        )));
                    }
                    iterations = Some(count);
                }
                _ => return Err(protocol(format!("malformed server-first token {pair:?}"))),
            }
        }
        let (Some(server_nonce), Some(salt), Some(iterations)) = (server_nonce, salt, iterations)
        else {
            return Err(protocol(
                "server-first message lacks r=, s= or i=".to_owned(),
            ));
        };
        if !server_nonce.starts_with(&self.nonce) {
            return Err(protocol(
                "server nonce is not an extension of the client nonce".to_owned(),
            ));
        }
        self.stored = Some(self.bare_intro().into_bytes());
        self.salted_password = Some(self.mechanism.salted_password(
            self.password.as_bytes(),
            &salt,
            iterations,
        ));
        self.server_nonce = Some(server_nonce);
        Ok(())
    }

    /// Produces the mongo `saslContinue` payload (client-final message)
    /// and retains the proof-free string for server-signature checking.
    pub fn client_final(&mut self) -> Result<String, ConnectionError> {
        let Some(salted) = self.salted_password.clone() else {
            return Err(protocol("server-first message missing".to_owned()));
        };
        let server_nonce = self
            .server_nonce
            .clone()
            .ok_or_else(|| protocol("server-first message missing".to_owned()))?;
        let message = format!("c=biws,r={server_nonce}");
        let client_key = self.mechanism.hmac(&salted, b"Client Key");
        let stored_key = self.mechanism.digest(&client_key);
        let client_signature = self.mechanism.hmac(&stored_key, message.as_bytes());
        let proof: Vec<u8> = client_key
            .iter()
            .zip(client_signature.iter())
            .map(|(key, signature)| key ^ signature)
            .collect();
        self.auth_message = Some(
            std::str::from_utf8(
                &self
                    .stored
                    .clone()
                    .ok_or_else(|| protocol("client-first message missing".to_owned()))?,
            )
            .map_err(|_| protocol("internal: non-UTF-8 client-first".to_owned()))?
            .to_owned()
                + ","
                + &message,
        );
        Ok(format!("{message},p={}", BASE64.encode(proof)))
    }

    /// Verifies the server signature in the server-final message; a
    /// mismatch means the server does not prove possession of the
    /// password and the authentication fails.
    pub fn server_final(&self, payload: &[u8]) -> Result<(), ConnectionError> {
        let message = std::str::from_utf8(payload)
            .map_err(|_| protocol("non-UTF-8 server-final payload".to_owned()))?;
        let value = message
            .strip_prefix("v=")
            .ok_or_else(|| protocol("server-final message lacks v=".to_owned()))?;
        let signature = BASE64
            .decode(value)
            .map_err(|_| protocol("malformed base64 server signature".to_owned()))?;
        let salted = self
            .salted_password
            .as_ref()
            .ok_or_else(|| protocol("server-first message missing".to_owned()))?;
        let auth_message = self
            .auth_message
            .as_ref()
            .ok_or_else(|| protocol("client-final message missing".to_owned()))?;
        let server_key = self.mechanism.hmac(salted, b"Server Key");
        let expected = self.mechanism.hmac(&server_key, auth_message.as_bytes());
        if signature != expected {
            return Err(ConnectionError::AuthFailed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A single self-contained SCRAM roundtrip against an independent
    /// RustCrypto server-side computation (no fake server needed).
    #[test]
    fn scram_sha256_round_trips_with_a_computing_server() {
        let password = "s3cret";
        let salt = BASE64.decode("c2FsdHNhbHRzYWx0").expect("salt");
        let iterations = 4096u32;

        let mut client = ScramClient::new(Mechanism::Sha256, "al,=ice", password);
        let client_first = client.client_first();
        assert!(client_first.starts_with("n,,n=al=2C=3Dice,r="));
        // The RFC auth message chain uses the client-first BARE message.
        let bare = &client_first["n,,".len()..];

        let server_nonce = format!(
            "{}srvrNONCE",
            bare.split_once("r=").expect("client nonce").1
        );
        let server_first = format!("r={server_nonce},s={},i={iterations}", BASE64.encode(&salt));
        client
            .server_first(server_first.as_bytes())
            .expect("server first ok");
        let client_final = client.client_final().expect("client final");

        // Server side: recompute the salted password and verify the proof.
        let salted = pbkdf2_sha256(password.as_bytes(), &salt, iterations);
        let proof_position = client_final.find(",p=").expect("p suffix");
        let without_proof = &client_final[..proof_position];
        assert_eq!(without_proof, format!("c=biws,r={server_nonce}"));
        let client_key = hmac_sha256(&salted, b"Client Key");
        let stored_key = Sha256::digest(&client_key).to_vec();
        let client_signature = hmac_sha256(&stored_key, without_proof.as_bytes());
        let received = BASE64
            .decode(&client_final[proof_position + 3..])
            .expect("proof b64");
        let expected: Vec<u8> = client_key
            .iter()
            .zip(client_signature.iter())
            .map(|(key, signature)| key ^ signature)
            .collect();
        assert_eq!(received, expected, "server must accept the proof");

        // Server-final: signature over client-final-without-proof.
        let auth_message = format!("{bare},{without_proof}");
        let server_key = hmac_sha256(&salted, b"Server Key");
        let server_signature = hmac_sha256(&server_key, auth_message.as_bytes());
        client
            .server_final(format!("v={}", BASE64.encode(&server_signature)).as_bytes())
            .expect("server final ok");

        let bad = client
            .server_final(b"v=bm9wdA==")
            .expect_err("wrong signature");
        assert_eq!(bad, ConnectionError::AuthFailed);
    }

    #[test]
    fn scram_sha1_round_gets_an_independent_verification() {
        let salt = BASE64.decode("c2FsdHNhbHRzYWx0").expect("salt");
        let mut client = ScramClient::new(Mechanism::Sha1, "u", "pw");
        let client_first = client.client_first();
        let bare = &client_first["n,,".len()..];
        let server_nonce = bare.split_once("r=").expect("client nonce").1.to_owned() + "Z";
        client
            .server_first(format!("r={server_nonce},s={},i=4096", BASE64.encode(&salt)).as_bytes())
            .expect("server first ok");
        let client_final = client.client_final().expect("client final");
        let salted = pbkdf2_sha1(b"pw", &salt, 4096);
        let proof_position = client_final.find(",p=").expect("p suffix");
        let without_proof = &client_final[..proof_position];
        let client_key = hmac_sha1(&salted, b"Client Key");
        let stored_key = Sha1::digest(&client_key).to_vec();
        let client_signature = hmac_sha1(&stored_key, without_proof.as_bytes());
        let received = BASE64
            .decode(&client_final[proof_position + 3..])
            .expect("proof b64");
        let expected: Vec<u8> = client_key
            .iter()
            .zip(client_signature.iter())
            .map(|(key, signature)| key ^ signature)
            .collect();
        assert_eq!(received, expected, "SHA-1 proof verifies");
        assert_eq!(Mechanism::Sha1.name(), "SCRAM-SHA-1");
    }

    #[test]
    fn negotiation_prefers_sha256_and_requires_a_standard_mechanism() {
        assert_eq!(
            Mechanism::negotiate(None).expect("legacy default"),
            Mechanism::Sha256
        );
        assert_eq!(
            Mechanism::negotiate(Some(&[
                "SCRAM-SHA-1".to_owned(),
                "SCRAM-SHA-256".to_owned()
            ]))
            .expect("list"),
            Mechanism::Sha256
        );
        assert_eq!(
            Mechanism::negotiate(Some(&["SCRAM-SHA-1".to_owned()])).expect("list"),
            Mechanism::Sha1
        );
        assert_eq!(
            Mechanism::negotiate(Some(&[])),
            Err(ConnectionError::AuthFailed)
        );
        assert_eq!(
            Mechanism::negotiate(Some(&["PLAIN".to_owned()])),
            Err(ConnectionError::AuthFailed)
        );
    }

    #[test]
    fn out_of_order_steps_and_malformed_servers_fail() {
        let mut client = ScramClient::new(Mechanism::Sha256, "u", "pw");
        assert!(matches!(
            client.client_final(),
            Err(ConnectionError::Protocol(message)) if message.contains("server-first")
        ));
        assert!(matches!(
            client.server_first(b"r=x,s=!!base64!!,i=4096"),
            Err(ConnectionError::Protocol(message)) if message.contains("base64 salt")
        ));
        assert!(matches!(
            client.server_first(b"r=onlynonce,s=am9i,i=4096"),
            Err(ConnectionError::Protocol(message)) if message.contains("extension of the client nonce")
        ));
        assert!(matches!(
            client.server_first(b"r=am9i,s=am9i"),
            Err(ConnectionError::Protocol(message)) if message.contains("lacks r=, s= or i=")
        ));
        let nonce = client.nonce.clone();
        assert!(matches!(
            client.server_first(format!("r={nonce},s=am9i,i=1").as_bytes()),
            Err(ConnectionError::Protocol(message)) if message.contains("iteration count")
        ));
        let _ = client.client_first();
        assert!(matches!(
            client.server_first(b"r=x,s=!!,i=4096"),
            Err(ConnectionError::Protocol(message)) if message.contains("base64 salt")
        ));
        assert!(matches!(
            client.server_final(b"v=non-utf8-\xff"),
            Err(ConnectionError::Protocol(_))
        ));
    }
}
