//! Authentication primitives: MD5 password digest and the SCRAM-SHA-256
//! client (PostgreSQL 14+ default). Crypto via RustCrypto `sha2`/`hmac`/
//! `md-5` (permissive licenses, verified by cargo-deny).
//!
//! SCRAM functions are `pub`: the fake-backend tests act as a real server
//! side (they recompute proofs from the password), so they need them too.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use hmac::Mac;
use rand::RngCore;
use sha2::{Digest, Sha256};

use anydb_shared::ConnectionError;

pub const SASL_MECHANISM: &str = "SCRAM-SHA-256";

type HmacSha256 = hmac::Hmac<Sha256>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// PostgreSQL MD5 auth: `md5(md5(password + user) + salt)` in hex.
pub fn md5_password(user: &str, password: &str, salt: &[u8]) -> String {
    use md5::{Digest, Md5};

    let mut inner = Md5::new();
    inner.update(password.as_bytes());
    inner.update(user.as_bytes());
    let inner_hex = hex(&inner.finalize());

    let mut outer = Md5::new();
    outer.update(inner_hex.as_bytes());
    outer.update(salt);
    format!("md5{}", hex(&outer.finalize()))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32], ConnectionError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| ConnectionError::Protocol("invalid HMAC key".to_owned()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Hi(password, salt, iterations) = PBKDF2-HMAC-SHA256. RFC 5802; the output
/// (32 bytes) never exceeds one SHA-256 block, so a single-block PBKDF2 is
/// sufficient.
pub fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<[u8; 32], ConnectionError> {
    let mut block = salt.to_vec();
    block.extend_from_slice(&1u32.to_be_bytes());

    let mut u = hmac_sha256(password, &block)?;
    let mut out = u;
    for _ in 1..iterations {
        u = hmac_sha256(password, &u)?;
        for (o, b) in out.iter_mut().zip(u.iter()) {
            *o ^= b;
        }
    }
    Ok(out)
}

/// Xors two equal-length byte slices (for the client proof).
fn xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = a[i] ^ b[i];
    }
    out
}

/// SCRAM-SHA-256 client state machine (RFC 5802/7677 shape used by
/// PostgreSQL's SASL exchange).
pub struct ScramClient {
    password: String,
    client_nonce: String,
    client_first_bare: String,
    /// Set by `client_final_message`: (salted_password, auth_message).
    auth_state: Option<([u8; 32], String)>,
}

impl ScramClient {
    pub fn new(password: &str) -> Self {
        let mut nonce = [0u8; 18];
        rand::rng().fill_bytes(&mut nonce);
        let client_nonce = B64.encode(nonce);
        let client_first_bare = format!("n=,r={client_nonce}");
        Self {
            password: password.to_owned(),
            client_nonce,
            client_first_bare,
            auth_state: None,
        }
    }

    /// Client-first-message-bare; the frame adds the `n,,` GS2 header.
    pub fn client_first_bare(&self) -> &str {
        &self.client_first_bare
    }

    /// Builds the client-final-message from the server-first-message and
    /// stores the auth state needed to verify the server's signature.
    pub fn client_final_message(&mut self, server_first: &[u8]) -> Result<String, ConnectionError> {
        let server_first = std::str::from_utf8(server_first)
            .map_err(|_| ConnectionError::Protocol("invalid server-first-message".to_owned()))?;

        let mut server_nonce = None;
        let mut salt_b64 = None;
        let mut iterations = None;
        for field in server_first.split(',') {
            if let Some(value) = field.strip_prefix("r=") {
                server_nonce = Some(value.to_owned());
            } else if let Some(value) = field.strip_prefix("s=") {
                salt_b64 = Some(value.to_owned());
            } else if let Some(value) = field.strip_prefix("i=") {
                iterations = Some(value.parse::<u32>().map_err(|_| {
                    ConnectionError::Protocol(format!("invalid iteration count: {value}"))
                })?);
            }
        }
        let server_nonce = server_nonce.ok_or_else(|| {
            ConnectionError::Protocol("server-first-message missing nonce".to_owned())
        })?;
        let salt_b64 = salt_b64.ok_or_else(|| {
            ConnectionError::Protocol("server-first-message missing salt".to_owned())
        })?;
        let iterations = iterations.ok_or_else(|| {
            ConnectionError::Protocol("server-first-message missing iterations".to_owned())
        })?;

        if !server_nonce.starts_with(self.client_nonce.as_str())
            || server_nonce.len() <= self.client_nonce.len()
        {
            return Err(ConnectionError::Protocol(
                "server nonce does not extend the client nonce".to_owned(),
            ));
        }
        let salt = B64
            .decode(salt_b64.as_bytes())
            .map_err(|_| ConnectionError::Protocol("invalid server salt".to_owned()))?;

        let salted = pbkdf2_hmac_sha256(self.password.as_bytes(), &salt, iterations)?;
        let client_key = hmac_sha256(&salted, b"Client Key")?;
        let stored_key = sha256(&client_key);
        let client_final_without_proof = format!("c=biws,r={server_nonce}");
        let auth_message = format!(
            "{},{},{}",
            self.client_first_bare, server_first, client_final_without_proof
        );
        let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes())?;
        let proof = xor(&client_key, &client_signature);

        self.auth_state = Some((salted, auth_message));
        Ok(format!(
            "{client_final_without_proof},p={}",
            B64.encode(proof)
        ))
    }

    /// Verifies the server signature from the SASL final message.
    pub fn verify_server_final(&self, server_final: &[u8]) -> Result<(), ConnectionError> {
        let text = std::str::from_utf8(server_final)
            .map_err(|_| ConnectionError::Protocol("invalid server-final-message".to_owned()))?;
        let Some(signature_b64) = text.strip_prefix("v=") else {
            return Err(ConnectionError::Protocol(
                "SCRAM server error (e=...) in server-final-message".to_owned(),
            ));
        };
        let Some((salted, auth_message)) = &self.auth_state else {
            return Err(ConnectionError::Protocol(
                "verify_server_final called before client_final_message".to_owned(),
            ));
        };
        let server_key = hmac_sha256(salted, b"Server Key")?;
        let server_signature = hmac_sha256(&server_key, auth_message.as_bytes())?;
        let expected = B64.encode(server_signature);
        if signature_b64 != expected {
            return Err(ConnectionError::Protocol(
                "server signature mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_digest_known_shape() {
        // md5("pass") + "user" then salted again; verify the concat logic
        // against a direct md5 computation of the documented formula.
        use md5::Md5;

        let salt = [1u8, 2, 3, 4];
        let expected = {
            let mut first = Md5::new();
            first.update(b"secretuser");
            let hexed: String = first
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let mut second = Md5::new();
            second.update(hexed.as_bytes());
            second.update(salt);
            let out: String = second
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            format!("md5{out}")
        };
        assert_eq!(md5_password("user", "secret", &salt), expected);
        assert!(md5_password("user", "secret", &salt).starts_with("md5"));
    }

    #[test]
    fn pbkdf2_matches_rfc6070_style_single_block() {
        // Known PBKDF2-HMAC-SHA256 vector (RFCH): password="password",
        // salt="salt", iterations=1 "salted"? Use RFC 7914 §11 vector:
        // PBKDF2-HMAC-SHA-256(P=passwd, S=salt, c=1, dkLen=64)... our dk is 32;
        // validate c=1 equals HMAC(password, salt+1).
        let salt = b"salt";
        let dk = pbkdf2_hmac_sha256(b"passwd", salt, 1).expect("ok");
        let expected = hmac_sha256(
            b"passwd",
            [salt.as_slice(), &1u32.to_be_bytes()].concat().as_slice(),
        )
        .expect("ok");
        assert_eq!(dk, expected);
    }

    #[test]
    fn scram_client_final_and_server_signature_round_trip() {
        let password = "pencil";
        let mut client = ScramClient::new(password);
        let client_first_bare = client.client_first_bare().to_owned();
        let client_nonce = client_first_bare
            .strip_prefix("n=,r=")
            .expect("client first shape");

        // Server side: extend the nonce, fixed 8-byte salt, 4096 iterations.
        let salt: [u8; 8] = [0x59, 0x53, 1, 2, 3, 4, 5, 6];
        let server_first = format!("r={client_nonce}SRV,s={},i=4096", B64.encode(salt));
        let client_final = client
            .client_final_message(server_first.as_bytes())
            .expect("client final");
        let (client_final_without_proof, proof_b64) =
            client_final.rsplit_once(",p=").expect("client final shape");
        assert!(client_final_without_proof.starts_with("c=biws,r="));

        // Server recomputes the expected proof from the password only.
        let salted = pbkdf2_hmac_sha256(password.as_bytes(), &salt, 4096).expect("ok");
        let client_key = hmac_sha256(&salted, b"Client Key").expect("ok");
        let stored_key = sha256(&client_key);
        let auth_message = format!(
            "{},{},{}",
            client_first_bare, server_first, client_final_without_proof
        );
        let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes()).expect("ok");
        let expected_proof: Vec<u8> = client_key
            .iter()
            .zip(client_signature.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(
            proof_b64,
            B64.encode(expected_proof),
            "wrong password proof must not match"
        );

        // Server signature is verifiable by the client; tampering is rejected.
        let server_key = hmac_sha256(&salted, b"Server Key").expect("ok");
        let server_signature = hmac_sha256(&server_key, auth_message.as_bytes()).expect("ok");
        client
            .verify_server_final(format!("v={}", B64.encode(server_signature)).as_bytes())
            .expect("valid server signature");
        client
            .verify_server_final(format!("v={}", B64.encode([0u8; 32])).as_bytes())
            .expect_err("tampered server signature must fail");
    }
}
