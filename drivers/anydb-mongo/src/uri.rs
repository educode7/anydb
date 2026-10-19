//! Target parsing: `mongodb://[user[:password]@]host[:port][/authdb]`.
//! Hand-rolled like the postgres driver's `url.rs` to keep the driver
//! light. Percent-encoding (RFC 3986) is decoded strictly for the
//! URL-derived credential segments only (user, password and auth
//! database): every `%` must be followed by two hex digits and the
//! result must be valid UTF-8; error messages name the context but
//! never the decoded value. Query options (`?tls=...`) are ignored on
//! purpose: TLS comes from the `ssl_mode` / `ssl_root_cert` resolved
//! properties, not the connection string. `mongodb+srv://` and
//! multi-host seeds are explicit `Protocol` errors, never silently
//! narrowed.

use std::borrow::Cow;

use anydb_shared::ConnectionError;

/// Default mongo port (server default since forever).
pub const DEFAULT_PORT: u16 = 27017;

/// Default authentication database when the URL carries no `/authdb`
/// segment (mongo `authSource` default is `admin`).
pub const DEFAULT_AUTH_DB: &str = "admin";

/// TLS policy for the connection. Only two levels: mongo has no wire
/// negotiation probe like the postgres `SSLRequest`/`S|N` dance, so a
/// `prefer` fallback would mean sending a `ClientHello` that a
/// plaintext mongod parses as a wire message with a huge length and
/// deadlocks against. The mongo ecosystem treats TLS as on/off for the
/// same reason; this surface follows that instead of the postgres
/// three-level shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SslMode {
    /// Plain TCP (default; back-compat with the pre-TLS verticals).
    #[default]
    Disable,
    /// TLS is mandatory from the first byte. Certificates are always
    /// verified (OS roots or `ssl_root_cert`); no insecure mode.
    Require,
}

impl SslMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "disable" => Some(Self::Disable),
            "require" => Some(Self::Require),
            _ => None,
        }
    }
}

/// Everything the wire layer needs to reach and authenticate against
/// one mongod / mongos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MongoTarget {
    pub host: String,
    pub port: u16,
    /// `None` means anonymous access: the connect pipeline skips SCRAM.
    pub user: Option<String>,
    pub password: Option<String>,
    /// Database the SCRAM credentials live in (`authSource`).
    pub auth_db: String,
    pub ssl_mode: SslMode,
    /// Optional PEM file with extra trust anchors; overrides OS roots.
    pub ssl_root_cert: Option<String>,
}

pub fn percent_decode<'a>(value: &'a str, context: &str) -> Result<Cow<'a, str>, ConnectionError> {
    if !value.contains('%') {
        return Ok(Cow::Borrowed(value));
    }
    let bytes = value.as_bytes();
    let mut decoded: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            decoded.push(bytes[i]);
            i += 1;
            continue;
        }
        let high = hex_digit(bytes.get(i + 1).copied());
        let low = hex_digit(bytes.get(i + 2).copied());
        let (Some(high), Some(low)) = (high, low) else {
            return Err(ConnectionError::Protocol(format!(
                "invalid percent-encoding in the URL {context}"
            )));
        };
        decoded.push((high << 4) | low);
        i += 3;
    }
    String::from_utf8(decoded)
        .map(Cow::Owned)
        .map_err(|_| ConnectionError::Protocol(format!("invalid UTF-8 in the URL {context}")))
}

fn hex_digit(byte: Option<u8>) -> Option<u8> {
    match byte? {
        digit @ b'0'..=b'9' => Some(digit - b'0'),
        letter @ b'a'..=b'f' => Some(letter - b'a' + 10),
        letter @ b'A'..=b'F' => Some(letter - b'A' + 10),
        _ => None,
    }
}

pub fn parse_target(
    url: &str,
    fallback_user: Option<&str>,
) -> Result<MongoTarget, ConnectionError> {
    if url.starts_with("mongodb+srv://") {
        return Err(ConnectionError::Protocol(
            "mongodb+srv:// targets are not supported".to_owned(),
        ));
    }
    let rest = url.strip_prefix("mongodb://").ok_or_else(|| {
        ConnectionError::Protocol(
            "target must be mongodb://[user[:password]@]host[:port][/authdb]".to_owned(),
        )
    })?;

    // Strip the query string: options are ignored in this vertical.
    let rest = rest.split('?').next().unwrap_or_default();

    let (authority, auth_db) = match rest.split_once('/') {
        Some((authority, auth_db)) => (authority, Some(auth_db)),
        None => (rest, None),
    };

    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((userinfo, hostport)) => (Some(userinfo), hostport),
        None => (None, authority),
    };

    let (user, password) = match userinfo {
        Some(info) => match info.split_once(':') {
            Some((user, password)) => (
                Some(percent_decode(user, "user")?.into_owned()),
                Some(percent_decode(password, "password")?.into_owned()),
            ),
            None => (Some(percent_decode(info, "user")?.into_owned()), None),
        },
        None => (None, None),
    };

    let user = user.or_else(|| fallback_user.map(str::to_owned));

    let auth_db = auth_db
        .map(|name| percent_decode(name, "auth database").map(|decoded| decoded.into_owned()))
        .transpose()?;
    let auth_db = match auth_db {
        Some(db) if !db.is_empty() => db,
        _ => DEFAULT_AUTH_DB.to_owned(),
    };

    let (host, port) = match hostport.rsplit_once(':') {
        Some((host, port)) => {
            let port = port.parse::<u16>().map_err(|_| {
                ConnectionError::Protocol(format!("invalid port in target: {hostport}"))
            })?;
            (host.to_owned(), port)
        }
        None => (hostport.to_owned(), DEFAULT_PORT),
    };

    if host.is_empty() {
        return Err(ConnectionError::Protocol(
            "missing host in target".to_owned(),
        ));
    }
    if host.contains(',') {
        return Err(ConnectionError::Protocol(
            "multi-host targets are not supported".to_owned(),
        ));
    }

    Ok(MongoTarget {
        host,
        port,
        user,
        password,
        auth_db,
        ssl_mode: SslMode::default(),
        ssl_root_cert: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_url_parses_every_component() {
        let target =
            parse_target("mongodb://adm:s3cret@db.local:27018/shop", None).expect("parses");
        assert_eq!(target.host, "db.local");
        assert_eq!(target.port, 27018);
        assert_eq!(target.user.as_deref(), Some("adm"));
        assert_eq!(target.password.as_deref(), Some("s3cret"));
        assert_eq!(target.auth_db, "shop");
    }

    #[test]
    fn defaults_apply_without_user_database_or_port() {
        let target = parse_target("mongodb://db.local", None).expect("parses");
        assert_eq!(target.host, "db.local");
        assert_eq!(target.port, DEFAULT_PORT);
        assert_eq!(target.user, None);
        assert_eq!(target.password, None);
        assert_eq!(target.auth_db, DEFAULT_AUTH_DB);
        assert_eq!(target.ssl_mode, SslMode::Disable);
        assert_eq!(target.ssl_root_cert, None);
    }

    #[test]
    fn ssl_mode_parser_is_two_valued() {
        assert_eq!(SslMode::parse("disable"), Some(SslMode::Disable));
        assert_eq!(SslMode::parse("require"), Some(SslMode::Require));
        // No mongo negotiation exists, so the postgres `prefer` level is
        // not a mode here (documented in the enum).
        assert_eq!(SslMode::parse("prefer"), None);
        assert_eq!(SslMode::parse("bogus"), None);
        assert_eq!(SslMode::default(), SslMode::Disable);
    }

    #[test]
    fn fallback_user_and_query_strings_apply() {
        let target = parse_target("mongodb://db.local:1/shop?tls=true&app=anydb", Some("svc"))
            .expect("parses");
        assert_eq!(target.user.as_deref(), Some("svc"));
        assert_eq!(target.auth_db, "shop");
    }

    #[test]
    fn percent_decoding_is_strict_and_single_pass() {
        let target =
            parse_target("mongodb://u%40co:m%25p%2Fss@db.local/shop", None).expect("parses");
        assert_eq!(target.user.as_deref(), Some("u@co"));
        assert_eq!(target.password.as_deref(), Some("m%p/ss"));

        assert!(matches!(
            parse_target("mongodb://u%2x@db.local/shop", None),
            Err(ConnectionError::Protocol(message)) if message.contains("percent-encoding in the URL user")
        ));
        // A literal `%` in a secret is never expanded twice.
        let target = parse_target("mongodb://u:m%25@db.local/shop", None).expect("parses");
        assert_eq!(target.password.as_deref(), Some("m%"));
    }

    #[test]
    fn srv_and_multi_host_and_bad_urls_are_rejected() {
        assert!(parse_target("mongodb+srv://db.local/shop", None).is_err());
        assert!(parse_target("mongodb://a.local,b.local/shop", None).is_err());
        assert!(parse_target("mongo://db.local/shop", None).is_err());
        assert!(parse_target("mongodb://db.local:notaport/shop", None).is_err());
        assert!(parse_target("mongodb://:1/shop", None).is_err());
        assert!(parse_target("", None).is_err());
    }
}
