//! Target URL parsing: `postgres[ql]://[user[:password]@]host[:port][/database]`.
//! Hand-rolled to keep the driver light; percent-encoding is not supported
//! in v0 (documented limitation). TLS policy lives in the resolved settings
//! (`ssl_mode` / `ssl_root_cert`), not in the URL.

use anydb_shared::ConnectionError;

/// TLS policy for the connection (libpq `sslmode` analog at three levels).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SslMode {
    /// Plain TCP, no SSLRequest (default; back-compat with v0).
    #[default]
    Disable,
    /// Try SSLRequest; fall back to plaintext if the server answers `N`.
    Prefer,
    /// SSL is mandatory; a `N` answer is a hard failure. Certificates are
    /// always verified (OS roots or `ssl_root_cert`); no insecure mode.
    Require,
}

impl SslMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "disable" => Some(Self::Disable),
            "prefer" => Some(Self::Prefer),
            "require" => Some(Self::Require),
            _ => None,
        }
    }
}

/// Everything the wire protocol client needs to reach one server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresTarget {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Option<String>,
    pub database: Option<String>,
    pub ssl_mode: SslMode,
    /// Optional PEM file with extra trust anchors; overrides OS roots.
    pub ssl_root_cert: Option<String>,
}

pub const DEFAULT_PORT: u16 = 5432;

impl PostgresTarget {
    fn plain(
        host: String,
        port: u16,
        user: String,
        password: Option<String>,
        database: Option<String>,
    ) -> Self {
        Self {
            host,
            port,
            user,
            password,
            database,
            ssl_mode: SslMode::default(),
            ssl_root_cert: None,
        }
    }
}

pub fn parse_target(
    target: &str,
    fallback_user: Option<&str>,
) -> Result<PostgresTarget, ConnectionError> {
    let rest = target
        .strip_prefix("postgresql://")
        .or_else(|| target.strip_prefix("postgres://"))
        .ok_or_else(|| {
            ConnectionError::Protocol(
                "target must be postgres://[user[:password]@]host[:port][/database]".to_owned(),
            )
        })?;

    let (authority, database) = match rest.split_once('/') {
        Some((authority, database)) => {
            // Query strings after '?' are ignored in v0.
            let database = database.split('?').next().unwrap_or_default();
            (
                authority,
                if database.is_empty() {
                    None
                } else {
                    Some(database.to_owned())
                },
            )
        }
        None => (rest, None),
    };

    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((userinfo, hostport)) => (Some(userinfo), hostport),
        None => (None, authority),
    };

    let (user, password) = match userinfo {
        Some(info) => match info.split_once(':') {
            Some((user, password)) => (Some(user.to_owned()), Some(password.to_owned())),
            None => (Some(info.to_owned()), None),
        },
        None => (None, None),
    };

    let user = user
        .or_else(|| fallback_user.map(str::to_owned))
        .ok_or_else(|| {
            ConnectionError::Protocol("missing user in target URL or properties".to_owned())
        })?;

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

    Ok(PostgresTarget::plain(host, port, user, password, database))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_url_parses_every_component() {
        let target =
            parse_target("postgres://admin:secret@db.local:5433/shop", None).expect("parses");
        assert_eq!(target.host, "db.local");
        assert_eq!(target.port, 5433);
        assert_eq!(target.user, "admin");
        assert_eq!(target.password.as_deref(), Some("secret"));
        assert_eq!(target.database.as_deref(), Some("shop"));
    }

    #[test]
    fn defaults_and_fallback_user_apply() {
        let target = parse_target("postgresql://db.local/shop", Some("svc")).expect("parses");
        assert_eq!(target.port, DEFAULT_PORT);
        assert_eq!(target.user, "svc");
        assert_eq!(target.password, None);
    }

    #[test]
    fn rejects_bad_schemes_and_ports() {
        assert!(parse_target("mysql://h", Some("u")).is_err());
        assert!(parse_target("postgres://h:notaport/db", Some("u")).is_err());
        assert!(parse_target("postgres://h/db", None).is_err());
        assert!(parse_target("postgres://", Some("u")).is_err());
    }

    #[test]
    fn ssl_mode_parsing() {
        assert_eq!(SslMode::parse("disable"), Some(SslMode::Disable));
        assert_eq!(SslMode::parse("prefer"), Some(SslMode::Prefer));
        assert_eq!(SslMode::parse("require"), Some(SslMode::Require));
        assert_eq!(SslMode::parse("bogus"), None);
        assert_eq!(SslMode::default(), SslMode::Disable);
    }
}
