//! Target URL parsing: `postgres[ql]://[user[:password]@]host[:port][/database]`.
//! Hand-rolled to keep the driver light; percent-encoding is not supported
//! in v0 (documented limitation).

use anydb_shared::ConnectionError;

/// Everything the wire protocol client needs to reach one server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresTarget {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Option<String>,
    pub database: Option<String>,
}

pub const DEFAULT_PORT: u16 = 5432;

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

    Ok(PostgresTarget {
        host,
        port,
        user,
        password,
        database,
    })
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
}
