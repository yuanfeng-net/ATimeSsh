#![cfg_attr(windows, windows_subsystem = "windows")]

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use if_addrs::get_if_addrs;
use rand::RngExt;
use rusqlite::{params, Connection, OptionalExtension};
use russh::server::{self, Auth, Msg, Server as RusshServer, Session};
use russh::{client, Channel, ChannelId, Preferred, Pty};
use rust_embed::RustEmbed;
use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::Write,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tokio::{
    net::{lookup_host, TcpListener, TcpSocket, TcpStream},
    sync::oneshot,
    task::JoinHandle,
};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem},
    Icon, TrayIconBuilder,
};
use uuid::Uuid;

const DEFAULT_HOST: &str = "127.0.0.1";

fn log_message(message: impl AsRef<str>) {
    let mut dir = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    dir.push("ATimeSsh");
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("atimesh.log");
    let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    let _ = writeln!(
        file,
        "[{}] {}",
        epoch_seconds(SystemTime::now()),
        message.as_ref()
    );
}

#[derive(RustEmbed)]
#[folder = "../frontend/dist/"]
struct FrontendAssets;

#[derive(Clone)]
struct AppState {
    app_port: u16,
    leases: Arc<Mutex<HashMap<String, SessionLease>>>,
    servers: Arc<Mutex<HashMap<String, ServerConfig>>>,
    db: Arc<Mutex<Connection>>,
    auth_sessions: Arc<Mutex<HashMap<String, SystemTime>>>,
    encryption_key: Arc<Mutex<Option<[u8; 32]>>>,
}

#[derive(Clone, Deserialize)]
struct ServerConfig {
    name: String,
    host: String,
    port: u16,
    username: String,
    password: String,
    host_key: Option<String>,
}

#[derive(Serialize)]
struct ServerSummary {
    id: String,
    name: String,
    host: String,
    port: u16,
    environment: String,
    status: &'static str,
    latency: Option<u16>,
    last_seen: String,
    host_key: Option<String>,
}

#[derive(Serialize)]
struct ServerDetails {
    id: String,
    name: String,
    host: String,
    port: u16,
    username: String,
    environment: String,
    host_key: Option<String>,
}

#[derive(Deserialize)]
struct UpdateServerRequest {
    name: String,
    host: String,
    port: u16,
    username: String,
    #[serde(default)]
    password: String,
}

#[derive(Deserialize)]
struct AuthRequest {
    password: String,
}

#[derive(Serialize)]
struct AuthStatusResponse {
    configured: bool,
    authenticated: bool,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[allow(dead_code)]
struct SessionLease {
    server_id: String,
    token: String,
    port: u16,
    relay_task: JoinHandle<()>,
    expires_at: SystemTime,
    max_expires_at: SystemTime,
}

#[derive(Serialize)]
struct RuntimeResponse {
    app_port: u16,
    host: &'static str,
}

#[derive(Serialize)]
struct NetworkInterfaceSummary {
    index: Option<u32>,
    name: String,
    ip: String,
    is_tunnel: bool,
    selectable: bool,
}

#[derive(Deserialize)]
struct NetworkSettingsRequest {
    interface_index: Option<u32>,
}

#[derive(Serialize)]
struct NetworkSettingsResponse {
    interface_index: Option<u32>,
    mode: &'static str,
}

#[derive(Serialize)]
struct SessionResponse {
    session_id: String,
    server_id: String,
    port: u16,
    token: String,
    connect_command: String,
    connect_uri: String,
    expires_at: u64,
    max_expires_at: u64,
}

#[derive(Serialize)]
struct SessionStatusResponse {
    session_id: String,
    server_id: String,
    port: u16,
    expires_at: u64,
    max_expires_at: u64,
    status: &'static str,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = Arc::new(Mutex::new(init_database()?));
    let app_listener = TcpListener::bind((DEFAULT_HOST, 0)).await?;
    let app_port = app_listener.local_addr()?.port();
    let state = AppState {
        app_port,
        leases: Arc::new(Mutex::new(HashMap::new())),
        servers: Arc::new(Mutex::new(HashMap::new())),
        db,
        auth_sessions: Arc::new(Mutex::new(HashMap::new())),
        encryption_key: Arc::new(Mutex::new(None)),
    };
    let dashboard_url = format!("http://{DEFAULT_HOST}:{app_port}/");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let api_state = state.clone();
    let expiry_leases = state.leases.clone();
    let expiry_db = state.db.clone();

    tokio::spawn(async move {
        expire_sessions(expiry_leases, expiry_db).await;
    });

    tokio::spawn(async move {
        let app = Router::new()
            .route("/api/runtime", get(runtime))
            .route("/api/auth/status", get(auth_status))
            .route("/api/auth/setup", post(auth_setup))
            .route("/api/auth/login", post(auth_login))
            .route("/api/auth/logout", post(auth_logout))
            .route("/api/network/interfaces", get(list_network_interfaces))
            .route(
                "/api/settings/network",
                get(get_network_settings).post(set_network_settings),
            )
            .route(
                "/api/servers/{server_id}/ssh-sessions",
                get(get_session).post(create_session),
            )
            .route("/api/servers", get(list_servers))
            .route(
                "/api/servers/{server_id}",
                get(get_server).post(upsert_server).put(update_server),
            )
            .route("/api/ssh-sessions/{session_id}", post(revoke_session))
            .route("/api/ssh-sessions/{session_id}/renew", post(renew_session))
            .route("/api/ssh-sessions/{session_id}/status", get(session_status))
            .fallback(static_asset)
            .with_state(api_state);
        let result = axum::serve(app_listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
        if let Err(error) = result {
            log_message(format!("ATimeSsh HTTP server stopped: {error}"));
        }
    });

    open_dashboard(&dashboard_url);
    run_tray(dashboard_url, shutdown_tx);
}

async fn runtime(State(state): State<AppState>) -> Json<RuntimeResponse> {
    Json(RuntimeResponse {
        app_port: state.app_port,
        host: DEFAULT_HOST,
    })
}

fn init_database() -> Result<Connection, rusqlite::Error> {
    let mut dir = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    dir.push("ATimeSsh");
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("atimesh.sqlite3");
    let connection = Connection::open(path)?;
    connection.execute_batch("PRAGMA journal_mode = WAL;")?;
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS servers (
           id TEXT PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
           username TEXT NOT NULL, password_ciphertext BLOB NOT NULL, password_nonce BLOB NOT NULL,
           host_key TEXT
         );",
    )?;
    let has_legacy_token = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('ssh_sessions') WHERE name = 'token')",
        [],
        |row| row.get::<_, i64>(0),
    )? == 1;
    if has_legacy_token {
        // Session leases are memory-only and are never restored after restart, so the
        // old plaintext-token table can be safely replaced during schema migration.
        connection.execute_batch("DROP TABLE ssh_sessions;")?;
    }
    let has_host_key = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('servers') WHERE name = 'host_key')",
        [],
        |row| row.get::<_, i64>(0),
    )? == 1;
    if !has_host_key {
        connection.execute_batch("ALTER TABLE servers ADD COLUMN host_key TEXT;")?;
    }
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS app_config (key TEXT PRIMARY KEY, value BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS servers (
           id TEXT PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
           username TEXT NOT NULL, password_ciphertext BLOB NOT NULL, password_nonce BLOB NOT NULL,
           host_key TEXT
         );
         CREATE TABLE IF NOT EXISTS ssh_sessions (
           id TEXT PRIMARY KEY, server_id TEXT NOT NULL, port INTEGER NOT NULL, token_hash BLOB NOT NULL,
           expires_at INTEGER NOT NULL, max_expires_at INTEGER NOT NULL
         );
         DELETE FROM ssh_sessions;",
    )?;
    Ok(connection)
}

fn config_value(db: &Connection, key: &str) -> Result<Option<Vec<u8>>, rusqlite::Error> {
    db.query_row(
        "SELECT value FROM app_config WHERE key = ?1",
        [key],
        |row| row.get(0),
    )
    .optional()
}

fn is_configured(db: &Connection) -> bool {
    config_value(db, "password_hash").ok().flatten().is_some()
}

fn hash_session_token(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    rand::rng().fill(&mut bytes);
    bytes
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0_u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|error| error.to_string())?;
    Ok(key)
}

fn encrypt_secret(key: &[u8; 32], secret: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = random_bytes::<12>();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), secret.as_bytes())
        .map_err(|_| "credential encryption failed".to_string())?;
    Ok((ciphertext, nonce.to_vec()))
}

fn decrypt_secret(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8]) -> Result<String, String> {
    if nonce.len() != 12 {
        return Err("invalid credential nonce".to_string());
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| "credential decryption failed".to_string())?;
    String::from_utf8(plaintext).map_err(|_| "credential is not valid utf-8".to_string())
}

fn new_auth_token() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<32>())
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            (name == "atimesh_session").then(|| value.to_string())
        })
}

fn authenticated(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(token) = cookie_token(headers) else {
        return false;
    };
    let Ok(mut sessions) = state.auth_sessions.lock() else {
        return false;
    };
    let Some(expires_at) = sessions.get(&token).copied() else {
        return false;
    };
    if expires_at <= SystemTime::now() {
        sessions.remove(&token);
        return false;
    }
    true
}

fn auth_error(status: StatusCode, message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: message.to_string(),
        }),
    )
}

fn session_cookie(token: &str) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "atimesh_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800"
    ))
    .expect("valid session cookie")
}

fn load_servers(db: &Connection, key: &[u8; 32]) -> Result<HashMap<String, ServerConfig>, String> {
    let mut statement = db
        .prepare(
            "SELECT id, name, host, port, username, password_ciphertext, password_nonce, host_key FROM servers",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| {
            let id: String = row.get(0)?;
            let config = ServerConfig {
                name: row.get(1)?,
                host: row.get(2)?,
                port: row.get(3)?,
                username: row.get(4)?,
                password: decrypt_secret(
                    key,
                    &row.get::<_, Vec<u8>>(5)?,
                    &row.get::<_, Vec<u8>>(6)?,
                )
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(std::io::Error::other(error)),
                    )
                })?,
                host_key: row.get(7)?,
            };
            Ok((id, config))
        })
        .map_err(|error| error.to_string())?;
    rows.collect::<Result<HashMap<_, _>, _>>()
        .map_err(|error| error.to_string())
}

async fn list_servers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ServerSummary>>, (StatusCode, String)> {
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }
    let servers = state
        .servers
        .lock()
        .map_err(|_| internal_error("server lock poisoned"))?;
    let summaries = servers
        .iter()
        .map(|(id, server)| ServerSummary {
            id: id.clone(),
            name: server.name.clone(),
            host: server.host.clone(),
            port: server.port,
            environment: "STAGING".to_string(),
            status: "healthy",
            latency: None,
            last_seen: "stored locally".to_string(),
            host_key: server.host_key.clone(),
        })
        .collect();
    Ok(Json(summaries))
}

async fn auth_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<AuthStatusResponse> {
    let configured = state
        .db
        .lock()
        .map(|db| is_configured(&db))
        .unwrap_or(false);
    Json(AuthStatusResponse {
        configured,
        authenticated: configured && authenticated(&state, &headers),
    })
}

async fn auth_setup(
    State(state): State<AppState>,
    Json(request): Json<AuthRequest>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    if request.password.chars().count() < 8 {
        return Err(auth_error(
            StatusCode::BAD_REQUEST,
            "password must contain at least 8 characters",
        ));
    }
    let db = state
        .db
        .lock()
        .map_err(|_| auth_error(StatusCode::INTERNAL_SERVER_ERROR, "database lock poisoned"))?;
    if is_configured(&db) {
        return Err(auth_error(
            StatusCode::CONFLICT,
            "security password is already configured",
        ));
    }
    let password_salt = random_bytes::<16>();
    let encryption_salt = random_bytes::<16>();
    let salt_string = SaltString::encode_b64(&password_salt)
        .map_err(|_| auth_error(StatusCode::INTERNAL_SERVER_ERROR, "salt generation failed"))?;
    let password_hash = Argon2::default()
        .hash_password(request.password.as_bytes(), &salt_string)
        .map_err(|_| auth_error(StatusCode::INTERNAL_SERVER_ERROR, "password hashing failed"))?
        .to_string();
    db.execute(
        "INSERT INTO app_config(key, value) VALUES (?1, ?2)",
        params!["password_hash", password_hash.as_bytes()],
    )
    .map_err(|error| auth_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    db.execute(
        "INSERT INTO app_config(key, value) VALUES (?1, ?2)",
        params!["encryption_salt", encryption_salt.to_vec()],
    )
    .map_err(|error| auth_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?;
    let key = derive_key(&request.password, &encryption_salt)
        .map_err(|error| auth_error(StatusCode::INTERNAL_SERVER_ERROR, &error))?;
    *state
        .encryption_key
        .lock()
        .map_err(|_| auth_error(StatusCode::INTERNAL_SERVER_ERROR, "key lock poisoned"))? =
        Some(key);
    let token = new_auth_token();
    state
        .auth_sessions
        .lock()
        .map_err(|_| auth_error(StatusCode::INTERNAL_SERVER_ERROR, "session lock poisoned"))?
        .insert(
            token.clone(),
            SystemTime::now() + Duration::from_secs(8 * 60 * 60),
        );
    let mut response = Json(AuthStatusResponse {
        configured: true,
        authenticated: true,
    })
    .into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, session_cookie(&token));
    Ok(response)
}

async fn auth_login(
    State(state): State<AppState>,
    Json(request): Json<AuthRequest>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let db = state
        .db
        .lock()
        .map_err(|_| auth_error(StatusCode::INTERNAL_SERVER_ERROR, "database lock poisoned"))?;
    let Some(hash_bytes) = config_value(&db, "password_hash")
        .map_err(|error| auth_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?
    else {
        return Err(auth_error(
            StatusCode::PRECONDITION_FAILED,
            "security password is not configured",
        ));
    };
    let hash = String::from_utf8(hash_bytes)
        .map_err(|_| auth_error(StatusCode::INTERNAL_SERVER_ERROR, "invalid password hash"))?;
    let parsed = PasswordHash::new(&hash)
        .map_err(|_| auth_error(StatusCode::INTERNAL_SERVER_ERROR, "invalid password hash"))?;
    if Argon2::default()
        .verify_password(request.password.as_bytes(), &parsed)
        .is_err()
    {
        return Err(auth_error(
            StatusCode::UNAUTHORIZED,
            "invalid security password",
        ));
    }
    let salt = config_value(&db, "encryption_salt")
        .map_err(|error| auth_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()))?
        .ok_or_else(|| {
            auth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "encryption salt is missing",
            )
        })?;
    let key = derive_key(&request.password, &salt)
        .map_err(|error| auth_error(StatusCode::INTERNAL_SERVER_ERROR, &error))?;
    let servers = load_servers(&db, &key)
        .map_err(|error| auth_error(StatusCode::INTERNAL_SERVER_ERROR, &error))?;
    drop(db);
    *state
        .encryption_key
        .lock()
        .map_err(|_| auth_error(StatusCode::INTERNAL_SERVER_ERROR, "key lock poisoned"))? =
        Some(key);
    *state
        .servers
        .lock()
        .map_err(|_| auth_error(StatusCode::INTERNAL_SERVER_ERROR, "server lock poisoned"))? =
        servers;
    let token = new_auth_token();
    state
        .auth_sessions
        .lock()
        .map_err(|_| auth_error(StatusCode::INTERNAL_SERVER_ERROR, "session lock poisoned"))?
        .insert(
            token.clone(),
            SystemTime::now() + Duration::from_secs(8 * 60 * 60),
        );
    let mut response = Json(AuthStatusResponse {
        configured: true,
        authenticated: true,
    })
    .into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, session_cookie(&token));
    Ok(response)
}

async fn auth_logout(State(state): State<AppState>, headers: HeaderMap) -> StatusCode {
    if let Some(token) = cookie_token(&headers) {
        if let Ok(mut sessions) = state.auth_sessions.lock() {
            sessions.remove(&token);
        }
    }
    if let Ok(mut key) = state.encryption_key.lock() {
        *key = None;
    }
    if let Ok(mut servers) = state.servers.lock() {
        servers.clear();
    }
    StatusCode::NO_CONTENT
}

fn network_interface_preference(db: &Connection) -> Option<u32> {
    config_value(db, "network_interface_index")
        .ok()
        .flatten()
        .and_then(|value| String::from_utf8(value).ok())
        .and_then(|value| value.parse::<u32>().ok())
}

fn network_interface_summaries() -> Vec<NetworkInterfaceSummary> {
    let tunnel_markers = [
        "tun",
        "tap",
        "vpn",
        "virtual",
        "wsl",
        "docker",
        "clash",
        "meta",
        "tailscale",
        "zerotier",
        "wireguard",
        "wg",
        "utun",
    ];
    let mut grouped = std::collections::BTreeMap::<(Option<u32>, String), Vec<IpAddr>>::new();
    for interface in get_if_addrs().unwrap_or_default() {
        if interface.is_loopback() || interface.is_link_local() {
            continue;
        }
        let ip = interface.ip();
        grouped
            .entry((interface.index, interface.name))
            .or_default()
            .push(ip);
    }
    grouped
        .into_iter()
        .map(|((index, name), addresses)| {
            let is_tunnel = tunnel_markers
                .iter()
                .any(|marker| name.to_ascii_lowercase().contains(marker));
            let selectable = index.is_some() && !is_tunnel;
            NetworkInterfaceSummary {
                index,
                name,
                ip: addresses
                    .into_iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                is_tunnel,
                selectable,
            }
        })
        .collect()
}

async fn list_network_interfaces(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<NetworkInterfaceSummary>>, (StatusCode, String)> {
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }
    Ok(Json(network_interface_summaries()))
}

async fn get_network_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<NetworkSettingsResponse>, (StatusCode, String)> {
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }
    let interface_index = state
        .db
        .lock()
        .map_err(|_| internal_error("database lock poisoned"))
        .map(|db| network_interface_preference(&db))?;
    Ok(Json(NetworkSettingsResponse {
        interface_index,
        mode: if interface_index.is_some() {
            "manual"
        } else {
            "auto"
        },
    }))
}

async fn set_network_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<NetworkSettingsRequest>,
) -> Result<Json<NetworkSettingsResponse>, (StatusCode, String)> {
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }
    if let Some(index) = request.interface_index {
        let selected = network_interface_summaries()
            .into_iter()
            .any(|interface| interface.index == Some(index) && interface.selectable);
        if !selected {
            return Err((
                StatusCode::BAD_REQUEST,
                "the selected interface is unavailable or not a physical interface".to_string(),
            ));
        }
    }
    let db = state
        .db
        .lock()
        .map_err(|_| internal_error("database lock poisoned"))?;
    if let Some(index) = request.interface_index {
        db.execute(
            "INSERT INTO app_config(key, value) VALUES ('network_interface_index', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [index.to_string().as_bytes()],
        )
        .map_err(internal_error)?;
    } else {
        db.execute(
            "DELETE FROM app_config WHERE key = 'network_interface_index'",
            [],
        )
        .map_err(internal_error)?;
    }
    Ok(Json(NetworkSettingsResponse {
        interface_index: request.interface_index,
        mode: if request.interface_index.is_some() {
            "manual"
        } else {
            "auto"
        },
    }))
}

async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server_id): Path<String>,
) -> Result<Json<SessionResponse>, (StatusCode, String)> {
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }
    let target = state
        .servers
        .lock()
        .map_err(|_| internal_error("server lock poisoned"))?
        .get(&server_id)
        .cloned()
        .ok_or((
            StatusCode::PRECONDITION_FAILED,
            "server credentials are not configured".to_string(),
        ))?;
    if target.host_key.is_none() {
        return Err((
            StatusCode::PRECONDITION_FAILED,
            "host key verification required".to_string(),
        ));
    }
    let preferred_interface = state
        .db
        .lock()
        .map_err(|_| internal_error("database lock poisoned"))
        .map(|db| network_interface_preference(&db))?;
    // A fresh OS-owned listener is retained for the lifetime of this lease. This makes
    // every active server session unique and closes the bind race before SSH relay code runs.
    let listener = TcpListener::bind((DEFAULT_HOST, 0))
        .await
        .map_err(internal_error)?;
    let port = listener.local_addr().map_err(internal_error)?.port();
    let session_id = Uuid::new_v4().to_string();
    let token = Uuid::new_v4().simple().to_string();
    let relay_username = target.username.clone();
    let expires_at = SystemTime::now() + Duration::from_secs(10 * 60);
    let max_expires_at = SystemTime::now() + Duration::from_secs(60 * 60);
    let relay_task = spawn_relay(listener, token.clone(), target, preferred_interface);
    let session = SessionLease {
        server_id: server_id.clone(),
        token: token.clone(),
        port,
        relay_task,
        expires_at,
        max_expires_at,
    };

    let mut leases = state
        .leases
        .lock()
        .map_err(|_| internal_error("lease lock poisoned"))?;
    // One active temporary link per server: generating again revokes and releases the old port.
    let old_session = leases
        .iter()
        .find(|(_, lease)| lease.server_id == server_id)
        .map(|(id, _)| id.clone());
    if let Some(old_session) = old_session {
        if let Some(old_lease) = leases.remove(&old_session) {
            old_lease.relay_task.abort();
        }
    }
    leases.insert(session_id.clone(), session);
    if let Ok(db) = state.db.lock() {
        let _ = db.execute(
            "INSERT INTO ssh_sessions(id, server_id, port, token_hash, expires_at, max_expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![session_id, server_id, port as i64, hash_session_token(&token).to_vec(), epoch_seconds(expires_at) as i64, epoch_seconds(max_expires_at) as i64],
        );
    }

    Ok(Json(SessionResponse {
        session_id,
        server_id,
        port,
        token: token.clone(),
        connect_command: format!(
            "ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no {}@{DEFAULT_HOST} -p {port}",
            relay_username.as_str()
        ),
        connect_uri: format!("ssh://{}:{token}@{DEFAULT_HOST}:{port}", relay_username),
        expires_at: epoch_seconds(expires_at),
        max_expires_at: epoch_seconds(max_expires_at),
    }))
}

async fn get_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server_id): Path<String>,
) -> Result<Json<SessionResponse>, (StatusCode, String)> {
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }

    let mut leases = state
        .leases
        .lock()
        .map_err(|_| internal_error("lease lock poisoned"))?;
    let session_id = leases
        .iter()
        .find(|(_, lease)| lease.server_id == server_id)
        .map(|(id, _)| id.clone())
        .ok_or((StatusCode::NOT_FOUND, "session not found".to_string()))?;

    if leases
        .get(&session_id)
        .map(|lease| lease.expires_at <= SystemTime::now())
        .unwrap_or(true)
    {
        if let Some(lease) = leases.remove(&session_id) {
            lease.relay_task.abort();
        }
        if let Ok(db) = state.db.lock() {
            let _ = db.execute("DELETE FROM ssh_sessions WHERE id = ?1", [&session_id]);
        }
        return Err((StatusCode::NOT_FOUND, "session not found".to_string()));
    }

    let lease = leases
        .get(&session_id)
        .ok_or((StatusCode::NOT_FOUND, "session not found".to_string()))?;
    let username = state
        .servers
        .lock()
        .map_err(|_| internal_error("server lock poisoned"))?
        .get(&server_id)
        .map(|server| server.username.clone())
        .ok_or((StatusCode::NOT_FOUND, "server not found".to_string()))?;

    Ok(Json(SessionResponse {
        session_id,
        server_id,
        port: lease.port,
        token: lease.token.clone(),
        connect_command: format!(
            "ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no {}@{DEFAULT_HOST} -p {}",
            username, lease.port
        ),
        connect_uri: format!("ssh://{}:{}@{DEFAULT_HOST}:{}", username, lease.token, lease.port),
        expires_at: epoch_seconds(lease.expires_at),
        max_expires_at: epoch_seconds(lease.max_expires_at),
    }))
}

async fn upsert_server(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server_id): Path<String>,
    Json(server): Json<ServerConfig>,
) -> Result<StatusCode, (StatusCode, String)> {
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }
    if server.host.trim().is_empty()
        || server.username.trim().is_empty()
        || server.password.is_empty()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "host, username and password are required".to_string(),
        ));
    }
    if server.port == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "port must be between 1 and 65535".to_string(),
        ));
    }
    let existing_host_key = state
        .servers
        .lock()
        .map_err(|_| internal_error("server lock poisoned"))?
        .get(&server_id)
        .and_then(|existing| existing.host_key.clone());
    let preferred_interface = state
        .db
        .lock()
        .map_err(|_| internal_error("database lock poisoned"))
        .map(|db| network_interface_preference(&db))?;
    let scanned_host_key = scan_target_host_key(&server, preferred_interface)
        .await
        .map_err(|error| {
            (
                StatusCode::BAD_GATEWAY,
                format!("unable to verify target host key: {error}"),
            )
        })?;
    if let Some(existing_host_key) = existing_host_key {
        if existing_host_key != scanned_host_key {
            return Err((
                StatusCode::CONFLICT,
                "target host key changed; server was not saved".to_string(),
            ));
        }
    }
    let mut server = server;
    server.host_key = Some(scanned_host_key);
    let key = state
        .encryption_key
        .lock()
        .map_err(|_| internal_error("key lock poisoned"))?
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ))?;
    let (ciphertext, nonce) = encrypt_secret(&key, &server.password).map_err(internal_error)?;
    state.db.lock().map_err(|_| internal_error("database lock poisoned"))?.execute(
        "INSERT INTO servers(id, name, host, port, username, password_ciphertext, password_nonce, host_key) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(id) DO UPDATE SET name=excluded.name, host=excluded.host, port=excluded.port, username=excluded.username, password_ciphertext=excluded.password_ciphertext, password_nonce=excluded.password_nonce, host_key=COALESCE(excluded.host_key, servers.host_key)",
        params![server_id, server.name, server.host, server.port as i64, server.username, ciphertext, nonce, server.host_key],
    ).map_err(internal_error)?;
    state
        .servers
        .lock()
        .map_err(|_| internal_error("server lock poisoned"))?
        .insert(server_id, server);
    Ok(StatusCode::NO_CONTENT)
}

async fn get_server(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server_id): Path<String>,
) -> Result<Json<ServerDetails>, (StatusCode, String)> {
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }
    let server = state
        .servers
        .lock()
        .map_err(|_| internal_error("server lock poisoned"))?
        .get(&server_id)
        .cloned()
        .ok_or((StatusCode::NOT_FOUND, "server not found".to_string()))?;
    Ok(Json(ServerDetails {
        id: server_id,
        name: server.name,
        host: server.host,
        port: server.port,
        username: server.username,
        environment: "STAGING".to_string(),
        host_key: server.host_key,
    }))
}

async fn update_server(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(server_id): Path<String>,
    Json(request): Json<UpdateServerRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }
    if request.name.trim().is_empty()
        || request.host.trim().is_empty()
        || request.username.trim().is_empty()
        || request.port == 0
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "name, host, username and valid port are required".to_string(),
        ));
    }
    let old = state
        .servers
        .lock()
        .map_err(|_| internal_error("server lock poisoned"))?
        .get(&server_id)
        .cloned()
        .ok_or((StatusCode::NOT_FOUND, "server not found".to_string()))?;
    let password = if request.password.is_empty() {
        old.password.clone()
    } else {
        request.password.clone()
    };
    let candidate = ServerConfig {
        name: request.name.trim().to_string(),
        host: request.host.trim().to_string(),
        port: request.port,
        username: request.username.trim().to_string(),
        password,
        host_key: old.host_key.clone(),
    };
    let preferred_interface = state
        .db
        .lock()
        .map_err(|_| internal_error("database lock poisoned"))
        .map(|db| network_interface_preference(&db))?;
    let scanned = scan_target_host_key(&candidate, preferred_interface)
        .await
        .map_err(|error| {
            (
                StatusCode::BAD_GATEWAY,
                format!("unable to verify target host key: {error}"),
            )
        })?;
    let key = state
        .encryption_key
        .lock()
        .map_err(|_| internal_error("key lock poisoned"))?
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ))?;
    let (ciphertext, nonce) = encrypt_secret(&key, &candidate.password).map_err(internal_error)?;
    state.db.lock().map_err(|_| internal_error("database lock poisoned"))?.execute(
        "UPDATE servers SET name=?1, host=?2, port=?3, username=?4, password_ciphertext=?5, password_nonce=?6, host_key=?7 WHERE id=?8",
        params![candidate.name, candidate.host, candidate.port as i64, candidate.username, ciphertext, nonce, scanned, server_id],
    ).map_err(internal_error)?;
    state
        .servers
        .lock()
        .map_err(|_| internal_error("server lock poisoned"))?
        .insert(
            server_id,
            ServerConfig {
                host_key: Some(scanned),
                ..candidate
            },
        );
    Ok(StatusCode::NO_CONTENT)
}

async fn renew_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Result<Json<SessionStatusResponse>, (StatusCode, String)> {
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }
    let mut leases = state
        .leases
        .lock()
        .map_err(|_| internal_error("lease lock poisoned"))?;
    let lease = leases
        .get_mut(&session_id)
        .ok_or((StatusCode::NOT_FOUND, "session not found".to_string()))?;
    if lease.expires_at <= SystemTime::now() {
        return Err((StatusCode::GONE, "session expired".to_string()));
    }
    lease.expires_at = std::cmp::min(
        lease.expires_at + Duration::from_secs(10 * 60),
        lease.max_expires_at,
    );
    if let Ok(db) = state.db.lock() {
        let _ = db.execute(
            "UPDATE ssh_sessions SET expires_at = ?1 WHERE id = ?2",
            params![epoch_seconds(lease.expires_at) as i64, session_id],
        );
    }
    Ok(Json(session_status_payload(&session_id, lease)))
}

async fn session_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Result<Json<SessionStatusResponse>, (StatusCode, String)> {
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }
    let mut leases = state
        .leases
        .lock()
        .map_err(|_| internal_error("lease lock poisoned"))?;
    let expired = leases
        .get(&session_id)
        .map(|lease| lease.expires_at <= SystemTime::now())
        .unwrap_or(false);
    if expired {
        if let Some(lease) = leases.remove(&session_id) {
            lease.relay_task.abort();
        }
        return Err((StatusCode::GONE, "session expired".to_string()));
    }
    let lease = leases
        .get(&session_id)
        .ok_or((StatusCode::NOT_FOUND, "session not found".to_string()))?;
    Ok(Json(session_status_payload(&session_id, lease)))
}

fn session_status_payload(session_id: &str, lease: &SessionLease) -> SessionStatusResponse {
    SessionStatusResponse {
        session_id: session_id.to_string(),
        server_id: lease.server_id.clone(),
        port: lease.port,
        expires_at: epoch_seconds(lease.expires_at),
        max_expires_at: epoch_seconds(lease.max_expires_at),
        status: "active",
    }
}

fn epoch_seconds(value: SystemTime) -> u64 {
    value
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn expire_sessions(
    leases: Arc<Mutex<HashMap<String, SessionLease>>>,
    db: Arc<Mutex<Connection>>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        let expired = {
            let mut guard = match leases.lock() {
                Ok(guard) => guard,
                Err(_) => continue,
            };
            let ids: Vec<String> = guard
                .iter()
                .filter(|(_, lease)| lease.expires_at <= SystemTime::now())
                .map(|(id, _)| id.clone())
                .collect();
            let mut tasks = Vec::new();
            for id in ids {
                if let Some(lease) = guard.remove(&id) {
                    tasks.push(lease.relay_task);
                    if let Ok(connection) = db.lock() {
                        let _ = connection.execute("DELETE FROM ssh_sessions WHERE id = ?1", [&id]);
                    }
                }
            }
            tasks
        };
        for relay_task in expired {
            relay_task.abort();
        }
    }
}

async fn static_asset(uri: axum::http::Uri) -> Response {
    let requested = uri.path().trim_start_matches('/');
    let path = if requested.is_empty() {
        "index.html"
    } else {
        requested
    };
    if let Some(content) = FrontendAssets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return (
            [(axum::http::header::CONTENT_TYPE, mime.as_ref())],
            content.data,
        )
            .into_response();
    }
    FrontendAssets::get("index.html")
        .map(|content| {
            (
                [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                content.data,
            )
                .into_response()
        })
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response())
}

async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    if !authenticated(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "authentication required".to_string(),
        ));
    }
    let mut leases = state
        .leases
        .lock()
        .map_err(|_| internal_error("lease lock poisoned"))?;
    if let Some(lease) = leases.remove(&session_id) {
        lease.relay_task.abort();
        if let Ok(db) = state.db.lock() {
            let _ = db.execute("DELETE FROM ssh_sessions WHERE id = ?1", [session_id]);
        }
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, "session not found".to_string()))
    }
}

fn internal_error(error: impl ToString) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

fn open_dashboard(url: &str) {
    if let Err(error) = webbrowser::open(url) {
        log_message(format!("Unable to open ATimeSsh dashboard: {error}"));
    }
}

fn run_tray(dashboard_url: String, shutdown_tx: oneshot::Sender<()>) -> ! {
    let event_loop = EventLoopBuilder::new().build();
    let menu = Menu::new();
    let open_item = MenuItem::new("打开管理后台 / Open dashboard", true, None);
    let exit_item = MenuItem::new("退出 / Exit", true, None);
    menu.append(&open_item).expect("unable to build tray menu");
    menu.append(&exit_item).expect("unable to build tray menu");
    let icon = Icon::from_rgba(tray_icon_rgba(), 32, 32).expect("unable to build tray icon");
    let _tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("ATimeSsh")
        .with_icon(icon)
        .build()
        .expect("unable to create system tray");
    let menu_receiver = MenuEvent::receiver();
    let shutdown_tx = Arc::new(Mutex::new(Some(shutdown_tx)));
    let open_id = open_item.id().clone();
    let exit_id = exit_item.id().clone();

    event_loop.run(move |_event, _window_target, control_flow| {
        *control_flow = ControlFlow::Wait;
        while let Ok(event) = menu_receiver.try_recv() {
            if event.id == open_id {
                open_dashboard(&dashboard_url);
            } else if event.id == exit_id {
                if let Ok(mut sender) = shutdown_tx.lock() {
                    if let Some(sender) = sender.take() {
                        let _ = sender.send(());
                    }
                }
                *control_flow = ControlFlow::Exit;
            }
        }
    });
}

fn tray_icon_rgba() -> Vec<u8> {
    let mut pixels = Vec::with_capacity(32 * 32 * 4);
    for y in 0i32..32 {
        for x in 0i32..32 {
            let edge = x < 3 || y < 3 || x >= 29 || y >= 29;
            let inside_a = (7..25).contains(&x)
                && (7..25).contains(&y)
                && (x - 16).abs() + (y - 16).abs() < 12;
            if edge {
                pixels.extend_from_slice(&[17, 22, 27, 0]);
            } else if inside_a {
                pixels.extend_from_slice(&[240, 188, 92, 255]);
            } else {
                pixels.extend_from_slice(&[17, 22, 27, 255]);
            }
        }
    }
    pixels
}

// Reserved for the relay accept loop. The listener is intentionally held in SessionLease
// until the SSH relay layer takes ownership of it.
#[allow(dead_code)]
async fn accept_relay(listener: TcpListener) -> Result<(), std::io::Error> {
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(proxy_placeholder(stream));
    }
}

async fn proxy_placeholder(mut stream: TcpStream) {
    use tokio::io::AsyncWriteExt;
    let _ = stream
        .write_all(b"ATimeSsh relay is waiting for SSH authentication.\r\n")
        .await;
}

#[derive(Clone)]
struct RelayServer {
    token: String,
    target: ServerConfig,
    preferred_interface: Option<u32>,
}

impl RusshServer for RelayServer {
    type Handler = RelayHandler;

    fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        RelayHandler {
            token: self.token.clone(),
            target: self.target.clone(),
            preferred_interface: self.preferred_interface,
        }
    }
}

struct RelayHandler {
    token: String,
    target: ServerConfig,
    preferred_interface: Option<u32>,
}

#[derive(Clone, Copy)]
struct LocalSource {
    ip: IpAddr,
    interface_index: Option<u32>,
}

#[derive(Clone)]
struct TargetClient {
    expected_fingerprint: Option<String>,
    observed_fingerprint: Option<Arc<Mutex<Option<String>>>>,
}

impl client::Handler for TargetClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let fingerprint = server_public_key
            .public_key()
            .fingerprint(russh::keys::HashAlg::Sha256)
            .to_string();
        if let Some(observed) = &self.observed_fingerprint {
            if let Ok(mut value) = observed.lock() {
                *value = Some(fingerprint.clone());
            }
        }
        Ok(self
            .expected_fingerprint
            .as_deref()
            .map(|expected| expected == fingerprint)
            .unwrap_or(true))
    }
}

impl server::Handler for RelayHandler {
    type Error = russh::Error;

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if user == self.target.username && password == self.token {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut target_session = connect_target(
            &self.target,
            TargetClient {
                expected_fingerprint: self.target.host_key.clone(),
                observed_fingerprint: None,
            },
            self.preferred_interface,
        )
        .await
        .map_err(|error| {
            log_message(format!("ATimeSsh target connection failed: {error}"));
            russh::Error::Disconnect
        })?;
        let auth = target_session
            .authenticate_password(&self.target.username, &self.target.password)
            .await
            .map_err(|_| russh::Error::Disconnect)?;
        if !auth.success() {
            return Err(russh::Error::Disconnect);
        }
        let target_channel = target_session
            .channel_open_session()
            .await
            .map_err(|_| russh::Error::Disconnect)?;
        target_channel
            .request_pty(false, "xterm", 120, 40, 0, 0, &[])
            .await
            .map_err(|_| russh::Error::Disconnect)?;
        target_channel
            .request_shell(true)
            .await
            .map_err(|_| russh::Error::Disconnect)?;
        reply.accept().await;
        let mut relay_stream = channel.into_stream();
        let mut target_stream = target_channel.into_stream();
        tokio::spawn(async move {
            let _ = tokio::io::copy_bidirectional(&mut relay_stream, &mut target_stream).await;
            let _ = target_session
                .disconnect(russh::Disconnect::ByApplication, "relay closed", "en")
                .await;
        });
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = (channel, data, session);
        Ok(())
    }
}

fn local_source_candidates(preferred_interface: Option<u32>) -> Vec<LocalSource> {
    let tunnel_markers = [
        "tun",
        "tap",
        "vpn",
        "virtual",
        "wsl",
        "docker",
        "clash",
        "meta",
        "tailscale",
        "zerotier",
        "wireguard",
        "wg",
        "utun",
    ];
    let mut candidates = get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|interface| {
            let ip = interface.ip();
            if interface.is_loopback() || interface.is_link_local() {
                return None;
            }
            let name = interface.name.to_ascii_lowercase();
            let is_tunnel = tunnel_markers.iter().any(|marker| name.contains(marker));
            if let Some(preferred_index) = preferred_interface {
                if interface.index != Some(preferred_index) {
                    return None;
                }
            }
            Some((
                is_tunnel,
                LocalSource {
                    ip,
                    interface_index: interface.index,
                },
            ))
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(is_tunnel, source)| (*is_tunnel, source.ip.to_string()));
    candidates.dedup_by(|left, right| left.1.ip == right.1.ip);
    candidates.into_iter().map(|(_, source)| source).collect()
}

#[cfg(windows)]
fn force_socket_interface(
    socket: &TcpSocket,
    source: LocalSource,
    remote: IpAddr,
) -> Result<(), String> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF, SOCKET_ERROR,
    };

    let Some(interface_index) = source.interface_index else {
        return Ok(());
    };
    let option = interface_index.to_be_bytes();
    let (level, name) = match remote {
        IpAddr::V4(_) => (IPPROTO_IP, IP_UNICAST_IF),
        IpAddr::V6(_) => (IPPROTO_IPV6, IPV6_UNICAST_IF),
    };
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            level,
            name,
            option.as_ptr(),
            option.len() as i32,
        )
    };
    if result == SOCKET_ERROR {
        return Err(format!(
            "设置物理网卡接口 {} 失败：{}",
            interface_index,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn force_socket_interface(
    _socket: &TcpSocket,
    _source: LocalSource,
    _remote: IpAddr,
) -> Result<(), String> {
    Ok(())
}

async fn connect_target(
    target: &ServerConfig,
    handler: TargetClient,
    preferred_interface: Option<u32>,
) -> Result<client::Handle<TargetClient>, String> {
    let remote_addresses = lookup_host((target.host.as_str(), target.port))
        .await
        .map_err(|error| format!("解析目标地址失败：{error}"))?
        .collect::<Vec<_>>();
    if remote_addresses.is_empty() {
        return Err("目标地址没有可用的 IP".to_string());
    }
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(30)),
        ..Default::default()
    });
    let sources = local_source_candidates(preferred_interface);
    let mut attempts = 0_u32;
    let mut last_error = String::new();
    for remote in &remote_addresses {
        for source in &sources {
            if matches!(
                (source.ip, remote.ip()),
                (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_))
            ) {
                continue;
            }
            attempts += 1;
            let socket = match source.ip {
                IpAddr::V4(_) => TcpSocket::new_v4(),
                IpAddr::V6(_) => TcpSocket::new_v6(),
            }
            .map_err(|error| format!("创建本地连接失败：{error}"))?;
            socket
                .bind(SocketAddr::new(source.ip, 0))
                .map_err(|error| format!("绑定本地网卡 {} 失败：{error}", source.ip))?;
            if force_socket_interface(&socket, *source, remote.ip()).is_err() {
                continue;
            }
            match tokio::time::timeout(Duration::from_secs(8), socket.connect(*remote)).await {
                Ok(Ok(stream)) => match tokio::time::timeout(
                    Duration::from_secs(8),
                    client::connect_stream(config.clone(), stream, handler.clone()),
                )
                .await
                {
                    Ok(Ok(session)) => return Ok(session),
                    Ok(Err(_)) | Err(_) => {}
                },
                Ok(Err(_)) | Err(_) => {}
            }
        }
        attempts += 1;
        match tokio::time::timeout(Duration::from_secs(8), TcpStream::connect(*remote)).await {
            Ok(Ok(stream)) => match tokio::time::timeout(
                Duration::from_secs(8),
                client::connect_stream(config.clone(), stream, handler.clone()),
            )
            .await
            {
                Ok(Ok(session)) => return Ok(session),
                Ok(Err(error)) => last_error = format!("SSH 握手失败：{error}"),
                Err(_) => last_error = "SSH 握手超时（8 秒）".to_string(),
            },
            Ok(Err(error)) => last_error = format!("默认路由连接失败：{error}"),
            Err(_) => last_error = "默认路由连接超时（8 秒）".to_string(),
        }
    }
    Err(format!(
        "SSH 连接失败：已尝试绕过 TUN 的物理网卡和默认路由（{attempts} 次），最后错误：{last_error}"
    ))
}

async fn scan_target_host_key(
    target: &ServerConfig,
    preferred_interface: Option<u32>,
) -> Result<String, String> {
    let observed = Arc::new(Mutex::new(None));
    let mut session = connect_target(
        target,
        TargetClient {
            expected_fingerprint: None,
            observed_fingerprint: Some(observed.clone()),
        },
        preferred_interface,
    )
    .await?;
    let auth = session
        .authenticate_password(&target.username, &target.password)
        .await
        .map_err(|error| format!("SSH 认证请求失败：{error}"))?;
    if !auth.success() {
        return Err("SSH 用户名或密码验证失败".to_string());
    }
    let _ = session
        .disconnect(
            russh::Disconnect::ByApplication,
            "host key scan complete",
            "en",
        )
        .await;
    observed
        .lock()
        .ok()
        .and_then(|value| value.clone())
        .ok_or_else(|| "SSH 握手未返回主机指纹".to_string())
}

fn spawn_relay(
    listener: TcpListener,
    token: String,
    target: ServerConfig,
    preferred_interface: Option<u32>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let config = russh::server::Config {
            auth_rejection_time: std::time::Duration::from_millis(250),
            auth_rejection_time_initial: Some(std::time::Duration::from_millis(0)),
            inactivity_timeout: Some(std::time::Duration::from_secs(15 * 60)),
            keys: vec![russh::keys::PrivateKey::random(
                &mut rand::rng(),
                russh::keys::Algorithm::Ed25519,
            )
            .expect("unable to create relay host key")],
            preferred: Preferred::default(),
            ..Default::default()
        };
        let config = Arc::new(config);
        let mut server = RelayServer {
            token,
            target,
            preferred_interface,
        };
        let running = server.run_on_socket(config, &listener);
        if let Err(error) = running.await {
            log_message(format!("ATimeSsh relay stopped: {error}"));
        }
    })
}
