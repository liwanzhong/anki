// Copyright: Ankitects Pty Ltd and contributors
// License: GNU AGPL, version 3 or later; http://www.gnu.org/licenses/agpl.html

mod handlers;
mod logging;
mod media_manager;
mod routes;
mod user;

use std::collections::HashMap;
use std::future::Future;
use std::future::IntoFuture;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;

use anki_io::create_dir_all;
use axum::extract::DefaultBodyLimit;
use axum::routing::get;
use axum::Router;
use axum_client_ip::ClientIpSource;
use pbkdf2::password_hash::PasswordHash;
use pbkdf2::password_hash::PasswordHasher;
use pbkdf2::password_hash::PasswordVerifier;
use pbkdf2::password_hash::SaltString;
use pbkdf2::Pbkdf2;
use snafu::whatever;
use snafu::OptionExt;
use snafu::ResultExt;
use snafu::Whatever;
use tokio::net::TcpListener;
use tracing::Span;

use crate::error;
use crate::media::files::sha1_of_data;
use crate::sync::error::HttpResult;
use crate::sync::error::OrHttpErr;
use crate::sync::http_server::logging::with_logging_layer;
use crate::sync::http_server::media_manager::ServerMediaManager;
use crate::sync::http_server::routes::collection_sync_router;
use crate::sync::http_server::routes::health_check_handler;
use crate::sync::http_server::routes::media_sync_router;
use crate::sync::http_server::user::User;
use crate::sync::login::HostKeyRequest;
use crate::sync::login::HostKeyResponse;
use crate::sync::request::SyncRequest;
use crate::sync::request::MAXIMUM_SYNC_PAYLOAD_BYTES;
use crate::sync::response::SyncResponse;

pub struct SimpleServer {
    state: Mutex<SimpleServerInner>,
    auth_callback_url: Option<String>,
    base_folder: PathBuf,
}

pub struct SimpleServerInner {
    /// hkey->user
    users: HashMap<String, User>,
}

#[derive(serde::Deserialize, Debug)]
pub struct SyncServerConfig {
    #[serde(default = "default_host")]
    pub host: IpAddr,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_base", rename = "base")]
    pub base_folder: PathBuf,
    #[serde(default = "default_ip_header")]
    pub ip_header: ClientIpSource,
    #[serde(default)]
    pub auth_callback_url: Option<String>,
    #[serde(default = "default_callback_timeout")]
    pub auth_callback_timeout_ms: u64,
}

fn default_host() -> IpAddr {
    "0.0.0.0".parse().unwrap()
}

fn default_port() -> u16 {
    8080
}

fn default_base() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| panic!("Unable to determine home folder; please set SYNC_BASE"))
        .join(".syncserver")
}

pub fn default_ip_header() -> ClientIpSource {
    ClientIpSource::ConnectInfo
}

fn default_callback_timeout() -> u64 {
    5000
}

impl SimpleServerInner {
    fn new_from_env(base_folder: &Path) -> error::Result<Self, Whatever> {
        let mut idx = 1;
        let mut users: HashMap<String, User> = Default::default();
        loop {
            let envvar = format!("SYNC_USER{idx}");
            match std::env::var(&envvar) {
                Ok(val) => {
                    let hkey = derive_hkey(&val);
                    let (name, pwhash) = {
                        let (name, password) = val.split_once(':').with_whatever_context(|| {
                            format!("{envvar} should be in 'username:password' format.")
                        })?;
                        if std::env::var("PASSWORDS_HASHED").is_ok() {
                            (name, password.to_string())
                        } else {
                            (
                                name,
                                // Plain text passwords provided; hash them with a fixed salt.
                                Pbkdf2
                                    .hash_password(
                                        password.as_bytes(),
                                        &SaltString::from_b64("tonuvYGpksNFQBlEmm3lxg").unwrap(),
                                    )
                                    .expect("couldn't hash password")
                                    .to_string(),
                            )
                        }
                    };
                    let folder = base_folder.join(name);
                    create_dir_all(&folder).whatever_context("creating SYNC_BASE")?;
                    let media =
                        ServerMediaManager::new(&folder).whatever_context("opening media")?;
                    users.insert(
                        hkey,
                        User {
                            name: name.into(),
                            password_hash: pwhash,
                            col: None,
                            sync_state: None,
                            media,
                            folder,
                        },
                    );
                    idx += 1;
                }
                Err(_) => break,
            }
        }
        if users.is_empty() && std::env::var("SYNC_AUTH_CALLBACK_URL").is_err() {
            whatever!("No users defined and no auth callback configured. Set SYNC_USER1 or SYNC_AUTH_CALLBACK_URL.");
        }
        Ok(Self { users })
    }
}

// This is not what AnkiWeb does, but should suffice for this use case.
fn derive_hkey(user_and_pass: &str) -> String {
    hex::encode(sha1_of_data(user_and_pass.as_bytes()))
}

#[derive(serde::Deserialize, Debug)]
struct AuthCallbackResponse {
    user_id: String,
    email: String,
}

impl SimpleServer {
    async fn authenticate_via_callback(
        &self,
        hkey: &str,
    ) -> error::Result<AuthCallbackResponse, Whatever> {
        let url = self
            .auth_callback_url
            .as_ref()
            .whatever_context("auth callback not configured")?;
        
        tracing::debug!("authenticating via callback: {}", url);
        
        let client = reqwest::Client::new();
        let response = client
            .post(url)
            .json(&serde_json::json!({ "hkey": &hkey[..8] }))
            .timeout(std::time::Duration::from_millis(5000))
            .send()
            .await
            .whatever_context("auth callback request failed")?;
        
        if !response.status().is_success() {
            tracing::warn!("auth callback failed: {}", response.status());
            whatever!("auth callback returned {}", response.status());
        }
        
        let user_info = response
            .json::<AuthCallbackResponse>()
            .await
            .whatever_context("failed to parse auth callback response")?;
        
        tracing::info!("user authenticated: {}", user_info.email);
        Ok(user_info)
    }

    pub(in crate::sync) async fn with_authenticated_user<F, I, O>(
        &self,
        req: SyncRequest<I>,
        op: F,
    ) -> HttpResult<O>
    where
        F: FnOnce(&mut User, SyncRequest<I>) -> HttpResult<O>,
    {
        let hkey = req.sync_key.clone();
        
        // Step 1: Check cache first
        {
            let mut state = self.state.lock().unwrap();
            if let Some(user) = state.users.get_mut(&hkey) {
                Span::current().record("uid", &user.name);
                Span::current().record("client", &req.client_version);
                Span::current().record("session", &req.session_key);
                return op(user, req);
            }
        }
        
        // Step 2: HTTP callback authentication (no lock held)
        let user_info = if self.auth_callback_url.is_some() {
            self.authenticate_via_callback(&hkey)
                .await
                .or_forbidden("authentication failed")?
        } else {
            return None.or_forbidden("invalid hkey");
        };
        
        // Step 3: Create user resources (no lock held)
        let folder = self.base_folder.join(&user_info.user_id);
        create_dir_all(&folder)
            .whatever_context("creating user folder")
            .or_internal_err("create folder")?;
        let media = ServerMediaManager::new(&folder)
            .whatever_context("opening media")
            .or_internal_err("init media")?;
        
        // Step 4: Double-check and insert (prevent race condition)
        let mut state = self.state.lock().unwrap();
        if let Some(user) = state.users.get_mut(&hkey) {
            // Another thread created it while we were authenticating
            Span::current().record("uid", &user.name);
            Span::current().record("client", &req.client_version);
            Span::current().record("session", &req.session_key);
            return op(user, req);
        }
        
        // Step 5: Insert user with write lock
        let mut state = self.state.lock().unwrap();
        state.users.insert(
            hkey.clone(),
            User {
                name: user_info.email.clone(),
                password_hash: String::new(),
                col: None,
                sync_state: None,
                media,
                folder,
            },
        );
        let user = state.users.get_mut(&hkey).unwrap();
        Span::current().record("uid", &user.name);
        Span::current().record("client", &req.client_version);
        Span::current().record("session", &req.session_key);
        op(user, req)
    }

    pub(in crate::sync) fn get_host_key(
        &self,
        request: HostKeyRequest,
    ) -> HttpResult<SyncResponse<HostKeyResponse>> {
        let state = self.state.lock().unwrap();

        // This control structure might seem a bit crude,
        // its goal is to prevent a timing attack from gaining
        // information about whether a specific user exists.
        let user = {
            // This inner block returns Ok(hkey,user) if a user with corresponding
            // name is found and Err(user) with a random user if it isn't found.
            // The user is needed to verify against a random hash,
            // before returning an Error.
            let mut result: Result<(String, &User), &User> =
                Err(state.users.iter().next().unwrap().1);
            for (hkey, user) in state.users.iter() {
                if user.name == request.username {
                    result = Ok((hkey.to_string(), user));
                }
            }
            result
        };

        match user {
            Ok((key, user)) => {
                // Verify password
                let pwhash =
                    &PasswordHash::new(&user.password_hash).expect("couldn't parse password hash");
                if Pbkdf2
                    .verify_password(request.password.as_bytes(), pwhash)
                    .is_ok()
                {
                    SyncResponse::try_from_obj(HostKeyResponse { key })
                } else {
                    None.or_forbidden("invalid user/pass in get_host_key")
                }
            }
            Err(user) => {
                // Verify random password, in order to ensure constant-timedness,
                // then return an error
                let pwhash =
                    &PasswordHash::new(&user.password_hash).expect("couldn't parse password hash");
                let _ = Pbkdf2.verify_password(request.password.as_bytes(), pwhash);
                None.or_forbidden("invalid user/pass in get_host_key")
            }
        }
    }
    pub fn is_running() -> bool {
        let config = envy::prefixed("SYNC_")
            .from_env::<SyncServerConfig>()
            .unwrap();
        std::net::TcpStream::connect(format!("{}:{}", config.host, config.port)).is_ok()
    }
    pub fn new(base_folder: &Path) -> error::Result<Self, Whatever> {
        let inner = SimpleServerInner::new_from_env(base_folder)?;
        let auth_callback_url = std::env::var("SYNC_AUTH_CALLBACK_URL").ok();
        
        // Validate callback URL format
        if let Some(ref url) = auth_callback_url {
            reqwest::Url::parse(url).whatever_context("invalid auth callback URL")?;
        }
        
        Ok(SimpleServer {
            state: Mutex::new(inner),
            auth_callback_url,
            base_folder: base_folder.to_path_buf(),
        })
    }

    pub async fn make_server(
        config: SyncServerConfig,
    ) -> error::Result<(SocketAddr, ServerFuture), Whatever> {
        let server = Arc::new(
            SimpleServer::new(&config.base_folder).whatever_context("unable to create server")?,
        );
        let address = &format!("{}:{}", config.host, config.port);
        let listener = TcpListener::bind(address)
            .await
            .with_whatever_context(|_| format!("couldn't bind to {address}"))?;
        let addr = listener.local_addr().unwrap();
        let server = with_logging_layer(
            Router::new()
                .nest("/sync", collection_sync_router())
                .nest("/msync", media_sync_router())
                .route("/health", get(health_check_handler))
                .with_state(server)
                .layer(DefaultBodyLimit::max(*MAXIMUM_SYNC_PAYLOAD_BYTES))
                .layer(config.ip_header.into_extension()),
        );
        let future = axum::serve(
            listener,
            server.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .into_future();
        tracing::info!(%addr, "listening");
        Ok((addr, Box::pin(future)))
    }

    #[snafu::report]
    #[tokio::main]
    pub async fn run() -> error::Result<(), Whatever> {
        let config = envy::prefixed("SYNC_")
            .from_env::<SyncServerConfig>()
            .whatever_context("reading SYNC_* env vars")?;
        let (_addr, server_fut) = SimpleServer::make_server(config).await?;
        server_fut.await.whatever_context("await server")?;
        Ok(())
    }
}

pub type ServerFuture = Pin<Box<dyn Future<Output = error::Result<(), std::io::Error>> + Send>>;
