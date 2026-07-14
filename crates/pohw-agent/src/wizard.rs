use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use rand_core::{OsRng, RngCore};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{sleep, timeout};

use crate::bootstrap::{LaunchPhase, SnapshotPinV1, SourceJoinManifestV1};
use crate::files::{create_private_file, read_limited_regular};
use crate::node::{
    ManagedChild, MiningAdapterLaunch, NodeDriver, RegistrationChallenge, RegistrationResult,
};

const INDEX_HTML: &str = include_str!("../assets/index.html");
const APP_JS: &str = include_str!("../assets/app.js");
const CALLBACK_JS: &str = include_str!("../assets/callback.js");
const STYLE_CSS: &str = include_str!("../assets/style.css");
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 32 * 1024;
const MAX_TARGET_BYTES: usize = 4096;
const CALLBACK_VALIDITY: Duration = Duration::from_secs(10 * 60);
const LOCAL_FORK_RPC: &str = "127.0.0.1:40408";
const NO_VALUE_ACKNOWLEDGEMENT: &str = "I_UNDERSTAND_NO_VALUE";
const MAX_CONCURRENT_CONNECTIONS: usize = 16;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

pub struct WizardConfig {
    pub descriptor: SourceJoinManifestV1,
    pub driver: NodeDriver,
    pub activation_manifest_path: PathBuf,
    pub snapshot_dir: Option<PathBuf>,
    pub snapshot_min_voters: Option<usize>,
    pub bind_addr: SocketAddr,
    pub stratum_bind_addr: SocketAddr,
    pub open_browser: bool,
}

struct WizardContext {
    descriptor: SourceJoinManifestV1,
    driver: NodeDriver,
    activation_manifest_path: PathBuf,
    snapshot_dir: Option<PathBuf>,
    snapshot_min_voters: Option<usize>,
    bind_addr: SocketAddr,
    stratum_bind_addr: SocketAddr,
    expected_host: String,
    csrf_token: String,
    connection_limit: Arc<Semaphore>,
    state: Mutex<WizardState>,
}

#[derive(Default)]
struct WizardState {
    busy: bool,
    pending: Option<PendingRegistration>,
    registration: Option<RegistrationResult>,
    children: Vec<ManagedChild>,
    last_error: Option<String>,
}

struct PendingRegistration {
    challenge: RegistrationChallenge,
    callback_token_digest: [u8; 32],
    expires_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallbackTokenDecision {
    Accept,
    RejectMismatch,
    RejectExpired,
}

#[derive(Debug, Serialize)]
struct WizardView {
    experiment_id: String,
    activation_id_short: String,
    launch_phase: String,
    source_build_verified: bool,
    source_cid_short: String,
    registered: bool,
    identity_status: String,
    services_running: bool,
    launch_status: String,
    explorer_url: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareRequest {
    miner_id: String,
    idena_address: String,
}

#[derive(Debug, Serialize)]
struct PrepareResponse {
    web_sign_url: String,
    desktop_sign_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartRequest {
    acknowledgement: String,
}

#[derive(Debug, Serialize)]
struct StartResponse {
    state: WizardView,
    #[serde(skip_serializing_if = "Option::is_none")]
    stratum: Option<StratumCredentials>,
}

#[derive(Debug, Serialize)]
struct StateResponse {
    state: WizardView,
}

#[derive(Debug, Serialize)]
struct StratumCredentials {
    url: String,
    worker: String,
    password: String,
}

struct LaunchOutcome {
    children: Vec<ManagedChild>,
    stratum: Option<StratumCredentials>,
}

struct HttpRequest {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct HttpResponse {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

pub async fn run(config: WizardConfig) -> Result<()> {
    if !config.bind_addr.ip().is_loopback() {
        bail!("onboarding wizard must bind to a loopback address");
    }
    let listener = TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("bind onboarding wizard on {}", config.bind_addr))?;
    let bind_addr = listener.local_addr().context("read wizard bind address")?;
    let expected_host = bind_addr.to_string();
    let url = format!("http://{expected_host}/");
    let existing_registration = config.driver.existing_registration()?;
    let context = Arc::new(WizardContext {
        descriptor: config.descriptor,
        driver: config.driver,
        activation_manifest_path: config.activation_manifest_path,
        snapshot_dir: config.snapshot_dir,
        snapshot_min_voters: config.snapshot_min_voters,
        bind_addr,
        stratum_bind_addr: config.stratum_bind_addr,
        expected_host,
        csrf_token: random_hex(32),
        connection_limit: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
        state: Mutex::new(WizardState {
            registration: existing_registration,
            ..WizardState::default()
        }),
    });

    println!("P2PoolBTC onboarding wizard: {url}");
    println!("The wizard is loopback-only and will stop child services on Ctrl-C.");
    if config.open_browser {
        open_browser(&url);
    }
    INTERRUPTED.store(false, Ordering::SeqCst);
    install_interrupt_handler()?;

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(value) => value,
                    Err(error) => return Err(error).context("accept wizard connection"),
                };
                if !peer.ip().is_loopback() {
                    continue;
                }
                let Ok(permit) = Arc::clone(&context.connection_limit).try_acquire_owned() else {
                    continue;
                };
                let context = Arc::clone(&context);
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = serve_connection(stream, context).await;
                });
            }
            _ = sleep(Duration::from_millis(100)) => {
                if INTERRUPTED.load(Ordering::SeqCst) {
                    break;
                }
            }
        }
    }

    let mut state = context.state.lock().await;
    stop_children(&mut state.children);
    Ok(())
}

#[cfg(unix)]
fn install_interrupt_handler() -> Result<()> {
    unsafe extern "C" fn handle_interrupt(_signal: libc::c_int) {
        INTERRUPTED.store(true, Ordering::SeqCst);
    }

    let handler = handle_interrupt as *const () as libc::sighandler_t;
    let previous = unsafe { libc::signal(libc::SIGINT, handler) };
    if previous == libc::SIG_ERR {
        bail!(
            "install Ctrl-C handler: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn install_interrupt_handler() -> Result<()> {
    type ConsoleControlHandler = Option<unsafe extern "system" fn(u32) -> i32>;

    #[link(name = "Kernel32")]
    extern "system" {
        fn SetConsoleCtrlHandler(handler: ConsoleControlHandler, add: i32) -> i32;
    }

    unsafe extern "system" fn handle_control(control_type: u32) -> i32 {
        const CTRL_C_EVENT: u32 = 0;
        const CTRL_BREAK_EVENT: u32 = 1;
        const CTRL_CLOSE_EVENT: u32 = 2;
        const CTRL_LOGOFF_EVENT: u32 = 5;
        const CTRL_SHUTDOWN_EVENT: u32 = 6;

        match control_type {
            CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT
            | CTRL_SHUTDOWN_EVENT => {
                INTERRUPTED.store(true, Ordering::SeqCst);
                1
            }
            _ => 0,
        }
    }

    let installed = unsafe { SetConsoleCtrlHandler(Some(handle_control), 1) };
    if installed == 0 {
        bail!(
            "install Windows console control handler: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn install_interrupt_handler() -> Result<()> {
    bail!("safe child cleanup on interrupt is unsupported on this platform")
}

async fn serve_connection(mut stream: TcpStream, context: Arc<WizardContext>) -> Result<()> {
    let response = match timeout(REQUEST_TIMEOUT, read_request(&mut stream)).await {
        Ok(Ok(request)) => route_request(&context, request).await,
        Ok(Err(_)) => HttpResponse::text(400, "Bad request"),
        Err(_) => HttpResponse::text(408, "Request timeout"),
    };
    timeout(RESPONSE_TIMEOUT, write_response(&mut stream, response))
        .await
        .context("HTTP response timed out")?
}

async fn route_request(context: &Arc<WizardContext>, request: HttpRequest) -> HttpResponse {
    if request.headers.get("host") != Some(&context.expected_host) {
        return HttpResponse::json_error(421, "unexpected Host header");
    }
    if request.target.len() > MAX_TARGET_BYTES || !request.target.starts_with('/') {
        return HttpResponse::json_error(400, "invalid request target");
    }
    let parsed = match Url::parse(&format!(
        "http://{}{}",
        context.expected_host, request.target
    )) {
        Ok(value) => value,
        Err(_) => return HttpResponse::json_error(400, "invalid request target"),
    };
    let path = parsed.path();

    match (request.method.as_str(), path) {
        ("GET", "/") => HttpResponse::bytes(
            200,
            "text/html; charset=utf-8",
            INDEX_HTML.replace("__POHW_CSRF_TOKEN__", &context.csrf_token),
        ),
        ("GET", "/style.css") => HttpResponse::bytes(200, "text/css; charset=utf-8", STYLE_CSS),
        ("GET", "/app.js") => HttpResponse::bytes(200, "text/javascript; charset=utf-8", APP_JS),
        ("GET", "/callback.js") => {
            HttpResponse::bytes(200, "text/javascript; charset=utf-8", CALLBACK_JS)
        }
        ("GET", "/callback") => handle_callback(context, &parsed).await,
        ("GET", "/api/state") if api_request_authorized(context, &request) => {
            match current_view(context).await {
                Ok(view) => HttpResponse::json(200, &view),
                Err(error) => HttpResponse::json_error(500, &public_error(&error)),
            }
        }
        ("POST", "/api/prepare") if api_request_authorized(context, &request) => {
            match parse_json::<PrepareRequest>(&request).and_then(|input| {
                ensure_json_request(&request)?;
                Ok(input)
            }) {
                Ok(input) => match prepare_registration(context, input).await {
                    Ok(response) => HttpResponse::json(200, &response),
                    Err(error) => HttpResponse::json_error(400, &public_error(&error)),
                },
                Err(error) => HttpResponse::json_error(400, &public_error(&error)),
            }
        }
        ("POST", "/api/start") if api_request_authorized(context, &request) => {
            match parse_json::<StartRequest>(&request).and_then(|input| {
                ensure_json_request(&request)?;
                Ok(input)
            }) {
                Ok(input) => match start_services(context, input).await {
                    Ok(response) => HttpResponse::json(200, &response),
                    Err(error) => HttpResponse::json_error(400, &public_error(&error)),
                },
                Err(error) => HttpResponse::json_error(400, &public_error(&error)),
            }
        }
        ("POST", "/api/stop") if api_request_authorized(context, &request) => {
            if let Err(error) = ensure_json_request(&request) {
                return HttpResponse::json_error(400, &public_error(&error));
            }
            match stop_services(context).await {
                Ok(view) => HttpResponse::json(200, &StateResponse { state: view }),
                Err(error) => HttpResponse::json_error(500, &public_error(&error)),
            }
        }
        ("GET" | "POST", path) if path.starts_with("/api/") => {
            HttpResponse::json_error(403, "request rejected")
        }
        _ => HttpResponse::text(404, "Not found"),
    }
}

async fn prepare_registration(
    context: &Arc<WizardContext>,
    input: PrepareRequest,
) -> Result<PrepareResponse> {
    {
        let mut state = context.state.lock().await;
        if state.busy || !state.children.is_empty() {
            bail!("another onboarding operation is active");
        }
        if state.registration.is_some() {
            bail!("this local node is already registered in the wizard session");
        }
        state.busy = true;
        state.last_error = None;
    }

    let challenge = context
        .driver
        .prepare_registration(&input.miner_id, &input.idena_address);
    let challenge = match challenge {
        Ok(value) => value,
        Err(error) => {
            record_operation_error(context, &error).await;
            return Err(error);
        }
    };
    let callback_token = random_hex(32);
    let callback_url = callback_url(context, &callback_token)?;
    let web_sign_url = idena_sign_url(
        "https://app.idena.io/dna/sign",
        &challenge.idena_ownership_challenge,
        &callback_url,
    )?;
    let desktop_sign_url = idena_sign_url(
        "dna://sign/v1",
        &challenge.idena_ownership_challenge,
        &callback_url,
    )?;

    let mut state = context.state.lock().await;
    state.pending = Some(PendingRegistration {
        challenge,
        callback_token_digest: Sha256::digest(callback_token.as_bytes()).into(),
        expires_at: Instant::now() + CALLBACK_VALIDITY,
    });
    state.busy = false;
    Ok(PrepareResponse {
        web_sign_url,
        desktop_sign_url,
    })
}

async fn handle_callback(context: &Arc<WizardContext>, url: &Url) -> HttpResponse {
    let query = url.query_pairs().collect::<BTreeMap<_, _>>();
    let Some(token) = query.get("state") else {
        return callback_page(false);
    };
    let Some(signature) = query.get("signature") else {
        return callback_page(false);
    };
    let challenge = {
        let mut state = context.state.lock().await;
        if state.busy || state.registration.is_some() {
            return callback_page(false);
        }
        let Some(pending) = state.pending.as_ref() else {
            return callback_page(false);
        };
        match callback_token_decision(pending, token, Instant::now()) {
            CallbackTokenDecision::Accept => {}
            CallbackTokenDecision::RejectMismatch => return callback_page(false),
            CallbackTokenDecision::RejectExpired => {
                state.pending = None;
                return callback_page(false);
            }
        }
        let challenge = pending.challenge.clone();
        state.busy = true;
        challenge
    };

    let result = context
        .driver
        .complete_registration(&challenge, signature, &context.descriptor.peers.gossip)
        .await;
    let mut state = context.state.lock().await;
    state.busy = false;
    match result {
        Ok(registration) => {
            state.registration = Some(registration);
            state.pending = None;
            state.last_error = None;
            callback_page(true)
        }
        Err(error) => {
            state.last_error = Some(public_error(&error));
            callback_page(false)
        }
    }
}

fn callback_token_decision(
    pending: &PendingRegistration,
    token: &str,
    now: Instant,
) -> CallbackTokenDecision {
    if pending.expires_at <= now {
        return CallbackTokenDecision::RejectExpired;
    }
    let token_digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    if constant_time_equal(&token_digest, &pending.callback_token_digest) {
        CallbackTokenDecision::Accept
    } else {
        CallbackTokenDecision::RejectMismatch
    }
}

async fn start_services(
    context: &Arc<WizardContext>,
    input: StartRequest,
) -> Result<StartResponse> {
    if input.acknowledgement != NO_VALUE_ACKNOWLEDGEMENT {
        bail!("the exact no-value acknowledgement is required");
    }
    let miner_id = {
        let mut state = context.state.lock().await;
        if state.busy || !state.children.is_empty() {
            bail!("local services are already running or changing state");
        }
        let registration = state
            .registration
            .as_ref()
            .context("complete Idena registration before launch")?;
        let miner_id = registration.miner_id.clone();
        state.busy = true;
        state.last_error = None;
        miner_id
    };

    let outcome = launch_services(context, &miner_id).await;
    let mut state = context.state.lock().await;
    state.busy = false;
    let stratum = match outcome {
        Ok(outcome) => {
            state.children = outcome.children;
            state.last_error = None;
            outcome.stratum
        }
        Err(error) => {
            state.last_error = Some(public_error(&error));
            return Err(error);
        }
    };
    let view = build_view(context, &mut state)?;
    Ok(StartResponse {
        state: view,
        stratum,
    })
}

async fn launch_services(context: &Arc<WizardContext>, miner_id: &str) -> Result<LaunchOutcome> {
    let gossip_peers = context
        .driver
        .add_gossip_peers(&context.descriptor.peers.gossip)
        .await?;
    let fork_peers = if matches!(
        context.descriptor.launch.phase,
        LaunchPhase::ForkSync | LaunchPhase::Mining
    ) {
        Some(
            context
                .driver
                .matching_fork_peers(&context.descriptor, &context.activation_manifest_path)
                .await?,
        )
    } else {
        None
    };

    let mut children = Vec::new();
    children.push(context.driver.spawn_gossip(&gossip_peers)?);

    let fork_rpc_addr: SocketAddr = LOCAL_FORK_RPC.parse().expect("constant socket address");
    if let Some(peers) = fork_peers.as_ref() {
        if peers.rpc.is_empty() {
            bail!("no verified fork RPC peer is available");
        }
        children.push(context.driver.spawn_fork_node(
            &context.activation_manifest_path,
            &peers.p2p,
            fork_rpc_addr,
        )?);
        wait_for_local_fork(context, fork_rpc_addr).await?;
    }

    let stratum = if matches!(context.descriptor.launch.phase, LaunchPhase::Mining) {
        let snapshot_dir = context
            .snapshot_dir
            .as_ref()
            .context("mining snapshot directory is not configured")?;
        let min_snapshot_voters = context
            .snapshot_min_voters
            .context("mining snapshot voter quorum is not configured")?;
        let evidence = context.driver.mining_snapshot_evidence(
            snapshot_dir,
            Some(miner_id),
            min_snapshot_voters,
        )?;
        let expected_snapshot = context
            .descriptor
            .snapshot
            .as_ref()
            .context("mining snapshot pin is absent from the join manifest")?;
        if !snapshot_recheck_matches(expected_snapshot, &evidence.snapshot_pin()) {
            bail!("verified mining snapshot changed after onboarding inspection");
        }
        let password_path = context
            .driver
            .datadir()
            .join("agent-secrets")
            .join("stratum.password");
        let password = read_or_create_password(&password_path)?;
        children.push(context.driver.spawn_mining_adapter(MiningAdapterLaunch {
            descriptor: &context.descriptor,
            activation_manifest: &context.activation_manifest_path,
            miner_id,
            stratum_bind: context.stratum_bind_addr,
            stratum_password_file: &password_path,
            gossip_peers: &gossip_peers,
            fork_rpc_addr,
        })?);
        Some(StratumCredentials {
            url: format!("stratum+tcp://{}", context.stratum_bind_addr),
            worker: miner_id.to_string(),
            password,
        })
    } else {
        None
    };

    sleep(Duration::from_millis(400)).await;
    for child in &mut children {
        if !child.running()? {
            bail!("a local experiment service exited during launch");
        }
    }

    Ok(LaunchOutcome { children, stratum })
}

fn snapshot_recheck_matches(expected: &SnapshotPinV1, current: &SnapshotPinV1) -> bool {
    current.snapshot_id == expected.snapshot_id
        && current.proof_root == expected.proof_root
        && current.source_height == expected.source_height
        && current.distinct_voter_count >= expected.distinct_voter_count
}

async fn wait_for_local_fork(context: &Arc<WizardContext>, rpc_addr: SocketAddr) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(status) = context
            .driver
            .local_fork_status(&context.activation_manifest_path, rpc_addr)
        {
            if status.get("activation_id").and_then(|value| value.as_str())
                == Some(context.descriptor.activation.activation_id.as_str())
            {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            bail!("local fork node did not become ready with the pinned activation ID");
        }
        sleep(Duration::from_millis(250)).await;
    }
}

async fn stop_services(context: &Arc<WizardContext>) -> Result<WizardView> {
    let mut state = context.state.lock().await;
    if state.busy {
        bail!("another onboarding operation is active");
    }
    stop_children(&mut state.children);
    state.last_error = None;
    build_view(context, &mut state)
}

async fn current_view(context: &Arc<WizardContext>) -> Result<WizardView> {
    let mut state = context.state.lock().await;
    build_view(context, &mut state)
}

fn build_view(context: &WizardContext, state: &mut WizardState) -> Result<WizardView> {
    let mut all_running = !state.children.is_empty();
    if all_running {
        for child in &mut state.children {
            if !child.running()? {
                all_running = false;
                break;
            }
        }
        if !all_running {
            stop_children(&mut state.children);
            state.last_error =
                Some("a local experiment service exited; all services were stopped".to_string());
        }
    }
    let registered = state.registration.is_some();
    let identity_status = if registered {
        "Idena ownership verified and registration created.".to_string()
    } else if state.pending.is_some() {
        "Waiting for the signed Idena callback.".to_string()
    } else if state.busy {
        "Processing identity registration.".to_string()
    } else {
        "Waiting for identity details.".to_string()
    };
    let launch_status = if all_running {
        "Local experiment services are running.".to_string()
    } else if registered {
        "Ready for explicit no-value launch approval.".to_string()
    } else {
        "Identity registration is required.".to_string()
    };
    Ok(WizardView {
        experiment_id: context.descriptor.experiment_id.clone(),
        activation_id_short: short_id(&context.descriptor.activation.activation_id),
        launch_phase: launch_phase_name(&context.descriptor.launch.phase).to_string(),
        source_build_verified: true,
        source_cid_short: short_id(&context.descriptor.source.source_tree_cid),
        registered,
        identity_status,
        services_running: all_running,
        launch_status,
        explorer_url: context.descriptor.peers.explorer_url.clone(),
        error: state.last_error.clone(),
    })
}

fn stop_children(children: &mut Vec<ManagedChild>) {
    for child in children.iter_mut().rev() {
        child.stop();
    }
    children.clear();
}

async fn record_operation_error(context: &WizardContext, error: &anyhow::Error) {
    let mut state = context.state.lock().await;
    state.busy = false;
    state.last_error = Some(public_error(error));
}

fn callback_url(context: &WizardContext, token: &str) -> Result<String> {
    let mut url = Url::parse(&format!("http://{}/callback", context.bind_addr))?;
    url.query_pairs_mut().append_pair("state", token);
    Ok(url.into())
}

fn idena_sign_url(base: &str, message: &str, callback_url: &str) -> Result<String> {
    let mut url = Url::parse(base).context("construct Idena signing URL")?;
    url.query_pairs_mut()
        .append_pair("message", message)
        .append_pair("callback_url", callback_url);
    Ok(url.into())
}

fn read_or_create_password(path: &std::path::Path) -> Result<String> {
    if path.exists() {
        let bytes = read_limited_regular(path, 256)?;
        let password = String::from_utf8(bytes).context("Stratum password is not UTF-8")?;
        let password = password.trim().to_string();
        validate_password(&password)?;
        return Ok(password);
    }
    let password = random_hex(24);
    create_private_file(path, format!("{password}\n").as_bytes())?;
    Ok(password)
}

fn validate_password(password: &str) -> Result<()> {
    if password.len() < 16
        || password.len() > 128
        || password.bytes().any(|byte| byte.is_ascii_control())
    {
        bail!("existing Stratum password does not meet local safety requirements");
    }
    Ok(())
}

fn callback_page(success: bool) -> HttpResponse {
    let title = if success {
        "Identity verified"
    } else {
        "Identity verification failed"
    };
    let marker = if success { "✓" } else { "!" };
    HttpResponse::bytes(
        200,
        "text/html; charset=utf-8",
        format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{title}</title><link rel=\"stylesheet\" href=\"/style.css\"></head><body><main><section class=\"step\"><div class=\"step-index\">{marker}</div><div class=\"step-body\"><h1>{title}</h1><p class=\"inline-status\">Returning to the local onboarding wizard.</p></div></section></main><script src=\"/callback.js\"></script></body></html>"
        ),
    )
}

fn api_request_authorized(context: &WizardContext, request: &HttpRequest) -> bool {
    let csrf_matches = request
        .headers
        .get("x-pohw-csrf")
        .is_some_and(|value| constant_time_equal(value.as_bytes(), context.csrf_token.as_bytes()));
    let origin_matches = match request.headers.get("origin") {
        Some(origin) => origin == &format!("http://{}", context.expected_host),
        None => true,
    };
    csrf_matches && origin_matches
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn ensure_json_request(request: &HttpRequest) -> Result<()> {
    let content_type = request
        .headers
        .get("content-type")
        .context("Content-Type is required")?;
    if content_type != "application/json" {
        bail!("Content-Type must be application/json");
    }
    Ok(())
}

fn parse_json<T: for<'de> Deserialize<'de>>(request: &HttpRequest) -> Result<T> {
    serde_json::from_slice(&request.body).context("request body is invalid JSON")
}

async fn read_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 2048];
    let header_end = loop {
        let read = stream
            .read(&mut buffer)
            .await
            .context("read HTTP request")?;
        if read == 0 {
            bail!("connection closed before request headers");
        }
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(index) = find_header_end(&bytes) {
            break index;
        }
        if bytes.len() > MAX_HEADER_BYTES {
            bail!("request headers exceed safety limit");
        }
    };
    if header_end > MAX_HEADER_BYTES {
        bail!("request headers exceed safety limit");
    }
    let header_text = std::str::from_utf8(&bytes[..header_end]).context("headers are not UTF-8")?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().context("missing request line")?;
    let mut request_parts = request_line.split(' ');
    let method = request_parts
        .next()
        .context("missing HTTP method")?
        .to_string();
    let target = request_parts
        .next()
        .context("missing HTTP target")?
        .to_string();
    let version = request_parts.next().context("missing HTTP version")?;
    if request_parts.next().is_some()
        || !matches!(method.as_str(), "GET" | "POST")
        || version != "HTTP/1.1"
        || target.len() > MAX_TARGET_BYTES
    {
        bail!("unsupported request line");
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').context("malformed HTTP header")?;
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("invalid HTTP header name");
        }
        if headers.insert(name, value.trim().to_string()).is_some() {
            bail!("duplicate HTTP header");
        }
    }
    if headers.contains_key("transfer-encoding") {
        bail!("transfer encoding is not supported");
    }
    let content_length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>().context("invalid Content-Length"))
        .transpose()?
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        bail!("request body exceeds safety limit");
    }
    if method == "POST" && !headers.contains_key("content-length") {
        bail!("POST requires Content-Length");
    }
    let body_start = header_end + 4;
    let expected_total = body_start
        .checked_add(content_length)
        .context("request length overflow")?;
    while bytes.len() < expected_total {
        let read = stream.read(&mut buffer).await.context("read HTTP body")?;
        if read == 0 {
            bail!("connection closed before request body");
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.len() > expected_total {
            bail!("HTTP pipelining is not supported");
        }
    }
    if bytes.len() != expected_total {
        bail!("unexpected bytes after request body");
    }
    Ok(HttpRequest {
        method,
        target,
        headers,
        body: bytes[body_start..].to_vec(),
    })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

async fn write_response(stream: &mut TcpStream, response: HttpResponse) -> Result<()> {
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        408 => "Request Timeout",
        421 => "Misdirected Request",
        500 => "Internal Server Error",
        _ => "Error",
    };
    let headers = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'\r\nCross-Origin-Opener-Policy: same-origin\r\nCross-Origin-Resource-Policy: same-origin\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nPermissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()\r\nConnection: close\r\n\r\n",
        response.status,
        reason,
        response.content_type,
        response.body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(&response.body).await?;
    stream.shutdown().await?;
    Ok(())
}

impl HttpResponse {
    fn bytes(status: u16, content_type: &'static str, body: impl AsRef<[u8]>) -> Self {
        Self {
            status,
            content_type,
            body: body.as_ref().to_vec(),
        }
    }

    fn text(status: u16, body: &str) -> Self {
        Self::bytes(status, "text/plain; charset=utf-8", body)
    }

    fn json<T: Serialize>(status: u16, value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(body) => Self::bytes(status, "application/json; charset=utf-8", body),
            Err(_) => Self::json_error(500, "response serialization failed"),
        }
    }

    fn json_error(status: u16, message: &str) -> Self {
        Self::json(status, &serde_json::json!({ "error": message }))
    }
}

fn launch_phase_name(phase: &LaunchPhase) -> &'static str {
    match phase {
        LaunchPhase::Registration => "registration",
        LaunchPhase::ForkSync => "fork-sync",
        LaunchPhase::Mining => "mining",
    }
}

fn short_id(value: &str) -> String {
    value.chars().take(12).collect()
}

fn random_hex(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut value);
    hex::encode(value)
}

fn public_error(error: &anyhow::Error) -> String {
    let message = error.to_string();
    let clean = message
        .chars()
        .filter(|character| !character.is_control())
        .take(240)
        .collect::<String>();
    if clean.is_empty() {
        "operation failed".to_string()
    } else {
        clean
    }
}

fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let mut command = Command::new("open");
    #[cfg(target_os = "linux")]
    let mut command = Command::new("xdg-open");
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut value = Command::new("cmd");
        value.args(["/C", "start", ""]);
        value
    };
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    {
        let _ = command.arg(url).spawn();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrf_compare_requires_exact_bytes() {
        assert!(constant_time_equal(b"abc", b"abc"));
        assert!(!constant_time_equal(b"abc", b"abd"));
        assert!(!constant_time_equal(b"abc", b"ab"));
    }

    #[test]
    fn request_header_boundary_is_detected() {
        assert_eq!(
            find_header_end(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
            Some(23)
        );
    }

    #[test]
    fn idena_urls_encode_callback_and_challenge() {
        let url = idena_sign_url(
            "https://app.idena.io/dna/sign",
            "hello world",
            "http://127.0.0.1:8765/callback?state=a&b=c",
        )
        .unwrap();
        let parsed = Url::parse(&url).unwrap();
        let query = parsed.query_pairs().collect::<BTreeMap<_, _>>();
        assert_eq!(query.get("message").unwrap(), "hello world");
        assert_eq!(
            query.get("callback_url").unwrap(),
            "http://127.0.0.1:8765/callback?state=a&b=c"
        );
    }

    #[test]
    fn callback_page_never_reflects_query_data() {
        let response = callback_page(false);
        let body = String::from_utf8(response.body).unwrap();
        assert!(!body.contains("signature"));
        assert!(body.contains("callback.js"));
    }

    #[test]
    fn callback_token_mismatch_does_not_consume_a_live_challenge() {
        let token = "correct-state";
        let pending = PendingRegistration {
            challenge: RegistrationChallenge {
                status: "needs_idena_signature".to_string(),
                miner_id: "alice-01".to_string(),
                idena_address: format!("0x{}", "11".repeat(20)),
                idena_ownership_challenge: "challenge".to_string(),
                registration_binding_hash: "22".repeat(32),
                mining_pubkey_hex: "33".repeat(32),
                claim_owner_pubkey_hex: "44".repeat(32),
                btc_payout_script_hex: "51".to_string(),
            },
            callback_token_digest: Sha256::digest(token.as_bytes()).into(),
            expires_at: Instant::now() + Duration::from_secs(60),
        };

        assert_eq!(
            callback_token_decision(&pending, "wrong-state", Instant::now()),
            CallbackTokenDecision::RejectMismatch
        );
        assert_eq!(
            callback_token_decision(&pending, token, Instant::now()),
            CallbackTokenDecision::Accept
        );
        assert_eq!(
            callback_token_decision(&pending, token, pending.expires_at),
            CallbackTokenDecision::RejectExpired
        );
    }

    #[test]
    fn snapshot_recheck_allows_only_monotonic_voter_growth() {
        let expected = SnapshotPinV1 {
            snapshot_id: "2026-07-14".to_string(),
            proof_root: "11".repeat(32),
            source_height: 42,
            distinct_voter_count: 3,
        };
        let mut current = expected.clone();
        current.distinct_voter_count = 4;
        assert!(snapshot_recheck_matches(&expected, &current));

        current.distinct_voter_count = 2;
        assert!(!snapshot_recheck_matches(&expected, &current));
        current = expected.clone();
        current.proof_root = "22".repeat(32);
        assert!(!snapshot_recheck_matches(&expected, &current));
    }

    #[test]
    fn public_errors_remove_controls_and_bound_length() {
        let error = anyhow::anyhow!("{}\nsecret", "x".repeat(500));
        let output = public_error(&error);
        assert!(output.len() <= 240);
        assert!(!output.contains('\n'));
    }
}
