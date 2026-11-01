//! One place the container suites start a container from.
//!
//! Startup competes with whatever else holds the Docker daemon, so it is retried. The
//! retry lives here rather than at each call because there are about a hundred calls, and
//! a policy copied a hundred times is a policy that covers ninety-nine.

use std::future::Future;
use std::thread;
use std::time::Duration;

use diesel::pg::PgConnection;
use diesel::prelude::*;
use testcontainers::core::client::ClientError;
use testcontainers::core::error::{TestcontainersError, WaitContainerError};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, ContainerRequest, GenericImage, ImageExt};

pub(crate) const PG_USER: &str = "postgres";
pub(crate) const PG_PASSWORD: &str = "postgres";
pub(crate) const PG_DB: &str = "rls2fga";

/// How long one attempt waits for a container to call itself ready.
///
/// Over the crate's 60 second default, which a loaded daemon exceeds while doing nothing
/// wrong.
const READINESS_TIMEOUT: Duration = Duration::from_mins(3);

/// Attempts per container, the first included.
const STARTUP_ATTEMPTS: u32 = 4;

/// Whether `error` reports a busy daemon rather than a container that cannot work.
///
/// Create and start failures are transient whatever bollard says went wrong, because at
/// that point no container is running and a further attempt inherits nothing. A pull
/// failure, a bad daemon address and a container that ran and exited are all answers about
/// the request itself, so they are reported on the first attempt.
pub(crate) fn is_transient(error: &TestcontainersError) -> bool {
    matches!(
        error,
        TestcontainersError::WaitContainer(WaitContainerError::StartupTimeout)
            | TestcontainersError::Client(
                ClientError::CreateContainer(_) | ClientError::StartContainer(_)
            )
    )
}

/// Retry `attempt` while it fails transiently, up to [`STARTUP_ATTEMPTS`].
///
/// Generic over the attempt so the loop is exercised without a daemon. `attempt` receives
/// the attempt number, counting from one.
pub(crate) async fn retry_transient<T, A, F>(what: &str, attempt: A) -> T
where
    A: Fn(u32) -> F,
    F: Future<Output = Result<T, TestcontainersError>>,
{
    for number in 1..=STARTUP_ATTEMPTS {
        match attempt(number).await {
            Ok(value) => return value,
            Err(error) if is_transient(&error) && number < STARTUP_ATTEMPTS => {
                eprintln!(
                    "{what} did not start on attempt {number} of {STARTUP_ATTEMPTS}, \
                     retrying: {error}"
                );
                // Twelve seconds of patience across the three waits. A refused create
                // request fails in moments, so without a wait all four attempts land
                // inside one hiccup.
                tokio::time::sleep(Duration::from_secs(2 * u64::from(number))).await;
            }
            Err(error) => {
                panic!(
                    "{what} failed to start after {number} of {STARTUP_ATTEMPTS} attempts: {error}"
                )
            }
        }
    }
    unreachable!("the last attempt either returns or panics")
}

/// Start a container, rebuilding the request per attempt.
///
/// The request is rebuilt because `ContainerRequest` is not `Clone`, its log consumers
/// being boxed trait objects.
async fn start_with_retry<B>(what: &str, build: B) -> ContainerAsync<GenericImage>
where
    B: Fn() -> ContainerRequest<GenericImage>,
{
    retry_transient(what, |_| build().start()).await
}

/// A `PostgreSQL` 18 container, ready to accept connections.
pub(crate) async fn start_postgres() -> ContainerAsync<GenericImage> {
    start_postgres_major("18").await
}

/// A container of the `PostgreSQL` major release `major`, ready to accept connections.
pub(crate) async fn start_postgres_major(major: &str) -> ContainerAsync<GenericImage> {
    start_with_retry(&format!("PostgreSQL {major}"), || {
        GenericImage::new("postgres", major)
            .with_exposed_port(5432.tcp())
            .with_wait_for(WaitFor::message_on_stderr(
                "database system is ready to accept connections",
            ))
            .with_env_var("POSTGRES_USER", PG_USER)
            .with_env_var("POSTGRES_PASSWORD", PG_PASSWORD)
            .with_env_var("POSTGRES_DB", PG_DB)
            .with_startup_timeout(READINESS_TIMEOUT)
    })
    .await
}

/// An `OpenFGA` container serving both its HTTP and its gRPC port.
pub(crate) async fn start_openfga() -> ContainerAsync<GenericImage> {
    start_openfga_with(&[]).await
}

/// [`start_openfga`] with `settings` in its environment, such as
/// `OPENFGA_MAX_AUTHORIZATION_MODEL_SIZE_IN_BYTES`.
pub(crate) async fn start_openfga_with(
    settings: &[(&str, String)],
) -> ContainerAsync<GenericImage> {
    start_with_retry("OpenFGA v1.11.6", || {
        settings.iter().fold(
            GenericImage::new("openfga/openfga", "v1.11.6")
                .with_exposed_port(8080.tcp())
                .with_exposed_port(8081.tcp())
                .with_wait_for(WaitFor::message_on_stdout("starting HTTP server"))
                .with_cmd(["run"])
                .with_startup_timeout(READINESS_TIMEOUT),
            |request, (name, value)| request.with_env_var(*name, value.as_str()),
        )
    })
    .await
}

/// Provoke a real readiness timeout and hand back the error the daemon produced.
///
/// The one link the offline tests cannot check is whether a genuine timeout arrives as the
/// variant [`is_transient`] answers for. This exists so a test can, without building an
/// image outside this module.
pub(crate) async fn readiness_timeout_error() -> TestcontainersError {
    GenericImage::new("postgres", "18")
        .with_exposed_port(5432.tcp())
        // A line PostgreSQL never prints, so readiness cannot arrive.
        .with_wait_for(WaitFor::message_on_stderr("this readiness never comes"))
        .with_env_var("POSTGRES_PASSWORD", PG_PASSWORD)
        .with_startup_timeout(Duration::from_secs(2))
        .start()
        .await
        .expect_err("readiness never arrives, so startup times out")
}

/// The URL of `database` on a started `PostgreSQL` container.
pub(crate) async fn postgres_url(
    container: &ContainerAsync<GenericImage>,
    database: &str,
) -> String {
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("PostgreSQL container exposes 5432");
    format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{port}/{database}")
}

/// Connect once the server answers.
///
/// Readiness is the server's own message, which it prints before it is listening on the
/// mapped port, so the first connections lose a race the server has already announced.
pub(crate) fn connect_postgres_with_retry(database_url: &str) -> PgConnection {
    let mut last_error = String::new();
    for _ in 0..30 {
        match PgConnection::establish(database_url) {
            Ok(conn) => return conn,
            Err(error) => {
                last_error = error.to_string();
                thread::sleep(Duration::from_millis(200));
            }
        }
    }
    panic!("Failed to connect to PostgreSQL after retries: {last_error}");
}

/// A `PostgreSQL` container and a connection to its default database.
pub(crate) async fn start_postgres_connected() -> (ContainerAsync<GenericImage>, PgConnection) {
    let container = start_postgres().await;
    let url = postgres_url(&container, PG_DB).await;
    let conn = connect_postgres_with_retry(&url);
    (container, conn)
}
