//! Which container startup failures are worth another attempt.
//!
//! The container suites share one startup helper so that a busy Docker daemon costs a
//! retry rather than a red run. What it must not do is retry a failure that will never
//! succeed, because that turns a clear error into a slow one. This pins the split without
//! needing a daemon.

#![cfg(not(target_os = "windows"))]

use testcontainers::bollard::errors::Error as BollardError;
use testcontainers::core::client::ClientError;
use testcontainers::core::error::{TestcontainersError, WaitContainerError};

use crate::support;

use crate::support::containers::{is_transient, retry_transient};

#[test]
fn a_daemon_too_busy_to_answer_is_worth_another_attempt() {
    assert!(
        is_transient(&TestcontainersError::WaitContainer(
            WaitContainerError::StartupTimeout
        )),
        "a readiness timeout is the daemon being slow, which a retry survives"
    );
    assert!(
        is_transient(&TestcontainersError::Client(ClientError::CreateContainer(
            BollardError::RequestTimeoutError
        ))),
        "a create request that timed out never reached a container"
    );
    assert!(
        is_transient(&TestcontainersError::Client(ClientError::StartContainer(
            BollardError::RequestTimeoutError
        ))),
        "a start request that timed out leaves nothing running"
    );
}

#[test]
fn a_container_that_started_and_died_is_not_worth_another_attempt() {
    assert!(
        !is_transient(&TestcontainersError::WaitContainer(
            WaitContainerError::UnexpectedExitCode {
                expected: 0,
                actual: Some(1),
            }
        )),
        "the container ran and exited, so every attempt exits the same way"
    );
    assert!(
        !is_transient(&TestcontainersError::WaitContainer(
            WaitContainerError::Unhealthy
        )),
        "an unhealthy container is a broken container, not a busy daemon"
    );
}

#[test]
fn a_wrong_image_is_reported_on_the_first_attempt() {
    assert!(
        !is_transient(&TestcontainersError::Client(ClientError::PullImage {
            descriptor: "postgres:does-not-exist".to_string(),
            err: BollardError::RequestTimeoutError,
        })),
        "no number of attempts invents a tag the registry does not carry"
    );
    assert!(
        !is_transient(&TestcontainersError::Client(
            ClientError::InvalidDockerHost("tcp://nowhere".to_string())
        )),
        "a misconfigured daemon address is a setup error, and retrying hides it"
    );
}

/// A failure the helper retries, cheap to build.
fn busy() -> TestcontainersError {
    TestcontainersError::WaitContainer(WaitContainerError::StartupTimeout)
}

/// A failure the helper reports at once.
fn broken() -> TestcontainersError {
    TestcontainersError::WaitContainer(WaitContainerError::Unhealthy)
}

#[tokio::test(start_paused = true)]
async fn a_busy_daemon_costs_attempts_rather_than_the_run() {
    let started = retry_transient("probe", |attempt| async move {
        if attempt < 3 {
            Err(busy())
        } else {
            Ok(attempt)
        }
    })
    .await;

    assert_eq!(
        started, 3,
        "the third attempt is the one that succeeded, so the helper reported its result"
    );
}

#[tokio::test(start_paused = true)]
#[should_panic(expected = "after 4 of 4 attempts")]
async fn a_daemon_that_never_answers_stops_after_the_last_attempt() {
    // Every attempt is transient, so only the bound ends this.
    retry_transient("probe", |_| async { Err::<u32, _>(busy()) }).await;
}

#[tokio::test(start_paused = true)]
#[should_panic(expected = "after 1 of 4 attempts")]
async fn a_broken_container_is_reported_on_the_first_attempt() {
    retry_transient("probe", |_| async { Err::<u32, _>(broken()) }).await;
}

/// The classification is a claim about `testcontainers`, so one test checks it against the
/// real daemon rather than against the variant name.
#[tokio::test]
#[ignore = "needs Docker"]
async fn a_real_readiness_timeout_is_one_of_the_transient_failures() {
    let error = support::containers::readiness_timeout_error().await;
    assert!(
        is_transient(&error),
        "a container that timed out waiting for readiness must be retried, got: {error}"
    );
}
