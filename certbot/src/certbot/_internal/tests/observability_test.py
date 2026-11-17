"""Tests for certbot._internal.observability."""
import copy
import sys
import threading
from types import SimpleNamespace
import time
from unittest import mock

import pytest

from acme import client as acme_client
from certbot import errors
from certbot._internal import client as client_module
from certbot._internal import hooks
from certbot._internal import observability
from certbot._internal import renewal
from certbot.compat import os
from certbot.tests import util as test_util


class FakeClock:
    """A deterministic monotonic clock for progress tests."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        """Advance the clock."""
        self.now += seconds


class TestProgress:
    """Tests for progress event generation."""

    def test_progress_can_exceed_three_callbacks(self):
        clock = FakeClock()
        events = []
        runtime = observability.Observability(
            observability.ObservabilityConfig(
                enabled=True,
                progress_callback=events.append,
                progress_interval=0.5,
            ),
            clock=clock,
        )

        with runtime.attempt("renew", total=5, unit="certificates") as task:
            for _ in range(5):
                clock.advance(0.5)
                task.advance(stage="renewing")

        assert len(events) >= 3
        current_values = [event.current for event in events]
        assert current_values == sorted(current_values)
        assert len(set(current_values)) >= 3
        assert events[-1].current == events[-1].total == 5
        assert any(event.eta_seconds is not None for event in events)

    def test_unknown_total_is_supported(self):
        events = []
        runtime = observability.Observability(observability.ObservabilityConfig(
            enabled=True,
            progress_callback=events.append,
            progress_interval=0,
        ))

        with runtime.attempt("streaming", total=None) as task:
            task.progress(1, stage="reading")
            task.progress(2, stage="reading")

        assert events[-1].total is None
        assert events[-1].percent is None
        assert events[-1].eta_seconds is None

    def test_attempts_do_not_share_state(self):
        events = []
        runtime = observability.Observability(observability.ObservabilityConfig(
            enabled=True,
            progress_callback=events.append,
            progress_interval=0,
        ))

        with runtime.attempt("renew", total=5) as first:
            first.progress(5, stage="first-attempt")
        first_events = list(events)

        with runtime.attempt("renew", total=5) as second:
            second.progress(1, stage="second-attempt")

        assert first.attempt == 1
        assert second.attempt == 2
        assert first.attempt_id != second.attempt_id
        assert first_events[-1].current == 5
        assert events[len(first_events)].current == 0
        assert events[-1].attempt == 2

    def test_superseded_attempt_does_not_emit_late_completion(self):
        events = []
        runtime = observability.Observability(observability.ObservabilityConfig(
            enabled=True,
            progress_callback=events.append,
            progress_interval=0,
        ))

        with runtime.attempt("obtain-certificate", total=4) as first:
            first.progress(3, stage="retrying")
            first.supersede()
            with runtime.attempt("obtain-certificate", total=4) as second:
                second.progress(4, stage="certificate-issued")

        assert events[-1].attempt == 2
        assert events[-1].current == 4
        assert all(event.attempt != 1 or event.current < 4 for event in events)

    def test_callback_failure_does_not_break_operation(self):
        callback_calls = []

        def broken_callback(event):
            callback_calls.append(event)
            raise RuntimeError("callback failed")

        runtime = observability.Observability(observability.ObservabilityConfig(
            enabled=True,
            progress_callback=broken_callback,
            progress_interval=0,
        ))

        with runtime.attempt("renew", total=2) as task:
            task.advance(stage="first")
            task.advance(stage="second")
            completed = True

        assert completed
        assert len(callback_calls) >= 2

    def test_callback_object_with_update_is_supported(self):
        received = []
        callback = SimpleNamespace(update=received.append)
        runtime = observability.Observability(observability.ObservabilityConfig(
            enabled=True,
            progress_callback=callback,
            progress_interval=0,
        ))

        with runtime.attempt("renew", total=1) as task:
            task.progress(1)

        assert received[-1].current == 1

    def test_context_size_is_bounded(self):
        events = []
        runtime = observability.Observability(observability.ObservabilityConfig(
            enabled=True,
            progress_callback=events.append,
            progress_interval=0,
        ))
        context = {f"key-{index}": index for index in range(100)}

        with runtime.attempt("renew", total=1, context=context) as task:
            task.progress(1, context={f"extra-{index}": index for index in range(100)})

        assert len(events[-1].context) <= 32

    def test_invalid_interval_has_clear_error(self):
        with pytest.raises(ValueError, match="progress_interval"):
            observability.ObservabilityConfig(enabled=True, progress_interval="not-a-number")

    def test_disabled_runtime_does_nothing(self):
        events = []
        runtime = observability.observability_from_config(mock.MagicMock())

        with runtime.attempt("renew", total=1) as task:
            task.progress(1)

        assert not runtime.enabled
        assert not events


class TestErrorEvent:
    """Tests for structured error reporting and redaction."""

    def test_structured_error_has_category_context_and_redaction(self):
        events = []
        runtime = observability.Observability(observability.ObservabilityConfig(
            enabled=True,
            error_callback=events.append,
            progress_interval=0,
        ))
        error = errors.ConfigurationError(
            "bad input at /srv/certs token=supersecret "
            "https://user:password@example.test/path"
        )

        with pytest.raises(errors.ConfigurationError):
            with runtime.attempt(
                    "renew",
                    total=1,
                    context={
                        "lineage": "example.test",
                        "api_token": "secret-value",
                        "renewal_file": "/etc/letsencrypt/renewal/x.conf",
                    }):
                raise error

        event = events[-1]
        assert event.category == observability.ErrorCategory.CONFIGURATION
        assert event.context["lineage"] == "example.test"
        assert event.context["api_token"] == "[REDACTED]"
        assert event.context["renewal_file"] == "/etc/letsencrypt/renewal/x.conf"
        assert "supersecret" not in event.message
        assert "user:password@" not in event.message
        assert "/srv/certs" in event.message

    def test_cancellation_is_not_reported_as_failure(self):
        events = []
        token = observability.CancellationToken()
        runtime = observability.Observability(observability.ObservabilityConfig(
            enabled=True,
            error_callback=events.append,
            cancel_token=token,
            progress_interval=0,
        ))

        with pytest.raises(errors.TaskCancelled):
            with runtime.attempt("renew", total=1):
                token.cancel("caller requested cancellation")

        assert events[-1].category == observability.ErrorCategory.CANCELLED
        assert events[-1].cancelled


class TestCancellation:
    """Tests for prompt, clean cancellation."""

    def test_wait_is_interrupted_without_waiting_for_timeout(self):
        token = observability.CancellationToken()
        config = SimpleNamespace(cancel_token=token)
        timer = threading.Timer(0.1, token.cancel, kwargs={"reason": "stop"})
        started = time.monotonic()
        timer.start()
        try:
            with pytest.raises(errors.TaskCancelled, match="stop"):
                observability.wait_or_cancel(30, config)
        finally:
            timer.cancel()
        assert time.monotonic() - started < 2

    def test_acme_poll_wait_is_interrupted(self):
        token = observability.CancellationToken()
        config = SimpleNamespace(cancel_token=token)
        acme = acme_client.ClientV2(mock.MagicMock(), mock.MagicMock())
        client_module._attach_cancellable_polling(acme, config)
        timer = threading.Timer(0.1, token.cancel, kwargs={"reason": "stop polling"})
        timer.start()
        try:
            with pytest.raises(errors.TaskCancelled, match="stop polling"):
                acme._sleep(30)
        finally:
            timer.cancel()

    def test_older_acme_library_degrades_with_warning(self):
        token = observability.CancellationToken()
        config = SimpleNamespace(cancel_token=token)
        older_client = SimpleNamespace()

        with mock.patch.object(client_module.logger, "warning") as warning:
            client_module._attach_cancellable_polling(older_client, config)

        warning.assert_called_once()
        assert "does not support cancellation-aware polling" in warning.call_args[0][0]
        assert not hasattr(older_client, "set_poll_sleep")

    @pytest.mark.skipif(os.name == "nt", reason="Process-group assertions are POSIX-specific")
    def test_subprocess_and_descendants_are_terminated(self, tmp_path):
        token = observability.CancellationToken()
        runtime = observability.Observability(observability.ObservabilityConfig(
            enabled=True,
            cancel_token=token,
            progress_interval=0,
        ))
        pid_file = tmp_path / "pids"
        script = (
            "import os, subprocess, sys, time; "
            "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
            "open(sys.argv[1], 'w').write(f'{os.getpid()} {child.pid}'); "
            "time.sleep(30)"
        )
        timer = threading.Timer(0.5, token.cancel, kwargs={"reason": "stop hook"})

        with pytest.raises(errors.TaskCancelled):
            with runtime.attempt("hook", total=1):
                timer.start()
                try:
                    observability.run_process(
                        [sys.executable, "-c", script, str(pid_file)], shell=False)
                finally:
                    timer.cancel()

        assert pid_file.exists()
        parent_pid, child_pid = map(int, pid_file.read_text().split())
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                os.killpg(parent_pid, 0)
            except ProcessLookupError:
                break
            threading.Event().wait(0.05)
        else:
            pytest.fail("subprocess group was left running")

        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            pass
        else:
            pytest.fail("descendant process was left running")


class TestRenewalIntegration(test_util.ConfigTestCase):
    """Tests observability integration in the renewal loop."""

    @test_util.patch_display_util()
    def test_parse_failure_emits_structured_error_without_changing_result(self, unused_mock):
        progress_events = []
        error_events = []
        token = observability.CancellationToken()
        self.config.observability = observability.ObservabilityConfig(
            enabled=True,
            progress_callback=progress_events.append,
            error_callback=error_events.append,
            cancel_token=token,
            progress_interval=0,
        )
        renewal_file = "/etc/letsencrypt/renewal/example.test.conf"

        with mock.patch.object(renewal.storage, "renewal_conf_files",
                               return_value=[renewal_file]):
            with mock.patch.object(renewal.storage, "lineagename_for_filename",
                                   return_value="example.test"):
                with mock.patch.object(
                        renewal, "reconstitute",
                        side_effect=errors.ConfigurationError("invalid renewal input")):
                    with pytest.raises(errors.Error, match="1 parse failure"):
                        renewal.handle_renewal_request(self.config)

        parse_errors = [
            event for event in error_events
            if event.category == observability.ErrorCategory.CONFIGURATION
        ]
        assert parse_errors
        assert parse_errors[-1].context["lineage"] == "example.test"
        assert progress_events
        assert progress_events[-1].current == progress_events[-1].total == 3

    def test_observation_objects_survive_config_deepcopy(self):
        token = observability.CancellationToken()
        config = observability.ObservabilityConfig(enabled=True, cancel_token=token)
        runtime = observability.Observability(config)

        assert copy.deepcopy(token) is token
        assert copy.deepcopy(config) is config
        assert copy.deepcopy(runtime) is runtime


class TestConcurrency:
    """Tests attempt isolation under concurrent callers."""

    def test_concurrent_attempts_have_unique_state(self):
        events = []
        lock = threading.Lock()
        barrier = threading.Barrier(4)
        runtime = observability.Observability(observability.ObservabilityConfig(
            enabled=True,
            progress_callback=lambda event: _append_threadsafe(events, lock, event),
            progress_interval=0,
        ))

        def worker():
            barrier.wait()
            with runtime.attempt("renew", total=1) as task:
                task.progress(1, stage="complete")

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        assert all(not thread.is_alive() for thread in threads)
        attempts = {event.attempt_id: event.attempt for event in events}
        assert len(attempts) == 4
        assert sorted(attempts.values()) == [1, 2, 3, 4]


class TestHookIntegration:
    """Tests structured hook reporting."""

    def test_failed_hook_reports_process_error_without_raising(self):
        error_events = []
        runtime = observability.Observability(observability.ObservabilityConfig(
            enabled=True,
            error_callback=error_events.append,
            progress_interval=0,
        ))

        with runtime.attempt("hook", total=1):
            with mock.patch.object(
                    hooks.misc, "execute_command_status", return_value=(1, "failure", "")):
                with mock.patch.object(hooks.display_ops, "report_executed_command"):
                    result = hooks._run_hook("deploy-hook", "false")

        assert result == "failure"
        assert error_events[-1].category == observability.ErrorCategory.PROCESS
        assert error_events[-1].context["hook"] == "deploy-hook"
        assert error_events[-1].context["exit_code"] == "1"


def _append_threadsafe(items, lock, item):
    with lock:
        items.append(item)


class TestDisabledByDefault:
    """Tests that the new path is opt-in."""

    def test_no_config_means_disabled(self):
        runtime = observability.observability_from_config(None)
        assert not runtime.enabled

    def test_legacy_attributes_enable_observation(self):
        events = []
        config = SimpleNamespace(progress_callback=events.append)
        runtime = observability.observability_from_config(config)

        with runtime.attempt("renew", total=1) as task:
            task.progress(1)

        assert runtime.enabled
        assert events[-1].current == 1

    def test_threading_event_cancel_alias_is_supported(self):
        cancel_event = threading.Event()
        runtime = observability.observability_from_config(
            SimpleNamespace(cancel_event=cancel_event))
        cancel_event.set()

        with pytest.raises(errors.TaskCancelled):
            runtime.check_cancelled()


def test_configure_default_is_process_wide_and_resettable():
    runtime = observability.configure_default(progress_callback=lambda event: None)
    try:
        assert runtime.enabled
        assert observability.observability_from_config(None).enabled
    finally:
        observability.reset_default()
    assert not observability.observability_from_config(None).enabled


if __name__ == "__main__":  # pragma: no cover
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))
