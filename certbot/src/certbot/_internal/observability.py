"""Runtime observability for long-running Certbot operations.

The functionality in this module is disabled unless it is explicitly configured.
This keeps the existing human-oriented logging, function signatures and return
values unchanged.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from dataclasses import field
from enum import Enum
import logging
import math
import re
import signal
import subprocess
import threading
import time
from typing import Any
from typing import Callable
from typing import Iterator
from typing import Literal
from typing import Mapping
from typing import Optional
from typing import Union
from uuid import uuid4

from certbot import errors
from certbot.compat import os

logger = logging.getLogger(__name__)

ProgressCallback = Callable[["ProgressEvent"], Any]
ErrorCallback = Callable[["ErrorEvent"], Any]


class ErrorCategory(str, Enum):
    """Stable categories for failures reported by Certbot."""

    CANCELLED = "cancelled"
    CONFIGURATION = "configuration"
    AUTHORIZATION = "authorization"
    AUTHENTICATION = "authentication"
    ACME = "acme"
    NETWORK = "network"
    PLUGIN = "plugin"
    PROCESS = "process"
    STORAGE = "storage"
    LOCK = "lock"
    IO = "io"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ProgressEvent:
    """An immutable snapshot of progress for one operation attempt."""

    operation: str
    current: int
    total: Optional[int]
    attempt: int
    attempt_id: str
    stage: Optional[str] = None
    unit: str = "steps"
    message: Optional[str] = None
    elapsed_seconds: float = 0.0
    eta_seconds: Optional[float] = None
    sequence: int = 0
    context: Mapping[str, str] = field(default_factory=dict)

    @property
    def percent(self) -> Optional[float]:
        """Return completion percentage, or ``None`` when total is unknown."""
        if self.total is None or self.total <= 0:
            return None
        return min(100.0, max(0.0, self.current * 100.0 / self.total))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "type": "progress",
            "operation": self.operation,
            "current": self.current,
            "total": self.total,
            "percent": self.percent,
            "attempt": self.attempt,
            "attempt_id": self.attempt_id,
            "stage": self.stage,
            "unit": self.unit,
            "message": self.message,
            "elapsed_seconds": self.elapsed_seconds,
            "eta_seconds": self.eta_seconds,
            "sequence": self.sequence,
            "context": dict(self.context),
        }


@dataclass(frozen=True)
class ErrorEvent:
    """A structured failure with bounded, redacted context."""

    operation: str
    category: ErrorCategory
    message: str
    attempt: int
    attempt_id: str
    exception_type: Optional[str] = None
    context: Mapping[str, str] = field(default_factory=dict)
    sequence: int = 0

    @property
    def cancelled(self) -> bool:
        """Whether this event represents cancellation rather than failure."""
        return self.category == ErrorCategory.CANCELLED

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "type": "error",
            "operation": self.operation,
            "category": self.category.value,
            "message": self.message,
            "attempt": self.attempt,
            "attempt_id": self.attempt_id,
            "exception_type": self.exception_type,
            "context": dict(self.context),
            "sequence": self.sequence,
            "cancelled": self.cancelled,
        }


class CancellationToken:
    """A thread-safe cooperative cancellation token."""

    def __init__(self, event: Optional[threading.Event] = None) -> None:
        self._event = event or threading.Event()
        self._reason: Optional[str] = None
        self._lock = threading.Lock()

    @property
    def reason(self) -> Optional[str]:
        """The reason supplied to :meth:`cancel`, if any."""
        with self._lock:
            return self._reason

    def cancel(self, reason: Optional[str] = None) -> None:
        """Request cancellation. Calling this more than once is safe."""
        with self._lock:
            if self._reason is None and reason is not None:
                self._reason = reason
            self._event.set()

    def is_cancelled(self) -> bool:
        """Return whether cancellation has been requested."""
        return self._event.is_set()

    @property
    def cancelled(self) -> bool:
        """Alias for :meth:`is_cancelled`."""
        return self.is_cancelled()

    def wait(self, timeout: Optional[float] = None) -> bool:
        """Wait until cancellation or timeout, returning the cancellation state."""
        return self._event.wait(timeout)

    def raise_if_cancelled(self) -> None:
        """Raise :class:`certbot.errors.TaskCancelled` if cancellation was requested."""
        if self.is_cancelled():
            raise errors.TaskCancelled(self.reason or "Certbot operation cancelled.")

    def __deepcopy__(self, memo: dict[int, Any]) -> "CancellationToken":
        """Tokens are shared across copied Certbot configurations."""
        return self


@dataclass
class ObservabilityConfig:
    """Configuration for optional runtime observations.

    ``enabled`` defaults to ``False``. If a callback or cancellation token is
    supplied by an older integration, :func:`observability_from_config` will
    enable observation automatically.
    """

    enabled: bool = False
    progress_callback: Optional[ProgressCallback] = None
    error_callback: Optional[ErrorCallback] = None
    cancel_token: Optional[CancellationToken] = None
    progress_interval: float = 1.0

    def __post_init__(self) -> None:
        try:
            interval = float(self.progress_interval)
        except (TypeError, ValueError) as error:
            raise ValueError(
                "progress_interval must be a non-negative number of seconds") from error
        if not math.isfinite(interval) or interval < 0:
            raise ValueError(
                "progress_interval must be a non-negative finite number of seconds")
        self.progress_interval = interval

    def __deepcopy__(self, memo: dict[int, Any]) -> "ObservabilityConfig":
        """Keep callbacks and tokens shared when Certbot copies a config."""
        return self


_SENSITIVE_KEY = re.compile(
    r"(?:authorization|cookie|credential|eab|hmac|pass(?:word|wd)?|private[_-]?key|"
    r"secret|token|api[_-]?key)",
    re.IGNORECASE,
)
_URL_CREDENTIALS = re.compile(r"(\b[a-z][a-z0-9+.-]*://)[^/@\s]+@", re.IGNORECASE)
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)\b(authorization|cookie|credential|eab|hmac|pass(?:word|wd)?|private[_-]?key|"
    r"secret|token|api[_-]?key)\s*[=:]\s*[^\s,;]+",
)
_BEARER_TOKEN = re.compile(r"(?i)\b(bearer)\s+\S+")
_MAX_CONTEXT_VALUE = 512
_MAX_CONTEXT_ITEMS = 32
_MAX_ERROR_MESSAGE = 1000


def _redact_text(value: str, max_length: int = _MAX_CONTEXT_VALUE) -> str:
    value = _URL_CREDENTIALS.sub(r"\1[REDACTED]@", value)
    value = _CREDENTIAL_ASSIGNMENT.sub(r"\1=[REDACTED]", value)
    value = _BEARER_TOKEN.sub(r"\1 [REDACTED]", value)
    if len(value) > max_length:
        value = value[:max_length - 3] + "..."
    return value


def redact_context(context: Optional[Mapping[str, Any]]) -> dict[str, str]:
    """Return bounded context with credential-like values removed.

    Paths are retained because Certbot's existing logs already include paths.
    Values whose key suggests a credential are always replaced.
    """
    if not context:
        return {}
    redacted: dict[str, str] = {}
    for key, value in context.items():
        if len(redacted) >= _MAX_CONTEXT_ITEMS:
            break
        key_str = str(key)
        if _SENSITIVE_KEY.search(key_str):
            redacted[key_str] = "[REDACTED]"
        elif isinstance(value, bytes):
            redacted[key_str] = f"<{len(value)} bytes>"
        elif isinstance(value, (str, int, float, bool)) or value is None:
            redacted[key_str] = _redact_text(str(value))
        else:
            redacted[key_str] = f"<{type(value).__name__}>"
    return redacted


def _bounded_update(target: dict[str, str], updates: Mapping[str, str]) -> None:
    for key, value in updates.items():
        if key in target or len(target) < _MAX_CONTEXT_ITEMS:
            target[key] = value


def _classify_exception(error: BaseException) -> ErrorCategory:
    if isinstance(error, errors.TaskCancelled):
        return ErrorCategory.CANCELLED
    if isinstance(error, errors.HookCommandNotFound):
        return ErrorCategory.PROCESS
    if isinstance(error, errors.SubprocessError):
        return ErrorCategory.PROCESS
    if isinstance(error, errors.FailedChallenges):
        return ErrorCategory.AUTHORIZATION
    if isinstance(error, errors.AuthorizationError):
        return ErrorCategory.AUTHORIZATION
    if isinstance(error, errors.AccountNotFound):
        return ErrorCategory.AUTHENTICATION
    if isinstance(error, errors.AccountStorageError):
        return ErrorCategory.STORAGE
    if isinstance(error, errors.PluginError):
        return ErrorCategory.PLUGIN
    if isinstance(error, errors.PluginSelectionError):
        return ErrorCategory.PLUGIN
    if isinstance(error, errors.CertStorageError):
        return ErrorCategory.STORAGE
    if isinstance(error, errors.ConfigurationError):
        return ErrorCategory.CONFIGURATION
    if isinstance(error, errors.LockError):
        return ErrorCategory.LOCK
    if isinstance(error, (TimeoutError, ConnectionError)):
        return ErrorCategory.NETWORK
    if isinstance(error, OSError):
        return ErrorCategory.IO
    try:
        from acme import errors as acme_errors
        if isinstance(error, acme_errors.Error):
            return ErrorCategory.ACME
    except ImportError:  # pragma: no cover - acme is a Certbot dependency
        pass
    return ErrorCategory.UNKNOWN


def _redact_error_message(error: BaseException) -> str:
    message = str(error).strip()
    if not message:
        message = type(error).__name__
    return _redact_text(message, _MAX_ERROR_MESSAGE)


def _callback_event(callback: Optional[Callable[..., Any]], event: Any, event_name: str) -> None:
    if callback is None:
        return
    try:
        if callable(callback):
            callback(event)
        elif hasattr(callback, "update"):
            callback.update(event)
        else:
            raise TypeError(
                f"{event_name} callback must be callable or expose update(event)")
    except Exception:  # pylint: disable=broad-except
        logger.exception("%s callback failed; continuing the Certbot operation", event_name)


class TaskObservation:
    """State for one operation attempt.

    Instances are created through :class:`Observability`. A new attempt always
    has its own counters, timestamps and immutable event objects, so a retry
    cannot overwrite the progress of a previous attempt.
    """

    def __init__(self, config: ObservabilityConfig, operation: str, total: Optional[int],
                 attempt: int, stage: Optional[str] = None, unit: str = "steps",
                 context: Optional[Mapping[str, Any]] = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.config = config
        self.operation = operation
        self.total = total
        self.attempt = attempt
        self.unit = unit
        self.attempt_id = f"{operation}:{attempt}:{uuid4().hex[:12]}"
        self.current = 0
        self.stage = stage
        self.context = redact_context(context)
        self._clock = clock
        self._started_at = self._clock()
        self._last_emit_at: Optional[float] = None
        self._sequence = 0
        self._closed = False
        self._superseded = False
        self._context_token: Any = None

    @property
    def enabled(self) -> bool:
        """Whether observations are enabled."""
        return self.config.enabled

    def check_cancelled(self) -> None:
        """Raise if this attempt has been cancelled."""
        if _CANCELLATION_SUSPENDED.get():
            return
        token = self.config.cancel_token
        if token is not None:
            token.raise_if_cancelled()

    def _eta(self, now: float, current: int) -> Optional[float]:
        if self.total is None or current <= 0 or current >= self.total:
            return None
        elapsed = now - self._started_at
        if elapsed <= 0:
            return None
        return elapsed / current * (self.total - current)

    def progress(self, current: Optional[int] = None, stage: Optional[str] = None,
                 total: Optional[int] = None, message: Optional[str] = None,
                 force: bool = False, context: Optional[Mapping[str, Any]] = None,
                 ) -> Optional[ProgressEvent]:
        """Update progress subject to the configured callback interval.

        Progress values are monotonic within one attempt. Callback failures are
        logged and never propagated to the operation.
        """
        self.check_cancelled()
        if not self.enabled:
            return None

        now = self._clock()
        if current is not None:
            self.current = max(self.current, current)
        if total is not None:
            self.total = max(0, total)
        if stage is not None:
            self.stage = stage
        if context:
            _bounded_update(self.context, redact_context(context))

        interval = self.config.progress_interval
        due = (force or interval == 0 or self._last_emit_at is None
               or now - self._last_emit_at >= interval)
        if not due:
            return None

        self._sequence += 1
        event = ProgressEvent(
            operation=self.operation,
            current=self.current,
            total=self.total,
            attempt=self.attempt,
            attempt_id=self.attempt_id,
            stage=self.stage,
            unit=self.unit,
            message=_redact_text(message) if message else None,
            elapsed_seconds=max(0.0, now - self._started_at),
            eta_seconds=self._eta(now, self.current),
            sequence=self._sequence,
            context=dict(self.context),
        )
        self._last_emit_at = now
        _callback_event(self.config.progress_callback, event, "progress")
        return event

    def advance(self, amount: int = 1, **kwargs: Any) -> Optional[ProgressEvent]:
        """Advance progress by ``amount`` and emit when due."""
        return self.progress(self.current + amount, **kwargs)

    def supersede(self) -> None:
        """Mark this attempt as handed off to a newer attempt.

        A superseded attempt does not emit a late completion update when its
        context exits, preventing it from appearing after the newer attempt.
        """
        self._superseded = True

    def error(self, error: BaseException, category: Optional[ErrorCategory] = None,
              context: Optional[Mapping[str, Any]] = None) -> ErrorEvent:
        """Report a structured error event without suppressing the exception."""
        if category is None:
            category = _classify_exception(error)
        merged_context = dict(self.context)
        _bounded_update(merged_context, redact_context(context))
        self._sequence += 1
        event = ErrorEvent(
            operation=self.operation,
            category=category,
            message=_redact_error_message(error),
            attempt=self.attempt,
            attempt_id=self.attempt_id,
            exception_type=type(error).__name__,
            context=merged_context,
            sequence=self._sequence,
        )
        _callback_event(self.config.error_callback, event, "error")
        return event

    def __enter__(self) -> "TaskObservation":
        self.check_cancelled()
        if self.enabled:
            logger.info("Starting observed operation %s (attempt %d, total=%s)",
                        self.operation, self.attempt, self.total)
            self.progress(self.current, stage=self.stage, force=True)
        self._context_token = _ACTIVE_OBSERVATION.set(self)
        return self

    def __exit__(self, exc_type: Any, exc_value: Optional[BaseException],
                 traceback: Any) -> Literal[False]:
        try:
            if self._superseded:
                if self.enabled:
                    logger.info("Handed off observed operation %s (attempt %d)",
                                self.operation, self.attempt)
            elif exc_value is not None:
                if isinstance(exc_value, errors.TaskCancelled):
                    self.error(exc_value, category=ErrorCategory.CANCELLED)
                    if self.enabled:
                        logger.info("Cancelled observed operation %s (attempt %d)",
                                    self.operation, self.attempt)
                else:
                    self.error(exc_value)
                    if self.enabled:
                        logger.error("Failed observed operation %s (attempt %d, category=%s)",
                                     self.operation, self.attempt,
                                     _classify_exception(exc_value).value)
            else:
                try:
                    self.progress(self.total if self.total is not None else self.current,
                                  stage="complete", force=True)
                except errors.TaskCancelled as cancellation:
                    self.error(cancellation, category=ErrorCategory.CANCELLED)
                    if self.enabled:
                        logger.info("Cancelled observed operation %s (attempt %d)",
                                    self.operation, self.attempt)
                    raise
                else:
                    if self.enabled:
                        logger.info("Finished observed operation %s (attempt %d) in %.3fs",
                                    self.operation, self.attempt,
                                    self._clock() - self._started_at)
        finally:
            self._closed = True
            if self._context_token is not None:
                _ACTIVE_OBSERVATION.reset(self._context_token)
                self._context_token = None
        return False


class Observability:
    """Factory for independent, attempt-scoped observations."""

    def __init__(self, config: Optional[ObservabilityConfig] = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.config = config or ObservabilityConfig()
        self._attempts: dict[str, int] = {}
        self._lock = threading.Lock()
        self._clock = clock

    def __deepcopy__(self, memo: dict[int, Any]) -> "Observability":
        """Keep attempt state shared when Certbot copies a config."""
        return self

    @property
    def enabled(self) -> bool:
        """Whether observations are enabled."""
        return self.config.enabled

    def check_cancelled(self) -> None:
        """Raise if the configured cancellation token has been triggered."""
        if _CANCELLATION_SUSPENDED.get():
            return
        if self.config.cancel_token is not None:
            self.config.cancel_token.raise_if_cancelled()

    def cancel(self, reason: Optional[str] = None) -> None:
        """Request cancellation for this runtime's token, if one is configured."""
        if self.config.cancel_token is not None:
            self.config.cancel_token.cancel(reason)

    def is_cancelled(self) -> bool:
        """Return whether this runtime's cancellation token is set."""
        return (self.config.cancel_token is not None
                and self.config.cancel_token.is_cancelled())

    @contextmanager
    def attempt(self, operation: str, total: Optional[int] = None,
                stage: Optional[str] = None, unit: str = "steps",
                context: Optional[Mapping[str, Any]] = None,
                attempt: Optional[int] = None) -> Iterator[TaskObservation]:
        """Create an isolated observation context for one operation attempt."""
        if attempt is None:
            with self._lock:
                attempt = self._attempts.get(operation, 0) + 1
                self._attempts[operation] = attempt
        task = TaskObservation(
            self.config, operation, total, attempt, stage=stage, unit=unit, context=context,
            clock=self._clock)
        with task:
            yield task

    task = attempt

    def error(self, operation: str, error: BaseException, attempt: int = 0,
              context: Optional[Mapping[str, Any]] = None,
              category: Optional[ErrorCategory] = None) -> Optional[ErrorEvent]:
        """Emit a standalone structured error without opening a task context."""
        if not self.enabled:
            return None
        attempt_id = f"{operation}:{attempt}:standalone"
        merged_context = redact_context(context)
        event = ErrorEvent(
            operation=operation,
            category=category or _classify_exception(error),
            message=_redact_error_message(error),
            attempt=attempt,
            attempt_id=attempt_id,
            exception_type=type(error).__name__,
            context=merged_context,
        )
        _callback_event(self.config.error_callback, event, "error")
        return event


_ACTIVE_OBSERVATION: ContextVar[Optional[TaskObservation]] = ContextVar(
    "certbot_active_observation", default=None)
_CANCELLATION_SUSPENDED: ContextVar[bool] = ContextVar(
    "certbot_cancellation_suspended", default=False)
_DEFAULT_CONFIG = ObservabilityConfig()
_DEFAULT_LOCK = threading.Lock()


def active_observation() -> Optional[TaskObservation]:
    """Return the observation active in the current execution context."""
    return _ACTIVE_OBSERVATION.get()


def active_cancel_token() -> Optional[CancellationToken]:
    """Return the cancellation token for the active observation, if enabled."""
    if _CANCELLATION_SUSPENDED.get():
        return None
    observation = active_observation()
    if observation is None or not observation.enabled:
        return None
    return observation.config.cancel_token


def configure_default(config: Optional[Union[ObservabilityConfig, Observability]] = None,
                      **kwargs: Any) -> Observability:
    """Configure process-wide observation defaults.

    This is useful for embedders that call ``certbot.main.main()`` and cannot
    inject configuration after command-line parsing. The default remains
    disabled when this function is not called.
    """
    global _DEFAULT_CONFIG  # pylint: disable=global-statement
    if isinstance(config, Observability):
        runtime = config
        resolved = config.config
    else:
        if config is None and kwargs and "enabled" not in kwargs:
            kwargs["enabled"] = True
        resolved = config or ObservabilityConfig(**kwargs)
        if kwargs and config is not None:
            raise TypeError("pass either an ObservabilityConfig or keyword arguments")
        runtime = Observability(resolved)
    with _DEFAULT_LOCK:
        _DEFAULT_CONFIG = resolved
    return runtime


def reset_default() -> None:
    """Restore the default, disabled observation configuration."""
    global _DEFAULT_CONFIG  # pylint: disable=global-statement
    with _DEFAULT_LOCK:
        _DEFAULT_CONFIG = ObservabilityConfig()


def _explicit_config_value(config: Any, name: str) -> Any:
    namespace = getattr(config, "namespace", None)
    if namespace is not None and hasattr(namespace, "__dict__") and name in vars(namespace):
        return vars(namespace)[name]
    if isinstance(config, Mapping) and name in config:
        return config[name]
    try:
        values = vars(config)
    except TypeError:
        return None
    return values.get(name)


def observability_from_config(config: Any = None) -> Observability:
    """Build an observation runtime from a Certbot config or embedder object.

    Supported forms are an :class:`Observability` instance, an
    :class:`ObservabilityConfig`, a mapping, or attributes named
    ``observability``, ``progress_callback``, ``error_callback``,
    ``cancel_token`` and ``progress_interval``.
    """
    value = _explicit_config_value(config, "observability")
    if isinstance(value, Observability):
        return value
    if isinstance(value, ObservabilityConfig):
        return Observability(value)
    if isinstance(value, Mapping):
        return Observability(ObservabilityConfig(**value))

    progress_callback = _explicit_config_value(config, "progress_callback")
    error_callback = _explicit_config_value(config, "error_callback")
    cancel_token = _explicit_config_value(config, "cancel_token")
    cancel_event = _explicit_config_value(config, "cancel_event")
    progress_interval = _explicit_config_value(config, "progress_interval")
    enabled = _explicit_config_value(config, "observability_enabled")
    if cancel_token is None and cancel_event is not None:
        if isinstance(cancel_event, CancellationToken):
            cancel_token = cancel_event
        elif hasattr(cancel_event, "is_set") and hasattr(cancel_event, "wait"):
            cancel_token = CancellationToken(cancel_event)
    if any(item is not None for item in
           (progress_callback, error_callback, cancel_token, cancel_event,
            progress_interval, enabled)):
        return Observability(ObservabilityConfig(
            enabled=True if enabled is None else bool(enabled),
            progress_callback=progress_callback,
            error_callback=error_callback,
            cancel_token=cancel_token,
            progress_interval=1.0 if progress_interval is None else progress_interval,
        ))

    with _DEFAULT_LOCK:
        default = _DEFAULT_CONFIG
    return Observability(default)


def check_cancelled(config: Any = None) -> None:
    """Raise :class:`certbot.errors.TaskCancelled` if the config requests it."""
    if _CANCELLATION_SUSPENDED.get():
        return
    token = active_cancel_token()
    if token is None and config is not None:
        token = observability_from_config(config).config.cancel_token
    if token is not None:
        token.raise_if_cancelled()


def wait_or_cancel(seconds: float, config: Any = None) -> None:
    """Sleep for ``seconds`` but wake immediately when cancellation is requested."""
    if _CANCELLATION_SUSPENDED.get():
        time.sleep(seconds)
        return
    token = active_cancel_token()
    if token is None and config is not None:
        token = observability_from_config(config).config.cancel_token
    if token is None:
        time.sleep(seconds)
    elif token.wait(seconds):
        token.raise_if_cancelled()


def cancellation_requested(config: Any = None) -> bool:
    """Return whether cancellation is currently requested."""
    if _CANCELLATION_SUSPENDED.get():
        return False
    token = active_cancel_token()
    if token is not None:
        return token.is_cancelled()
    if config is None:
        return False
    token = observability_from_config(config).config.cancel_token
    return token is not None and token.is_cancelled()


@contextmanager
def suspend_cancellation() -> Iterator[None]:
    """Temporarily ignore cancellation while releasing resources."""
    token = _CANCELLATION_SUSPENDED.set(True)
    try:
        yield
    finally:
        _CANCELLATION_SUSPENDED.reset(token)


def _terminate_process_tree(process: subprocess.Popen) -> None:
    """Terminate a process and, on POSIX, its descendants."""
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":  # pragma: no cover - Windows has no process groups here
            process.terminate()
        else:
            os.killpg(process.pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        try:
            process.terminate()
        except OSError:
            pass


def _kill_process_tree(process: subprocess.Popen) -> None:
    """Forcibly kill a process and, on POSIX, its descendants."""
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":  # pragma: no cover - Windows has no process groups here
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except OSError:
            pass


def run_process(command: Union[str, list[str]], *, shell: bool,
                env: Optional[dict[str, str]] = None,
                poll_interval: float = 0.1) -> tuple[int, str, str]:
    """Run a subprocess while honoring the active cancellation token.

    The child is placed in its own process group on POSIX so cancellation also
    terminates descendants. The process is always waited for and reaped.
    """
    token = active_cancel_token()
    if token is None:
        raise RuntimeError("run_process called without an active cancellation token")
    token.raise_if_cancelled()

    kwargs: dict[str, Any] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "universal_newlines": True,
        "env": env,
    }
    if os.name != "nt":
        kwargs["start_new_session"] = True
    else:  # pragma: no cover - exercised on Windows
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

    process = subprocess.Popen(command, shell=shell, **kwargs)  # pylint: disable=consider-using-with
    try:
        while True:
            try:
                out, err = process.communicate(timeout=poll_interval)
                return process.returncode, err, out
            except subprocess.TimeoutExpired:
                if token.is_cancelled():
                    _terminate_process_tree(process)
                    try:
                        process.communicate(timeout=2)
                    except subprocess.TimeoutExpired:
                        _kill_process_tree(process)
                        process.communicate()
                    token.raise_if_cancelled()
    except BaseException:
        _terminate_process_tree(process)
        try:
            process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            _kill_process_tree(process)
            process.communicate()
        raise
    finally:
        if process.poll() is None:
            _kill_process_tree(process)
            process.wait()
