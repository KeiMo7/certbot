Runtime observability
=====================

Certbot can report machine-readable progress and structured errors while it is
obtaining or renewing certificates. This API is intended for applications that
embed Certbot or invoke it from an automation service.

The feature is disabled by default. When it is disabled, Certbot does not create
events, invoke callbacks, add logging records or change the return values of its
existing functions. The existing human-oriented step logs are unchanged.

Quick start
-----------

Configure a process-wide observer before calling :func:`certbot.main.main`:

.. code-block:: python

   import certbot.main
   import certbot.observability as observability

   token = observability.CancellationToken()
   events = []

   observability.configure_default(
       progress_callback=events.append,
       error_callback=events.append,
       cancel_token=token,
       progress_interval=1.0,
   )
   try:
       certbot.main.main(["renew", "--non-interactive"])
   finally:
       observability.reset_default()

Call ``token.cancel("deployment canceled")`` from another thread to request
cancellation. A cancelled task raises :class:`certbot.errors.TaskCancelled`
rather than being reported as an ordinary failure.

Embedders that already own a parsed ``NamespaceConfig`` can attach the
configuration directly:

.. code-block:: python

   from certbot._internal import renewal
   from certbot.observability import ObservabilityConfig

   config.observability = ObservabilityConfig(
       enabled=True,
       progress_callback=events.append,
       error_callback=events.append,
       progress_interval=1.0,
   )
   renewal.handle_renewal_request(config)

Progress events
---------------

Each callback receives an immutable :class:`certbot.observability.ProgressEvent`
with these fields:

``operation``
    Name of the operation, such as ``renew``, ``authorizations`` or
    ``obtain-certificate``.

``current`` and ``total``
    Completed and total work units. ``total`` is ``None`` when the input is
    streamed or otherwise has no known size. ``percent`` is then ``None``.

``eta_seconds``
    Estimated remaining seconds when both ``current`` and ``total`` are known.

``attempt`` and ``attempt_id``
    The attempt number and a unique identifier for that attempt. Every retry
    starts a new attempt with its own counters, timestamps and immutable events,
    so a later attempt cannot overwrite a previous attempt's state.

``stage`` and ``context``
    The current phase and a small, redacted context mapping. Context values are
    bounded. Credential-like keys and URL credentials are redacted. Filesystem
    paths are retained, matching Certbot's existing debug-log policy.

Progress callbacks are throttled by ``progress_interval`` (one second by
default when observation is enabled). The final progress update is always
emitted. The runtime keeps constant-size state and does not retain event
history.

Structured errors
-----------------

Failures are delivered as :class:`certbot.observability.ErrorEvent` objects.
The event contains a stable ``category``, the attempt identifier, the exception
type, a bounded redacted message and a context mapping. Categories include
``configuration``, ``authorization``, ``network``, ``plugin``, ``process``,
``storage``, ``lock``, ``io``, ``acme``, ``unknown`` and ``cancelled``.
Non-zero hook exits are reported as ``process`` errors while preserving
Certbot's existing behavior of continuing the renewal attempt.

Cancellation uses the ``cancelled`` category, and callers should distinguish it
from a failure with ``event.cancelled`` or by catching
:class:`certbot.errors.TaskCancelled`. Callback exceptions are logged and
ignored so a broken observer cannot stop certificate work.

Cancellation and cleanup
------------------------

Cancellation is checked before and after blocking phases, while waiting for
ACME authorization retries, and before and after subprocess execution. On POSIX,
observable hook and helper subprocesses run in their own process group; cancelling
terminates the group and waits for the direct child, preventing orphaned hook
processes. Cleanup hooks and authenticator cleanup temporarily ignore the
cancellation request so resources can be released.

A single underlying HTTP request can only be interrupted when the HTTP client
returns or its configured timeout expires. Certbot checks cancellation
immediately before and after that request. Deployments that require hard
interruption of an in-flight TLS connection should also enforce a transport
timeout at the surrounding service or proxy layer.

Concurrency
-----------

Observation does not create worker threads. Callbacks run synchronously on the
thread performing the Certbot operation, so the default disabled path has no
new concurrency behavior. If one ``Observability`` instance is shared by
multiple threads, attempt numbering is protected by a lock and every thread
gets a distinct attempt ID. A process-wide observer configured with
:func:`certbot.observability.configure_default` is shared by concurrent
operations, so a callback that writes to shared storage must itself be
thread-safe.

The concurrency behavior is covered by
``certbot/src/certbot/_internal/tests/observability_test.py``.
