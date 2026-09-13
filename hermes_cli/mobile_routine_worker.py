"""Host-owned dispatcher for mobile routine reservations.

The mobile API only creates a durable, fenced reservation.  This module is the explicit seam for
the host to supply an existing routine executor.  It deliberately has no command, shell, prompt,
path, provider, or credential resolution logic: those remain inside the injected host callback.
Mobile input is copied into a bounded in-memory JSON value and is never persisted by the worker.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import logging
import queue
import threading
from typing import Any, Callable, Protocol

from hermes_cli.mobile_routines import (
    MobileRoutineService,
    RoutineConflict,
    RoutineDefinition,
    RoutineError,
    RoutineLeaseExpired,
    RoutineNotFound,
    RoutineRun,
)


_LOGGER = logging.getLogger(__name__)
_MAX_INPUT_BYTES = 256_000
_QUEUE_SENTINEL = object()


class HostRoutineExecutor(Protocol):
    """A host-owned executor; implementations must resolve the routine server-side."""

    def __call__(
        self,
        *,
        routine: RoutineDefinition,
        profile_name: str,
        input: Any,
        run_id: str,
        actor_id: str,
    ) -> Any: ...


class RoutineExecutionRejected(RuntimeError):
    """The trusted host executor rejected work without an uncertain side effect."""


class RoutineWorkerUnavailable(RuntimeError):
    """A reservation could not be handed to the host worker."""


@dataclass(frozen=True, slots=True)
class RoutineDispatch:
    run: RoutineRun
    routine: RoutineDefinition
    profile_name: str
    input: Any


def _copy_json(value: Any) -> Any:
    """Validate and copy bounded data without permitting NaN or executable objects."""

    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        if len(encoded.encode("utf-8")) > _MAX_INPUT_BYTES:
            raise ValueError("routine input is too large")
        return json.loads(encoded)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("routine input must be bounded JSON data") from exc


class MobileRoutineWorker:
    """Serialize host-owned routine execution and fence every terminal write.

    The worker is intentionally opt-in.  A mobile listener without an injected executor must
    reject ``run`` rather than leave a reservation pending forever.  One worker thread is used by
    default so a host can apply its own concurrency policy inside the executor and so a close can
    make a deterministic decision about the one in-flight side effect.
    """

    def __init__(
        self,
        service: MobileRoutineService,
        executor: HostRoutineExecutor,
        *,
        queue_size: int = 32,
        lease_renew_interval: float | None = None,
        close_timeout: float = 1.0,
        on_terminal: Callable[[RoutineRun], None] | None = None,
    ) -> None:
        if not isinstance(service, MobileRoutineService):
            raise TypeError("service must be a MobileRoutineService")
        if not callable(executor):
            raise TypeError("executor must be callable")
        if not isinstance(queue_size, int) or not 1 <= queue_size <= 256:
            raise ValueError("queue_size is invalid")
        if lease_renew_interval is None:
            lease_renew_interval = min(30.0, max(0.1, service.lease_seconds / 3.0))
        if not isinstance(lease_renew_interval, (int, float)) or lease_renew_interval <= 0:
            raise ValueError("lease_renew_interval is invalid")
        if not isinstance(close_timeout, (int, float)) or close_timeout < 0:
            raise ValueError("close_timeout is invalid")
        self._service = service
        self._executor = executor
        self._queue: queue.Queue[RoutineDispatch | object] = queue.Queue(maxsize=queue_size)
        self._renew_interval = float(lease_renew_interval)
        self._close_timeout = float(close_timeout)
        self._on_terminal = on_terminal
        self._stop = threading.Event()
        self._started = threading.Event()
        self._closed = False
        self._state_lock = threading.RLock()
        self._active: RoutineDispatch | None = None
        self._thread = threading.Thread(
            target=self._run,
            name="hermes-mobile-routine-worker",
            daemon=True,
        )
        self._thread.start()
        self._started.wait(timeout=1.0)
        if not self._started.is_set():
            raise RuntimeError("mobile routine worker failed to start")

    @property
    def active_run_id(self) -> str | None:
        with self._state_lock:
            return None if self._active is None else self._active.run.run_id

    def submit(
        self,
        run: RoutineRun,
        *,
        profile_name: str,
        routine: RoutineDefinition,
        input: Any,
    ) -> None:
        """Hand one just-reserved run to the worker without persisting input."""

        if not isinstance(run, RoutineRun) or run.status != "pending":
            raise RoutineWorkerUnavailable("routine reservation is not pending")
        if not isinstance(routine, RoutineDefinition) or routine.routine_id != run.routine_id:
            raise RoutineWorkerUnavailable("routine definition does not match reservation")
        if routine.profile_id != run.profile_id or not isinstance(profile_name, str) or not profile_name:
            raise RoutineWorkerUnavailable("routine profile does not match reservation")
        copied_input = _copy_json(input)
        dispatch = RoutineDispatch(run, routine, profile_name, copied_input)
        with self._state_lock:
            if self._closed:
                raise RoutineWorkerUnavailable("mobile routine worker is closed")
            try:
                self._queue.put_nowait(dispatch)
            except queue.Full as exc:
                raise RoutineWorkerUnavailable("mobile routine worker queue is full") from exc

    def close(self) -> None:
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
        self._stop.set()
        # Wake a worker blocked on an empty queue.  A running executor is not force-killed.
        try:
            self._queue.put_nowait(_QUEUE_SENTINEL)
        except queue.Full:
            pass
        self._thread.join(timeout=self._close_timeout)
        self._drain_uncertain()
        with self._state_lock:
            active = self._active
        if active is not None:
            self._mark_uncertain(active.run.run_id, "worker_shutdown")

    def __enter__(self) -> "MobileRoutineWorker":
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _tb: Any) -> None:
        self.close()

    def _run(self) -> None:
        self._started.set()
        while True:
            try:
                item = self._queue.get(timeout=0.25)
            except queue.Empty:
                if self._stop.is_set():
                    return
                continue
            try:
                if item is _QUEUE_SENTINEL:
                    return
                assert isinstance(item, RoutineDispatch)
                with self._state_lock:
                    self._active = item
                self._execute(item)
            finally:
                with self._state_lock:
                    self._active = None
                self._queue.task_done()

    def _execute(self, dispatch: RoutineDispatch) -> None:
        run = dispatch.run
        try:
            # Claim the external-executor boundary atomically.  A queued
            # reservation can still be cancelled cleanly; once this marker is
            # written, cancellation fences the run as indeterminate so a
            # late executor result can never be reported as successful.
            run = self._service.begin_execution(
                run.run_id,
                actor_id=run.actor_id,
                execution_generation=run.execution_generation,
                fence_token=run.fence_token,
            )
        except RoutineNotFound:
            # A terminal/removed run is not worker-owned anymore.
            return
        except RoutineConflict:
            # Cancellation (or another worker) won the durable fence before
            # this worker reached the external side-effect boundary.
            return
        except RoutineError:
            # A durable read failure leaves the outcome unknown.  Never leave a
            # pending reservation behind for a future worker to replay.
            self._mark_uncertain(run.run_id, "worker_read_failure", run=run)
            return
        except Exception:
            self._mark_uncertain(run.run_id, "worker_read_failure", run=run)
            return

        renew_stop = threading.Event()
        renew_failed = threading.Event()

        def renew() -> None:
            while not renew_stop.wait(self._renew_interval):
                try:
                    self._service.renew(
                        run.run_id,
                        actor_id=run.actor_id,
                        execution_generation=run.execution_generation,
                        fence_token=run.fence_token,
                    )
                except RoutineError:
                    renew_failed.set()
                    return
                except Exception:
                    # A storage/host failure makes completion uncertain; do not retry the side effect.
                    renew_failed.set()
                    return

        renew_thread = threading.Thread(
            target=renew,
            name="hermes-mobile-routine-lease",
            daemon=True,
        )
        renew_thread.start()
        try:
            try:
                result = self._executor(
                    routine=dispatch.routine,
                    profile_name=dispatch.profile_name,
                    input=dispatch.input,
                    run_id=run.run_id,
                    actor_id=run.actor_id,
                )
            except RoutineExecutionRejected:
                try:
                    terminal = self._service.fail(
                        run.run_id,
                        actor_id=run.actor_id,
                        result={"error": "routine_execution_rejected"},
                        execution_generation=run.execution_generation,
                        fence_token=run.fence_token,
                    )
                except RoutineError:
                    self._mark_uncertain(run.run_id, "terminal_fence_lost", run=run)
                else:
                    self._notify_terminal(terminal)
                return
            except Exception:
                self._mark_uncertain(run.run_id, "executor_failure", run=run)
                return
            if renew_failed.is_set():
                self._mark_uncertain(run.run_id, "lease_lost", run=run)
                return
            try:
                terminal = self._service.complete(
                    run.run_id,
                    actor_id=run.actor_id,
                    result=result,
                    execution_generation=run.execution_generation,
                    fence_token=run.fence_token,
                )
            except (RoutineConflict, RoutineLeaseExpired, RoutineError, ValueError, TypeError):
                self._mark_uncertain(run.run_id, "terminal_fence_lost", run=run)
                return
            self._notify_terminal(terminal)
        finally:
            renew_stop.set()
            renew_thread.join(timeout=1.0)

    def _drain_uncertain(self) -> None:
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                return
            try:
                if isinstance(item, RoutineDispatch):
                    self._mark_uncertain(item.run.run_id, "worker_shutdown", run=item.run)
            finally:
                self._queue.task_done()

    def _mark_uncertain(self, run_id: str, reason: str, *, run: RoutineRun | None = None) -> None:
        try:
            terminal = self._service.mark_indeterminate(run_id, reason=reason)
        except RoutineError:
            return
        except Exception:
            _LOGGER.warning("Mobile routine uncertainty write failed (%s)", type(reason).__name__)
            return
        self._notify_terminal(terminal)

    def _notify_terminal(self, value: RoutineRun) -> None:
        if self._on_terminal is None:
            return
        try:
            self._on_terminal(value)
        except Exception:
            _LOGGER.warning("Mobile routine terminal callback failed (%s)", type(value).__name__)
