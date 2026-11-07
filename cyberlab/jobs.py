"""Bounded, deduplicated application jobs. Never accepts executable model output."""
from concurrent.futures import ThreadPoolExecutor
import logging
import threading


class BusyError(ValueError): pass


class Queue:
    def __init__(self,workers=2,capacity=6):
        self.executor=ThreadPoolExecutor(max_workers=workers,thread_name_prefix='cyberlab-job')
        self.slots=threading.BoundedSemaphore(capacity)
        self.lock=threading.Lock(); self.keys=set(); self.closed=False

    def submit(self,key,fn,*args):
        with self.lock:
            if self.closed or key in self.keys or not self.slots.acquire(blocking=False):
                raise BusyError('This action is already running or the work queue is full. Wait, then refresh the history.')
            self.keys.add(key)
        def release_slot():
            with self.lock:
                if key not in self.keys: return
                self.keys.discard(key)
            self.slots.release()
        def run():
            try: return fn(*args)
            except Exception as exc:
                # Do not log request values, response bodies or credential-bearing URLs.
                logging.getLogger('cyberlab').error('Background action failed: %s',type(exc).__name__)
            finally: release_slot()
        try:
            future=self.executor.submit(run)
            future.add_done_callback(lambda task: release_slot() if task.cancelled() else None)
            return future
        except RuntimeError:
            with self.lock: self.keys.discard(key)
            self.slots.release(); raise BusyError('Application is shutting down')

    def close(self):
        with self.lock: self.closed=True
        self.executor.shutdown(wait=True,cancel_futures=True)
