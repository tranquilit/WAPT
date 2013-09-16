# -*- coding: utf-8 -*-

# This file is part of the Rocket Web Server
# Copyright (c) 2011 Timothy Farrell

# Import System Modules
import time
try:
    from concurrent.futures import Future, ThreadPoolExecutor
    from concurrent.futures.thread import _WorkItem
    has_futures = True
except ImportError:
    has_futures = False

    class Future:
        pass

    class ThreadPoolExecutor:
        pass

    class _WorkItem:
        pass


class WSGIFuture(Future):
    def __init__(self, f_dict, *args, **kwargs):
        Future.__init__(self, *args, **kwargs)

        self.timeout = None

        self._mem_dict = f_dict
        self._lifespan = 30
        self._name = None
        self._start_time = time.time()

    def set_running_or_notify_cancel(self):
        if time.time() - self._start_time >= self._lifespan:
            self.cancel()
        else:
            return super(WSGIFuture, self).set_running_or_notify_cancel()


    def remember(self, name, lifespan=None):
        self._lifespan = lifespan or self._lifespan

        if name in self._mem_dict:
            raise NameError('Cannot remember future by name "%s".  ' % name + \
                            'A future already exists with that name.' )
        self._name = name
        self._mem_dict[name] = self

        return self

    def forget(self):
        if self._name in self._mem_dict and self._mem_dict[self._name] is self:
            del self._mem_dict[self._name]
            self._name = None

class _WorkItem(object):
    def __init__(self, future, fn, args, kwargs):
        self.future = future
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    def run(self):
        if not self.future.set_running_or_notify_cancel():
            return

        try:
            result = self.fn(*self.args, **self.kwargs)
        except BaseException:
            e = sys.exc_info()[1]
            self.future.set_exception(e)
        else:
            self.future.set_result(result)

class WSGIExecutor(ThreadPoolExecutor):
    multithread = True
    multiprocess = False

    def __init__(self, *args, **kwargs):
        ThreadPoolExecutor.__init__(self, *args, **kwargs)

        self.futures = dict()

    def submit(self, fn, *args, **kwargs):
        if self._shutdown_lock.acquire():
            if self._shutdown:
                self._shutdown_lock.release()
                raise RuntimeError('Cannot schedule new futures after shutdown')

            f = WSGIFuture(self.futures)
            w = _WorkItem(f, fn, args, kwargs)

            self._work_queue.put(w)
            self._adjust_thread_count()
            self._shutdown_lock.release()
            return f
        else:
            return False

class FuturesMiddleware(object):
    "Futures middleware that adds a Futures Executor to the environment"
    def __init__(self, app, threads=5):
        self.app = app
        self.executor = WSGIExecutor(threads)

    def __call__(self, environ, start_response):
        environ["wsgiorg.executor"] = self.executor
        environ["wsgiorg.futures"] = self.executor.futures
        return self.app(environ, start_response)
