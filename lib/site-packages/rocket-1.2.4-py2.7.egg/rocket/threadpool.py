# -*- coding: utf-8 -*-

# This file is part of the Rocket Web Server
# Copyright (c) 2010 Timothy Farrell

# Import System Modules
import logging
# Import Package Modules
from . import DEFAULTS, NullHandler
from .futures import has_futures, WSGIExecutor

# Setup Logging
log = logging.getLogger('Rocket.Errors.ThreadPool')
log.addHandler(NullHandler())

class ThreadPool:
    """The ThreadPool class is a container class for all the worker threads. It
    manages the number of actively running threads."""

    def __init__(self,
                 method,
                 app_info,
                 active_queue,
                 monitor_queue,
                 min_threads=DEFAULTS['MIN_THREADS'],
                 max_threads=DEFAULTS['MAX_THREADS'],
                 ):

        if __debug__:
            log.debug("Initializing ThreadPool.")

        self.check_for_dead_threads = 0
        self.active_queue = active_queue

        self.worker_class = method
        self.min_threads = min_threads
        self.max_threads = max_threads
        self.monitor_queue = monitor_queue
        self.stop_server = False
        self.alive = False

        # TODO - Optimize this based on some real-world usage data
        self.grow_threshold = int(max_threads/10) + 2

        if not isinstance(app_info, dict):
            app_info = dict()

        if has_futures and app_info.get('futures'):
            app_info['executor'] = WSGIExecutor(max([DEFAULTS['MIN_THREADS'],
                                                     2]))

        app_info.update(max_threads=max_threads,
                        min_threads=min_threads)

        self.min_threads = min_threads
        self.app_info = app_info

        self.threads = set()

    def start(self):
        self.stop_server = False
        if __debug__:
            log.debug("Starting threads.")

        self.grow(self.min_threads)

        self.alive = True

    def stop(self):
        self.alive = False

        if __debug__:
            log.debug("Stopping threads.")

        self.stop_server = True

        # Prompt the threads to die
        self.shrink(len(self.threads))

        # Stop futures initially
        if has_futures and self.app_info.get('futures'):
            if __debug__:
                log.debug("Future executor is present.  Python will not "
                          "exit until all jobs have finished.")
            self.app_info['executor'].shutdown(wait=False)

        # Give them the gun
        #active_threads = [t for t in self.threads if t.isAlive()]
        #while active_threads:
        #    t = active_threads.pop()
        #    t.kill()

        # Wait until they pull the trigger
        for t in self.threads:
            if t.isAlive():
                t.join()

        # Clean up the mess
        self.bring_out_your_dead()

    def bring_out_your_dead(self):
        # Remove dead threads from the pool

        dead_threads = [t for t in self.threads if not t.isAlive()]
        for t in dead_threads:
            if __debug__:
                log.debug("Removing dead thread: %s." % t.getName())
            try:
                # Py2.4 complains here so we put it in a try block
                self.threads.remove(t)
            except:
                pass
        self.check_for_dead_threads -= len(dead_threads)

    def grow(self, amount=None):
        if self.stop_server:
            return

        if not amount:
            amount = self.max_threads

        if self.alive:
            amount = min([amount, self.max_threads - len(self.threads)])

        if __debug__:
            log.debug("Growing by %i." % amount)

        for x in range(amount):
            worker = self.worker_class(self.app_info,
                                       self.active_queue,
                                       self.monitor_queue)

            worker.setDaemon(True)
            self.threads.add(worker)
            worker.start()

    def shrink(self, amount=1):
        if __debug__:
            log.debug("Shrinking by %i." % amount)

        self.check_for_dead_threads += amount

        for x in range(amount):
            self.active_queue.put(None)

    def dynamic_resize(self):
        if (self.max_threads > self.min_threads or self.max_threads == 0):
            if self.check_for_dead_threads > 0:
                self.bring_out_your_dead()

            queueSize = self.active_queue.qsize()
            threadCount = len(self.threads)

            if __debug__:
                log.debug("Examining ThreadPool. %i threads and %i Q'd conxions"
                          % (threadCount, queueSize))

            if queueSize == 0 and threadCount > self.min_threads:
                self.shrink()

            elif queueSize > self.grow_threshold:

                self.grow(queueSize)
