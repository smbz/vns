import sys
from Queue import PriorityQueue, Empty
from threading import Thread, Event, current_thread

from twisted.internet.defer import Deferred

from web.vnswww import models as db


queue = PriorityQueue()
new_items = Event()
thread = None


def start():
    """Constructor.  Initialises the queue of jobs to do and starts the DB
    thread."""
    global thread
    thread = Thread(name="DBService", target=loop)
    thread.start()

def run_in_db_thread(callback, priority=50):
    """Puts callback in the queue to be called from the database thread,
    and returns a twisted Deferred object to allow other operations after
    the db transaction has completed.
    @param callback  A callable to call from the database thread
    @param priority  The priority of the job; save operations should have
    lower priority to avoid faster read operations blocking for a long time
    """

    # Check that callback is callable
    if not callable(callback):
        raise TypeError("'%s' object is not callable" % type(callback))

    # Make a deferred and put the callback in the queue
    deferred = Deferred()
    queue.put((priority, (callback, deferred)))
    return deferred

def run_and_wait(callback, priority=20):
    """Puts callback in the queue to be called from the database thread and
    blocks until it returns.  Returns the value returned by callback, or
    raises any exceptions raised by callback."""

    # Check that callback is callable
    if not callable(callback):
        raise TypeError("'%s' object is not callable in run_and_wait" % type(callback))

    # If we're already in the database thread, then just run it
    if current_thread() == thread:
        return callback()
        
    # Create an event - this is used to notify us that the job has finished
    event = Event()

    # Create an object which to be passed to the run/wait functions to get
    # around python 2.*'s lack of "nonlocal" variables (we can't assign to
    # anything in run_background from _run_and_notify or _wait, but we can
    # if we make an object and assign to variables within the object).
    class RetValue(object):
        def __init__(self):
            self.ret = None
            self.exc_info = None
    r = RetValue()

    # A function to run the callback, set the return variable and tell us
    # when it's done.  We use a list to get around the fact that we can't
    # return anything from a function that's being run in the DB thread.
    def _run_and_notify():
        try:
            r.ret = callback()
        except Exception as e:
            r.exc_info = sys.exc_info()
        event.set()

    # Run the above function and wait for it to return
    queue.put((priority, (lambda:_run_and_notify(), None)))
    event.wait()

    # Return whatever the callback returned
    if r.exc_info is None:
        return r.ret
    else:
        raise r.exc_info[0], r.exc_info[1], r.exc_info[2]

def run_background(callback, priority=50):
    """Puts callback in the job queue to be run from the database thread
    and returns a callable which, when called, will block until the job has
    finished and return / raise anything returned or raised by the callback.
    This should be useful for running database queries, doing some work
    while the query is running, and then waiting until the query has
    completed before anything else is done.
    """

    # Check that callback is callable
    if not callable(callback):
        raise TypeError("'%s' object is not callable in run_background" % type(callback))

    # If we're already in the database thread, then just run it
    if current_thread() == thread:
        return callback

    event = Event()

    # Create an object which to be passed to the run/wait functions to get
    # around python 2.*'s lack of "nonlocal" variables (we can't assign to
    # anything in run_background from _run_and_notify or _wait, but we can
    # if we make an object and assign to variables within the object).
    class RetValue(object):
        def __init__(self):
            self.ret = None
            self.exc_info = None
    r = RetValue()

    # A function to run in the DB thread; this runs the callback, stores any
    # result, then pokes the wait function to say everything's done
    def _run_and_notify():
        try:
            r.ret = callback()
        except Exception as e:
            r.exc_info = sys.exc_info()
        event.set()

    # A function to return from run_background; when run, this blocks until
    # the query has finished and then returns/raises whatever the callback
    # did.
    def _wait():
        event.wait()
        if r.exc_info == None:
            return r.ret
        else:
            raise r.exc_info[0], r.exc_info[1], r.exc_info[2]

    queue.put((priority, (_run_and_notify, None)))
    return _wait

def loop():
    """Keeps looping and checking for jobs waiting in the queue."""
    while True:
        # Get a job from the queue and do it
        (_, (call, deferred)) = queue.get()
        ret = call()
        if deferred: deferred.callback(ret)
