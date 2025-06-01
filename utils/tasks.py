import redis
import celery
from config.settings import REDIS_CONN_URL


REDIS_CLIENT = redis.from_url(REDIS_CONN_URL)

def only_one(function=None):
    """Enforce only one celery task at a time."""

    def _dec(run_func):
        """Decorator."""

        def _caller(*args, **kwargs):
            """Caller."""
            ret_value = None
            have_lock = False
            timeout = 60 * 5
            lock_id = "celery-single-instance-" + run_func.__name__
            lock = REDIS_CLIENT.lock(lock_id, timeout=timeout)
            try:
                have_lock = lock.acquire(blocking=True)
                if have_lock:
                    ret_value = run_func(*args, **kwargs)
            finally:
                if have_lock:
                    lock.release()

            return ret_value

        return _caller

    return _dec(function) if function is not None else _dec

    
class BaseTaskWithRetry(celery.Task):
    autoretry_for = (Exception, KeyError)
    retry_kwargs = {'max_retries': 5}
    retry_backoff = True
