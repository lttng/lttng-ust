import lttngust
import logging
import time
import math


def hello():
    logger = logging.getLogger('hello-logger')

    while True:
        logger.debug('hello, debug message: %d', 23)
        time.sleep(0.1)
        logger.info('hello, info message: %s', 'world')
        time.sleep(0.1)
        logger.warn('hello, warn message')
        time.sleep(0.1)
        logger.error('hello, error message: %f', math.pi)
        time.sleep(0.1)
        logger.critical('hello, critical message')
        time.sleep(0.5)


if __name__ == '__main__':
    hello()
