import logging

from flask import request

logger = logging.getLogger(__name__)


def login(user, password, token):
    # ruleid: py/sensitive-log
    logger.info("login %s %s", user.id, password)
    # ruleid: py/sensitive-log
    logger.debug(f"issued token={token}")
    # ruleid: py/sensitive-log
    logging.info("headers: %s", request.headers)
    # ruleid: py/sensitive-log
    print("cpf", user.cpf)
    # ok: py/sensitive-log
    logger.info("password reset requested for %s", user.id)
    # ok: py/sensitive-log
    logger.info("has token: %s", bool(token))
