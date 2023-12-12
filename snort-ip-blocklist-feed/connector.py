"""
Copyright start
MIT License
Copyright (c) 2023 Fortinet Inc
Copyright end
"""

from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _check_health

logger = get_logger('snort-ip-blocklist-feed')


class SnortIPBlocklistFeed(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            operation = operations.get(operation)
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)
        return operation(config)

    def check_health(self, config):
        logger.info('starting health check')
        _check_health(config)
        logger.info('Completed health check and no errors found')


