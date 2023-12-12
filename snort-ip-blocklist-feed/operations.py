"""
Copyright start
MIT License
Copyright (c) 2023 Fortinet Inc
Copyright end
"""

import requests
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('snort-ip-blocklist-feed')


def make_api_call(method="GET", config=None):
    try:
        server_url = config.get('server_url').strip('/')
        if not server_url.startswith('https://') and not server_url.startswith('http://'):
            server_url = "https://" + server_url

        response = requests.request(method=method, url=server_url, verify=config.get('verify_ssl'))
        if response.ok:
            return response
        else:
            if response.text != "":
                err_resp = response.json()
                failure_msg = err_resp['response_msg']
                error_msg = 'Response [{0}:{1} Details: {2}]'.format(response.status_code, response.reason,
                                                                     failure_msg if failure_msg else '')
            else:
                error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.reason)
            logger.error(error_msg)
            raise ConnectorError(error_msg)
    except requests.exceptions.SSLError:
        logger.error('An SSL error occurred')
        raise ConnectorError('An SSL error occurred')
    except requests.exceptions.ConnectionError:
        logger.error('A connection error occurred')
        raise ConnectorError('A connection error occurred')
    except requests.exceptions.Timeout:
        logger.error('The request timed out')
        raise ConnectorError('The request timed out')
    except requests.exceptions.RequestException:
        logger.error('There was an error while handling the request')
        raise ConnectorError('There was an error while handling the request')
    except Exception as err:
        raise ConnectorError(str(err))


def get_indicators(config):
    response = make_api_call(config=config)
    ip_list = response.content.decode('utf-8').split('\n')
    ip_list = [ip for ip in ip_list if ip]
    return ip_list


def _check_health(config):
    try:
        if get_indicators(config):
            return True
    except Exception as e:
        logger.error("{0}".format(str(e)))
        raise ConnectorError("{0}".format(str(e)))


operations = {
    'get_indicators': get_indicators
}
