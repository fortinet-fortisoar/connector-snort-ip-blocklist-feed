"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

import requests
from connectors.core.connector import get_logger, ConnectorError
from bs4 import BeautifulSoup

logger = get_logger('snort-ip-blocklist-feed')


def get_indicators(config):
    try:
        session = requests.Session()
        headers = {}
        terms_url = "https://www.snort.org/downloads/ip-block-list/terms"
        terms_response = session.get(terms_url, headers=headers, timeout=10, verify=config.get('verify_ssl'))

        if terms_response.status_code != 200:
            raise ConnectorError(f"Failed to fetch terms page (status {terms_response.status_code})")

        soup = BeautifulSoup(terms_response.text, 'html.parser')
        csrf_meta = soup.find("meta", attrs={"name": "csrf-token"})
        if not csrf_meta:
            raise ConnectorError("CSRF token not found in page.")
        csrf_token = csrf_meta["content"]
        accept_url = "https://www.snort.org/downloads/ip-block-list/accept-terms"
        form_data = {"authenticity_token": csrf_token}
        headers["Referer"] = terms_url
        accept_response = session.post(accept_url, data=form_data, headers=headers, timeout=10, verify=config.get('verify_ssl'))
        if accept_response.status_code != 200:
            raise ConnectorError(f"Failed to accept terms (status {accept_response.status_code})")
        download_response = session.get(config.get('server_url'), headers=headers, timeout=10, verify=config.get('verify_ssl'))
        if download_response.status_code != 200:
            raise ConnectorError(f"Failed to download IP block list (status {download_response.status_code})")
        ip_list = download_response.content.decode('utf-8').split('\n')
        ip_list = [ip for ip in ip_list if ip]
        return ip_list
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
