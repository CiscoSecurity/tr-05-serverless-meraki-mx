import json
from json.decoder import JSONDecodeError
from ipaddress import ip_address
from logging.handlers import DEFAULT_SOAP_LOGGING_PORT
from stat import FILE_ATTRIBUTE_ENCRYPTED

import jwt
import requests
from flask import request, jsonify, current_app, g
from jwt import InvalidSignatureError, DecodeError, InvalidAudienceError
from requests.exceptions import ConnectionError, InvalidURL, HTTPError, SSLError, ConnectionError

from api.errors import (AuthorizationError, InvalidArgumentError,
                        MerakiMXSSLError, MerakiMXConnectionError)

NO_AUTH_HEADER = 'Authorization header is missing'
WRONG_AUTH_TYPE = 'Wrong authorization type'
WRONG_PAYLOAD_STRUCTURE = 'Wrong JWT payload structure'
WRONG_JWT_STRUCTURE = 'Wrong JWT structure'
WRONG_AUDIENCE = 'Wrong configuration-token-audience'
KID_NOT_FOUND = 'kid from JWT header not found in API response'
WRONG_KEY = ('Failed to decode JWT with provided key. '
             'Make sure domain in custom_jwks_host '
             'corresponds to your SecureX instance region.')
JWKS_HOST_MISSING = ('jwks_host is missing in JWT payload. Make sure '
                     'custom_jwks_host field is present in module_type')
WRONG_JWKS_HOST = ('Wrong jwks_host in JWT payload. Make sure domain follows '
                   'the visibility.<region>.cisco.com structure')


def get_public_key(jwks_host, token):
    """
    Get public key by requesting it from specified jwks host.

    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    expected_errors = (
        ConnectionError,
        InvalidURL,
        KeyError,
        JSONDecodeError,
        HTTPError
    )
    try:
        response = requests.get(f"https://{jwks_host}/.well-known/jwks")
        response.raise_for_status()
        jwks = response.json()

        public_keys = {}
        for jwk in jwks['keys']:
            kid = jwk['kid']
            public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(
                json.dumps(jwk)
            )
        kid = jwt.get_unverified_header(token)['kid']
        return public_keys.get(kid)

    except expected_errors:
        raise AuthorizationError(WRONG_JWKS_HOST)


def get_auth_token():
    """
    Parse and validate incoming request Authorization header.

    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """
    expected_errors = {
        KeyError: NO_AUTH_HEADER,
        AssertionError: WRONG_AUTH_TYPE
    }
    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def catch_errors(func):
    def wraps(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except SSLError as error:
            raise MerakiMXSSLError(error)
        except (ConnectionError, InvalidURL):
            raise MerakiMXConnectionError
    return wraps


def get_ip(input):
    if ':' not in input:
        return input
    (ip, port, version) = parse_ip(input)
    return ip


def parse_ip(input):
    ip, separator, port = input.rpartition(':')
    assert separator
    port = int(port)
    ip = ip_address(ip.strip("[]"))
    return (str(ip), port, ip.version)


def parse_proto(input):
    l3_proto, separator, l2_proto = input.rpartition('/')
    assert separator
    l3_proto = l3_proto
    return l3_proto


@catch_errors
def query_sightings(observables, credentials):
    network_id = credentials.get('NETWORK_ID')
    api_key = credentials.get('API_KEY')
    entities_limit = credentials.get('CTR_ENTITIES_LIMIT')

    url = "https://api.meraki.com/api/v1/organizations/%d/appliance/security/events?sortOrder=descending&perPage=%d" % (
        network_id, entities_limit)
    payload = None
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Cisco-Meraki-API-Key": api_key
    }

    response = requests.request('GET', url, headers=headers, data=payload)
    json_result = json.loads(response.text.encode('utf8'))

    results = []
    indicator = observables
    for record in json_result:
        event_type = record.get('eventType')
        if event_type == 'IDS Alert':
            (dst_ip, port, version) = parse_ip(record['destIp'])
            (src_ip, port, version) = parse_ip(record['srcIp'])
            device_mac = record['deviceMac']
            client_mac = record['clientMac']

            if (indicator in dst_ip
                or indicator in src_ip
                or indicator in device_mac
                or indicator in client_mac): results.append(record)

        elif event_type == 'File Scanned':
            client_name = record['clientName']
            client_mac = record['clientMac']
            client_ip = record['clientIp']
            src_ip = record['srcIp']
            dest_ip = record['destIp']
            file_hash = record['fileHash']
            file_type = record['fileType']
            canonical_name = record['canonicalName']

            if (indicator in dst_ip
                or indicator in src_ip
                or indicator in client_ip
                or indicator in file_hash):
                results.append(record)

    return results


def get_jwt():
    """
    Get Authorization token and validate its signature
    against the public key from /.well-known/jwks endpoint.

    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    expected_errors = {
        KeyError: WRONG_PAYLOAD_STRUCTURE,
        AssertionError: JWKS_HOST_MISSING,
        InvalidSignatureError: WRONG_KEY,
        DecodeError: WRONG_JWT_STRUCTURE,
        InvalidAudienceError: WRONG_AUDIENCE,
        TypeError: KID_NOT_FOUND
    }
    token = get_auth_token()
    try:
        jwks_payload = jwt.decode(token, options={'verify_signature': False})
        assert 'jwks_host' in jwks_payload
        jwks_host = jwks_payload.get('jwks_host')
        key = get_public_key(jwks_host, token)
        aud = request.url_root
        payload = jwt.decode(
            token, key=key, algorithms=['RS256'], audience=[aud.rstrip('/')]
        )

        assert 'NETWORK_ID' in payload
        assert 'ORG_ID' in payload
        assert 'API_KEY' in payload

        return payload
    except tuple(expected_errors) as error:
        message = expected_errors[error.__class__]
        raise AuthorizationError(message)


def get_json(schema):
    """
    Parse the incoming request's data as JSON.
    Validate it against the specified schema.
    """

    data = request.get_json(force=True, silent=True, cache=False)
    message = schema.validate(data)

    if message:
        raise InvalidArgumentError(message)

    return data


def format_docs(docs):
    return {'count': len(docs), 'docs': docs}


def jsonify_result():
    result = {'data': {}}

    if g.get('status'):
        result['data']['status'] = g.status

    if g.get('sightings'):
        result['data']['sightings'] = format_docs(g.sightings)

    if g.get('errors'):
        result['errors'] = g.errors
        if not result['data']:
            del result['data']

    return jsonify(result)


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(data):
    return jsonify({'errors': [data]})
