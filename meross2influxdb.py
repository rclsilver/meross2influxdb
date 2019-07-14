#!/usr/bin/env python

import argparse
import base64
import hashlib
import json
import logging
import os
import requests
import random
import string
import sys
import time

from influxdb import InfluxDBClient

def meross_build_message(url, secret, method, namespace, payload):
    # generating nonce
    nonce = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(16))

    # generating message id
    md5_hash = hashlib.md5()
    md5_hash.update(nonce.encode('utf-8'))
    message_id = md5_hash.hexdigest().lower()

    # generate timestamp
    timestamp = int(round(time.time()))

    # generate hash of message id, key and timestamp
    md5_hash = hashlib.md5()
    md5_hash.update(
        (
            '%s%s%s' % (
                message_id,
                secret,
                timestamp
            )
        ).encode('utf-8')
    )
    signature = md5_hash.hexdigest().lower()

    # generate data dict
    data = {
        'header': {
            'from': url,
            'messageId': message_id,
            'method': method,
            'namespace': namespace,
            'payloadVersion': 1,
            'sign': signature,
            'timestamp': timestamp
        },
        'payload': payload
    }

    return json.dumps(data).encode('utf-8')

def meross_verify_signature(secret, message):
    md5_hash = hashlib.md5()
    md5_hash.update(
        (
            '%s%s%s' % (
                message['header']['messageId'],
                secret,
                message['header']['timestamp'],
            )
        ).encode('utf-8')
    )
    signature = md5_hash.hexdigest().lower()

    return signature == message['header']['sign']

def meross_execute(url, secret, method, namespace, payload={}):
    headers = { 'Content-Type': 'application/json' }
    data = meross_build_message(url, secret, method, namespace, payload)

    try:
        logging.debug('Executing command to %s: %s', url, data)

        with requests.post(url, data=data, headers=headers) as r:
            if not r.ok:
                logging.error('Error while executing command to %s: invalid HTTP code: %d', url, r.status_code)
                return False

            message = r.json()

            if not meross_verify_signature(secret, message):
                logging.error('Invalid signature (secret is valid?)')
                return False

            logging.debug('Got %s', str(message))

            return message
    except requests.exceptions.RequestException as e:
        logging.error('Error while executing command to %s: %s', url, str(e))
        logging.exception(e)
        return False

def fetch_meross_infos(url, secret):
    system_data = meross_execute(url, secret, 'GET', 'Appliance.System.All')

    if system_data:
        abilities = meross_execute(url, secret, 'GET', 'Appliance.System.Ability')

        if abilities and 'Appliance.Control.Electricity' in abilities['payload']['ability']:
            electricity = meross_execute(url, secret, 'GET', 'Appliance.Control.Electricity')

            return (
                system_data['payload']['all']['system']['hardware']['uuid'],
                electricity['payload']['electricity'],
            )

    return None, None

def update(config):
    points = []

    for device in config.get('devices', {}):
        url = '{}://{}:{}/config'.format(
            device.get('protocol', 'http'),
            device.get('host'),
            device.get('port', 80)
        )

        logging.info('Fetching data from %s', url)

        uuid, data = fetch_meross_infos(
            url,
            device.get('secret', '')
        )

        if data:
            points.append({
                'measurement': 'voltage',
                'tags': {
                    'id': uuid,
                    'label': device.get('name', uuid),
                },
                'fields': {
                    'value': float(data['voltage']) / 10.0, # convert to volts
                }
            })
            points.append({
                'measurement': 'power',
                'tags': {
                    'id': uuid,
                    'label': device.get('name', uuid),
                },
                'fields': {
                    'value': float(data['power']) / 1000.0, # convert to watts
                }
            })
            points.append({
                'measurement': 'current',
                'tags': {
                    'id': uuid,
                    'label': device.get('name', uuid),
                },
                'fields': {
                    'value': float(data['current']) / 1000.0, # convert to amperes
                }
            })

    if len(points):
        logging.debug('Writing {} point(s) to InfluxDB...'.format(
            len(points)
        ))

        try:
            client = InfluxDBClient(
                host=config.get('influxdb', {}).get('host'),
                port=config.get('influxdb', {}).get('port', 8086),
                username=config.get('influxdb', {}).get('user'),
                password=config.get('influxdb', {}).get('pass'),
                database=config.get('influxdb', {}).get('base'),
            )
            client.write_points(points)

            logging.info('Written {} point(s) to InfluxDB.'.format(
                len(points)
            ))
        except Exception as e:
            logging.error('Unable to write {} point(s) to InfluxDB'.format(
                len(points),
            ))
            logging.exception(e)
            return False

    return True


def main(args):
    # Logging
    logging_level = int(os.getenv('LOG_LEVEL', logging.INFO if not args.debug else logging.DEBUG))
    logging.basicConfig(level=logging_level, format='[%(asctime)s] (%(levelname)s) %(message)s')

    # Configuration
    try:
        with open(args.configuration) as f:
            configuration = json.load(f)
    except Exception as e:
        logging.error('Unable to load configuration: %s', str(e))
        logging.exception(e)
        return 1
    
    while True:
        if not update(configuration):
            logging.warning('Error while updating data')
        time.sleep(os.getenv('LOOP_DELAY', 30))

if '__main__' == __name__:
    parser = argparse.ArgumentParser()

    parser.add_argument('-c', '--configuration', default='/etc/meross2influxdb.json')
    parser.add_argument('-d', '--debug', action='store_true', dest='debug', default=False)

    args = parser.parse_args()

    sys.exit(main(args))
