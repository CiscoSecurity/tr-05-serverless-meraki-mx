from uuid import uuid4
from flask import current_app, g
from datetime import datetime, timedelta
from api.utils import get_ip


class Mapping:
    @staticmethod
    def formatTime(dt_str):
        dt, _, us = dt_str.partition(".")
        dt = datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S")
        us = int(us.rstrip("Z"), 10)
        return dt + timedelta(microseconds=us)

    def observed_time(self, event):
        event_time = self.formatTime(event['ts'])
        return {
            'start_time': event_time,
            'end_time': event_time
        }

    @staticmethod
    def get_relations(event):
        event_type = event.get("eventType")
        relations = []

        if ((event.get("srcIp") and event.get("destIp")) and
                (event["srcIp"] != event["destIp"])):
            relations.append(
                {
                    "related": {
                        "type": "ip",
                        "value": get_ip(event['destIp'])
                    },
                    "source": {
                        "type": "ip",
                        "value": get_ip(event["srcIp"])
                    },
                    **current_app.config['RELATIONS_DEFAULTS']
                }
            )

        return relations

    def observables(self, event):
        observables = []
        event_type = event.get('eventType')
        if event_type == 'IDS Alert':
            if event.get('deviceMac'):
                observables.append(
                    {'type': 'mac', 'value': event.get('deviceMac')})

        elif event_type == 'File Scanned':
            if event.get('clientIp'):
                observables.append(
                    {'type': 'ip', 'value': event.get('clientIp')})

            if event.get('fileHash'):
                observables.append(
                    {'type': 'sha256', 'value': event.get('fileHash')})

        if event.get('clientMac'):
            observables.append(
                {'type': 'mac', 'value': event.get('clientMac')})

        if event.get('srcIp'):
            observables.append(
                {'type': 'ip', 'value': get_ip(event.get('srcIp'))})

        if event.get('destIp'):
            observables.append(
                {'type': 'ip', 'value': get_ip(event.get('destIp'))})

        if not observables:
            return []

        return observables

    def targets(self, event):
        observables = []

        event_type = event.get('eventType')
        if event_type == 'IDS Alert':
            if event.get('destIp'):
                observables.append({'type': 'ip',
                                    'value': get_ip(event['destIp'])})

            if event.get('srcIp'):
                observables.append({'type': 'ip',
                                    'value': get_ip(event['srcIp'])})

            if event.get('clientMac'):
                observables.append(
                    {'type': 'mac', 'value': event.get('clientMac')})

            if event.get('deviceMac'):
                observables.append(
                    {'type': 'mac', 'value': event.get('deviceMac')})
        elif event_type == 'File Scanned':
            if event.get('clientIp'):
                observables.append(
                    {'type': 'ip', 'value': event.get('clientIp')})

            if event.get('fileHash'):
                observables.append(
                    {'type': 'sha256', 'value': event.get('fileHash')})

        if not observables:
            return []

        target = {
            'observables': observables,
            'observed_time': self.observed_time(event),
            'type': 'network.ips',
        }

        return [target]

    def get_resolution(self, event):
        event_type = event.get('eventType')
        if event_type == 'IDS Alert':
            if event['blocked']:
                return 'blocked'
        elif event_type == 'File Scanned':
            if event['action'] == 'Blocked':
                return 'blocked'

        return 'allowed'

    def sighting(self, observable, event):
        event_type = event['eventType']
        severity = {
            1: 'High',
            2: 'Medium',
            3: 'Low',
            4: 'Info'
        }

        if event_type == 'IDS Alert':
            d = {
                'id': f'sighting-{uuid4()}',
                'observed_time': self.observed_time(event),
                'targets': self.targets(event),
                'relations': self.get_relations(event),
                'count': 1,
                'severity': severity.get(int(event['priority'])),
                'short_description': f"%s" % event['message'],
                'resolution': self.get_resolution(event),
                'observables': self.observables(event),
                'description': 'Cisco Meraki MX - %s' % event_type,
                **current_app.config['SIGHTING_DEFAULTS']
            }
            return d
        elif event_type == 'File Scanned':
            d = {
                'id': f'sighting-{uuid4()}',
                'observed_time': self.observed_time(event),
                'targets': self.targets(event),
                'relations': self.get_relations(event),
                'count': 1,
                'resolution': self.get_resolution(event),
                'observables': self.observables(event),
                'description': 'Cisco Meraki MX - %s' % event_type,
                **current_app.config['SIGHTING_DEFAULTS']
            }
            return d