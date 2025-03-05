from uuid import uuid4
from flask import current_app, g
from datetime import datetime, timedelta
from api.utils import get_ip, get_device_info, parse_rule_id_to_snort_link, get_client_info


class Mapping:
    @staticmethod
    def format_time(dt_str):
        """
        Updated time formatting for SecureX

        :param dt_str: str, datetime string to be formatted
        :return: str, formatted datetime string
        """
        dt, _, us = dt_str.partition(".")
        dt_obj = datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S")
        us = int(us.rstrip("Z"), 10)
        dt_obj = dt_obj + timedelta(microseconds=us)
        formatted_time = dt_obj.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return formatted_time

    def observed_time(self, event):
        """
        Extract observed time from an event and format it.

        :param event: dict, event data
        :return: dict, containing start and end times
        """
        if 'ts' in event:
            event_time = self.format_time(event['ts'])
        elif 'occurredAt' in event:
            event_time = self.format_time(event['occurredAt'])
        return {
            'start_time': event_time,
            'end_time': event_time
        }

    @staticmethod
    def get_relations(event):
        """
        Extract relations from an event.

        :param event: dict, event data
        :return: list, list of relations
        """
        event_type = event.get('eventType', event.get('type'))
        relations = []

        if event_type == 'IDS Alert':
            if event.get("srcIp") and event.get("destIp") and event["srcIp"] != event["destIp"]:
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
                        "origin": "Meraki Module",
                        "relation": "Connected To"
                    }
                )
            if event.get('deviceMac') and event.get('srcIp'):
                relations.append(
                    {
                        "related": {
                            "type": "mac_address",
                            "value": event['deviceMac']
                        },
                        "source": {
                            "type": "ip",
                            "value": get_ip(event['srcIp'])
                        },
                        "origin": "Meraki Module",
                        "relation": "Targeted"
                    }
                )

        if event_type == 'File Scanned':
            if event.get("srcIp") and event.get("destIp") and event["srcIp"] != event["destIp"]:
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
                        "origin": "Meraki Module",
                        "relation": "Connected_To"
                    }
                )

            file_hash = event.get('fileHash')

            output_downloaded_by = {
                "origin": "Meraki MX",
                "relation": "Downloaded_By",
                "source": {
                    "value": file_hash,
                    "type": "sha256"
                },
                "related": {
                    "value": get_ip(event["srcIp"]),
                    "type": "ip"
                }
            }
            output_downloaded_from = {
                "origin": "Meraki MX",
                "relation": "Downloaded_From",
                "source": {
                    "value": get_ip(event['destIp']),
                    "type": "ip"
                },
                "related": {
                    "value": file_hash,
                    "type": "sha256"
                }
            }
            output_filename_of = {
                "origin": "Meraki MX",
                "relation": "Filename_Of",
                "source": {
                    "value": event.get('canonicalName'),
                    "type": "file_name"
                },
                "related": {
                    "value": file_hash,
                    "type": "sha256"
                }
            }

            relations.extend([output_downloaded_by, output_downloaded_from, output_filename_of])

        elif event_type == 'nbar_block':
            if ((event['eventData'].get("Source IP") and event['eventData'].get("Destination IP")) and
                    (event['eventData']["Source IP"] != event['eventData']["Destination IP"])):
                relations.append(
                    {
                        "related": {
                            "type": "ip",
                            "value": get_ip(event['eventData']['Destination IP'])
                        },
                        "source": {
                            "type": "ip",
                            "value": get_ip(event['eventData']["Source IP"])
                        },
                        "origin": "Meraki Module",
                        "relation": "Attempted Connection"
                    }
                )

        elif event_type == 'cf_block':
            client_mac = event.get('clientMac')
            client_info = get_client_info(client_mac)
            client_ip = client_info.get('ip')

            if client_ip:
                client_ip = get_ip(client_ip)
            else:
                print("Unable to retrieve client IP.")

            relations.append(
                {
                    "related": {
                        "type": "ip",
                        "value": get_ip(event['eventData']['server'])
                    },
                    "source": {
                        "type": "mac_address",
                        "value": event['clientMac']
                    },
                    "origin": "Meraki Module",
                    "relation": "Attempted Connection"
                }
            )
            relations.append(
                {
                    "related": {
                        "type": "ip",
                        "value": get_ip(event['eventData']['server'])
                    },
                    "source": {
                        "type": "url",
                        "value": event['eventData']['url']
                    },
                    "origin": "Meraki Module",
                    "relation": "Hosted By"
                }
            )

        return relations

    def observables(self, event):
        """
        Extract observables from an event.

        :param event: dict, event data
        :return: list, list of observables
        """
        observables = []
        event_type = event.get('eventType') or event.get('type')

        if event_type == 'IDS Alert':
            if event.get('deviceMac'):
                observables.append({'type': 'device', 'value': event['deviceMac']})

        elif event_type == 'File Scanned':
            if event.get('clientIp'):
                observables.append({'type': 'ip', 'value': event['clientIp']})

            if event.get('fileHash'):
                observables.append({'type': 'sha256', 'value': event['fileHash']})

        elif event_type == 'nbar_block':
            if event['eventData'].get('Source IP'):
                observables.append({'type': 'ip', 'value': get_ip(event['eventData']['Source IP'])})

            if event['eventData'].get('Destination IP'):
                observables.append({'type': 'ip', 'value': get_ip(event['eventData']['Destination IP'])})

        elif event_type == 'cf_block':
            if event.get('clientId'):
                observables.append({'type': 'device', 'value': get_ip(event['clientId'])})

            if event.get('deviceMac'):
                observables.append({'type': 'device', 'value': event['deviceMac']})

            if event.get('deviceSerial'):
                observables.append({'type': 'serial_number', 'value': event['deviceSerial']})

            if event['eventData'].get('server'):
                observables.append({'type': 'ip', 'value': get_ip(event['eventData']['server'])})

        if event.get('clientMac'):
            observables.append({'type': 'mac_address', 'value': event['clientMac']})

        if event.get('srcIp'):
            observables.append({'type': 'ip', 'value': get_ip(event['srcIp'])})

        if event.get('destIp'):
            observables.append({'type': 'ip', 'value': get_ip(event['destIp'])})

        return observables


    def targets(self, event):
        """
        Extract targets from an event.

        :param event: dict, event data
        :return: list, list of targets
        """
        observables = []
        event_type = event.get('eventType') or event.get('type')

        if event_type == 'IDS Alert':
            client_mac = event.get('clientMac')
            client_info = get_client_info(client_mac)
            client_name = client_info.get('name')

            if client_name:
                observables.append({'type': 'hostname', 'value': client_name})
            else:
                print("Unable to retrieve client name.")

            if event.get('destIp'):
                observables.append({'type': 'ip', 'value': get_ip(event['destIp'])})

            if event.get('clientMac'):
                observables.append({'type': 'mac_address', 'value': event['clientMac']})

        elif event_type == 'File Scanned':
            if event.get('clientName'):
                observables.append({'type': 'device', 'value': event['clientName']})

            if event.get('clientIp'):
                observables.append({'type': 'ip', 'value': event['clientIp']})

            if event.get('clientMac'):
                observables.append({'type': 'mac_address', 'value': event['clientMac']})

        elif event_type == 'nbar_block':
            if event.get('clientId'):
                observables.append({'type': 'device', 'value': event['clientId']})

            if event.get('clientDescription'):
                observables.append({'type': 'hostname', 'value': event['clientDescription']})

            if event.get('clientMac'):
                observables.append({'type': 'mac_address', 'value': event['clientMac']})

            if event['eventData'].get('Source IP'):
                observables.append({'type': 'ip', 'value': get_ip(event['eventData']['Source IP'])})

        elif event_type == 'cf_block':
            if event.get('clientId'):
                observables.append({'type': 'device', 'value': event['clientId']})

            if event.get('clientDescription'):
                observables.append({'type': 'hostname', 'value': event['clientDescription']})

            if event.get('clientMac'):
                observables.append({'type': 'mac_address', 'value': event['clientMac']})

            client_mac = event.get('clientMac')
            client_info = get_client_info(client_mac)
            client_ip = client_info.get('ip')

            if client_ip:
                client_ip = get_ip(client_ip)
                observables.append({'type': 'ip', 'value': client_ip})

        if not observables:
            return []

        target = [{
            'observables': observables,
            'observed_time': self.observed_time(event),
            'type': 'endpoint',
        }]

        device_observables = []
        device_mac = event.get('deviceMac')
        if device_mac:
            device_info = get_device_info(device_mac)

            device_observables.append({'type': 'ngfw_name', 'value': device_info['name']})
            device_observables.append({'type': 'mac_address', 'value': device_mac})
            device_observables.append({'type': 'serial_number', 'value': device_info['serial']})
            device_observables.append({'type': 'ngfw_id', 'value': device_info['model']})

            target.append({
                'observables': device_observables,
                'observed_time': self.observed_time(event),
                'type': 'network.firewall',
            })

        return target


    def get_resolution(self, event):
        # Determine event_type from the given event
        event_type = event.get('eventType') or event.get('type')

        # Check for resolution based on event_type
        if event_type == 'IDS Alert':
            if event['blocked']:
                return 'blocked'
        elif event_type == 'File Scanned':
            if event['action'] == 'Blocked':
                return 'blocked'

        # Default resolution is 'allowed'
        return 'allowed'

    
    def data_table(self, event):
        # Determine event_type from the given event
        event_type = event.get('eventType') or event.get('type')

        # Check for data table based on event_type
        if event_type == 'File Scanned':
            file_type = event.get('fileType', '')
            file_size = str(event.get('fileSizeBytes', ''))
            uri = event.get('uri', '')
            disposition = event.get('disposition', '')
            protocol = event.get('protocol', '')

            rows = [file_type, file_size, uri, disposition, protocol]

            data = {
                'columns': [
                    {'name': 'File Type', 'type': 'string'},
                    {'name': 'File Size (Bytes)', 'type': 'string'},
                    {'name': 'URI', 'type': 'string'},
                    {'name': 'Disposition', 'type': 'string'},
                    {'name': 'Protocol', 'type': 'string'}
                ],
                'rows': [rows],
                'row_count': 1
            }

        elif event_type == 'nbar_block':
            device_name = event.get('deviceName', '')
            device_serial = event.get('deviceSerial', '')
            src_port = str(event['eventData'].get('Source Port', ''))
            dest_port = str(event['eventData'].get('Destination Port', ''))
            protocol = event['eventData'].get('Protocol', '')
            block_type = event['eventData'].get('Block Type', '')
            nbar_id = str(event['eventData'].get('NBAR ID', ''))

            rows = [device_name, device_serial, src_port, dest_port, protocol, block_type, nbar_id]

            data = {
                'columns': [
                    {'name': 'Device Name', 'type': 'string'},
                    {'name': 'Device Serial', 'type': 'string'},
                    {'name': 'Source Port', 'type': 'string'},
                    {'name': 'Destination Port', 'type': 'string'},
                    {'name': 'Protocol', 'type': 'string'},
                    {'name': 'Block Type', 'type': 'string'},
                    {'name': 'NBAR ID', 'type': 'string'}
                ],
                'rows': [rows],
                'row_count': 1
            }

        return data

    
    def markdown_table(self, event):
        # Reuse the data_table function to get the data structure
        data = self.data_table(event)
        
        # Create the header row
        header = "| " + " | ".join([col["name"] for col in data["columns"]]) + " |"
        
        # Create the separator row
        separator = "| " + " | ".join(["-" * len(col["name"]) for col in data["columns"]]) + " |"
        
        # Create the data rows
        rows = []
        for row_data in data["rows"]:
            row = "| " + " | ".join([str(cell_data) for cell_data in row_data]) + " |"
            rows.append(row)
        
        # Combine the header, separator, and data rows
        markdown = "\n".join([header, separator] + rows)
        
        return markdown


    def sighting(self, observable, event):
        # Determine event_type from the given event
        event_type = event.get('eventType') or event.get('type')
        internal = True
        severity = {
            1: 'High',
            2: 'Medium',
            3: 'Low',
            4: 'Info'
        }

        if event_type == 'IDS Alert':
            d = {
                'title' : 'Meraki Event: IDS Alert',
                'schema_version' : "1.0.17",
                'type' : 'sighting',
                'confidence' : 'Low',
                'id': f'transient:sighting-{uuid4()}',
                'observed_time': self.observed_time(event),
                'targets': self.targets(event),
                'relations': self.get_relations(event),
                'count': 1,
                'severity': severity.get(int(event['priority'])),
                'short_description': f"%s" % event['message'],
                'resolution': self.get_resolution(event),
                'observables': self.observables(event),
                'description': 'Cisco Meraki MX - %s' % event_type,
                'external_references' : [{'source_name' : 'Snort', 'url' : parse_rule_id_to_snort_link(event)}],
                'source' : 'Meraki MX Module',
                'sensor' : get_device_info(event.get('deviceMac')).get('name'),
                'internal' : internal
            }

            indicator = self.indicator(event)
            sighting_id = d['id']
            indicator_id = indicator['id']
            relationship = self.extract_relationship(sighting_id, indicator_id)

            return [d, indicator, relationship]

        elif event_type == 'File Scanned':
            fs_priority = 1
            relationship = ''

            """
                === Data table not surfacing in XDR ===
                    - Can replace with markdown table in description field for now
                    - 'description': f"Cisco Meraki MX - {event_type}",
            """

            d = {
                'title' : 'Meraki Event: File Scanned',
                'schema_version' : "1.3.7",
                'type' : 'sighting',
                'confidence' : 'Low',
                'severity': severity.get(fs_priority),
                'id': f'transient:sighting-{uuid4()}',
                'observed_time': self.observed_time(event),
                'targets': self.targets(event),
                'relations': self.get_relations(event),
                'count': 1,
                'resolution': self.get_resolution(event),
                'observables': self.observables(event),
                'source' : 'Meraki MX Module',
                'internal' : internal,
                'data' : self.data_table(event),
                'description' : self.markdown_table(event)
            }

            return d, relationship
        
        elif event_type == 'nbar_block':
            relationship = ''
            event_type = event['type']
            nbar_priority = 2
            
            """
                === Data table not surfacing in XDR ===
                    - Can replace with markdown table in description field for now
                    - 'description': f"Cisco Meraki MX - {event_type}",
            """
            
            d = {
                'title' : 'Meraki Event: NBAR Block',
                'schema_version' : "1.0.17",
                'type' : 'sighting',
                'confidence' : 'Low',
                'id': f'transient:sighting-{uuid4()}',
                'observed_time': self.observed_time(event),
                'targets': self.targets(event),
                'relations': self.get_relations(event),
                'count': 1,
                'severity': severity.get(nbar_priority),
                'short_description': f"{event['description']}",
                'resolution': event['eventData']['Layer 7 firewall rule'],
                'observables': self.observables(event),
                'source' : 'Meraki MX Module',
                'internal' : internal,
                'description' : self.markdown_table(event),
                'data' : self.data_table(event)
            }

            return d, relationship
        
        elif event_type == 'cf_block':
            relationship = ''
            event_type = event['type']
            nbar_priority = 3
            
            d = {
                'title' : 'Meraki Event: Content Filter Block',
                'schema_version' : "1.0.17",
                'type' : 'sighting',
                'confidence' : 'Low',
                'id': f'transient:sighting-{uuid4()}',
                'observed_time': self.observed_time(event),
                'targets': self.targets(event),
                'relations': self.get_relations(event),
                'count': 1,
                'severity': severity.get(nbar_priority),
                'short_description': f"{event['description']}",
                'resolution': "Blocked",
                'observables': self.observables(event),
                'description': f"Cisco Meraki MX - {event_type}",
                'source' : 'Meraki MX Module',
                'internal' : internal
            }

            return d, relationship
        
    def indicator(self, event):
        # Check if the event is an IDS Alert and has a ruleId
        if event.get('eventType') == 'IDS Alert' and event.get('ruleId'):
            rule_id = event.get('ruleId')

            indicator = {
                'description' : event.get('message'),
                'valid_time' : self.observed_time(event),
                'producer' : 'Meraki Relay Module',
                'schema_version' : "1.3.7",
                'type' : 'indicator',
                'source' : "Snort Documentation",
                'short_description' : rule_id,
                'title' : 'Snort Rule: ' + rule_id,
                'source_uri' : parse_rule_id_to_snort_link(event),
                'id': f'transient:indicator-{uuid4()}',
                'tlp' : 'amber'
            }
            return indicator


    def extract_relationship(self, sighting_id, indicator_id):
        # Create a relationship between sighting and indicator
        return {
            'schema_version' : "1.3.7",
            'type': 'relationship',
            'relationship_type': 'member-of',
            'id': f'transient:relationship-{uuid4()}',
            'source_ref': sighting_id,
            'target_ref': indicator_id,
        }
