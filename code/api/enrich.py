from flask import Blueprint, current_app, g
from functools import partial
from api.mapping import Mapping
from api.schemas import ObservableSchema
from api.utils import get_json, get_jwt, jsonify_data, query_sightings, jsonify_result, get_ip, get_client_info

enrich_api = Blueprint('enrich', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))

@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    _ = get_jwt()
    _ = get_observables()
    return jsonify_data({})


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    # Get JWT credentials and observables
    credentials = get_jwt()
    observables = get_observables()

    # Initialize sightings, indicators, and relationships lists
    g.sightings = []
    g.indicators = []
    g.relationships = []

    # Iterate through observables and query sightings for each observable
    for observable in observables:
        response = query_sightings(observable['value'], credentials)

        # Process each event in the response
        for event in response:
            mapping = Mapping()
            this_sighting = mapping.sighting(observable, event)

            # Append sighting, indicator, and relationship data to the respective lists
            g.sightings.append(this_sighting[0])
            if this_sighting[1] != '':
                g.indicators.append(this_sighting[1])
                g.relationships.append(this_sighting[2])

    # Return the JSON response
    return jsonify_result()


import meraki

@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    # Retrieve Meraki configuration and initialize the Meraki Dashboard API
    meraki_config = get_jwt()
    dashboard = meraki.DashboardAPI(meraki_config.get('API_KEY'), suppress_logging=True, print_console=False)
    network_id = meraki_config.get('NETWORK_ID')

    json_refer = []
    dev_url = "https://dashboard.meraki.com"

    # Get the list of devices in the network
    org_devices = dashboard.networks.getNetworkDevices(network_id)

    try:
        ob = get_observables()
    except Exception as e:
        return f'Error getting observables: {e}'

    # Get the first observable from the list
    first_ob = ob[0] if len(ob) > 0 else None

    def construct_json_response(url):
        return [{
            "id": "meraki-dashboard-link",
            "title": "View Device in Meraki Dashboard",
            "description": "Open this device in Meraki Dashboard",
            "categories": ["Meraki Dashboard", "Device"],
            "url": url
        }]

    if first_ob:
        if first_ob.get("type") == "ip":
            for org_device in org_devices:
                # Check if the IP address matches any of the device's IP addresses
                if first_ob.get("value") in (org_device.get("lanIp"), org_device.get("wan1Ip"), org_device.get("wan2Ip")):
                    dev_url = org_device["url"]
                    break

        elif first_ob.get("type") == 'device':
            mac_address = first_ob['value']

            for org_device in org_devices:
                if org_device.get('mac') == mac_address:
                    dev_url = org_device['url']
                    break

        elif first_ob.get('type') == 'mac_address':
            mac_address = first_ob['value']
            client_info = get_client_info(mac_address)
            dev_url = client_info.get('client_url', dev_url)

    json_refer = construct_json_response(dev_url)
    return jsonify_data(json_refer)
