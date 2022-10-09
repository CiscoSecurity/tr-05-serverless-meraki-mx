import json


class Config:
    settings = json.load(open('container_settings.json', 'r'))
    VERSION = settings["VERSION"]
    CTIM_DEFAULTS = {
        'schema_version': '1.1.12',
    }

    SOURCE = 'Cisco Meraki MX'
    RELATIONS_DEFAULTS = {
        "origin": SOURCE,
        "relation": 'Connected_To'
    }
    SIGHTING_DEFAULTS = {
        **CTIM_DEFAULTS,
        'type': 'sighting',
        'source': SOURCE,
    }
