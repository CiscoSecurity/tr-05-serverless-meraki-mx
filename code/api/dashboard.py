import datetime

import dateutil.parser
import meraki
from flask import Blueprint, request

from .utils import get_jwt, jsonify_data

meraki_base_url = "https://api.meraki.com/api/v1"
meraki_user_agent = "MerakiRelayModuleForCiscoXDR Cisco"

tiles_api = Blueprint("tiles", __name__)
dashboard_api = Blueprint("dashboard", __name__)


def get_tile_data_definition(tile_id, timespan=None):
    in_vals = get_jwt()
    in_list = in_vals

    if tile_id == "meraki_device_summary":
        dashboard = meraki.DashboardAPI(
            base_url=meraki_base_url,
            api_key=in_list["API_KEY"],
            print_console=False,
            output_log=False,
            caller=meraki_user_agent,
            suppress_logging=True,
        )

        dev_stat = dashboard.organizations.getOrganizationDevicesStatuses(in_list["ORG_ID"], total_pages=10)

        tile_data = [
            {"value": 0, "icon": "device-type", "link_uri": "https://dashboard.meraki.com", "label": "Total Devices"},
            {"value": 0, "icon": "device-type", "link_uri": "https://dashboard.meraki.com", "label": "Online Devices"},
            {"value": 0, "icon": "device-type", "link_uri": "https://dashboard.meraki.com", "label": "Offline Devices"},
        ]
        for d in dev_stat:
            tile_data[0]["value"] += 1
            if d["status"] == "online":
                tile_data[1]["value"] += 1
            elif d["status"] == "offline":
                tile_data[2]["value"] += 1

        return tile_data, None
    elif tile_id == "meraki_device_summary_by_type":
        dashboard = meraki.DashboardAPI(
            base_url=meraki_base_url,
            api_key=in_list["API_KEY"],
            print_console=False,
            output_log=False,
            caller=meraki_user_agent,
            suppress_logging=True,
        )

        dev_stat = dashboard.organizations.getOrganizationDevices(in_list["ORG_ID"])

        tile_data = [
            {
                "value": 0,
                "icon": "device-type",
                "link_uri": "https://dashboard.meraki.com",
                "label": "Cellular Gateways",
            },
            {"value": 0, "icon": "device-type", "link_uri": "https://dashboard.meraki.com", "label": "Appliances"},
            {"value": 0, "icon": "device-type", "link_uri": "https://dashboard.meraki.com", "label": "Switches"},
            {"value": 0, "icon": "device-type", "link_uri": "https://dashboard.meraki.com", "label": "Access Points"},
            {"value": 0, "icon": "device-type", "link_uri": "https://dashboard.meraki.com", "label": "Cameras"},
            {"value": 0, "icon": "device-type", "link_uri": "https://dashboard.meraki.com", "label": "Sensors"},
            {"value": 0, "icon": "device-type", "link_uri": "https://dashboard.meraki.com", "label": "Other"},
        ]
        for d in dev_stat:
            if d["model"][:2] == "MG":
                tile_data[0]["value"] += 1
            elif d["model"][:3] == "vMX" or d["model"][:2] == "MX" or d["model"][:1] == "Z":
                tile_data[1]["value"] += 1
            elif d["model"][:2] == "MS":
                tile_data[2]["value"] += 1
            elif d["model"][:2] == "MR":
                tile_data[3]["value"] += 1
            elif d["model"][:2] == "MV":
                tile_data[4]["value"] += 1
            elif d["model"][:2] == "MT":
                tile_data[5]["value"] += 1
            else:
                tile_data[6]["value"] += 1

        return tile_data, None
    elif tile_id == "meraki_device_bar_chart":
        dashboard = meraki.DashboardAPI(
            base_url=meraki_base_url,
            api_key=in_list["API_KEY"],
            print_console=False,
            output_log=False,
            caller=meraki_user_agent,
            suppress_logging=True,
        )

        dev_stat = dashboard.organizations.getOrganizationDevicesStatuses(in_list["ORG_ID"], total_pages=10)
        dev_list = dashboard.organizations.getOrganizationDevices(in_list["ORG_ID"])

        tile_extras = {
            "keys": [
                {"key": "device_online", "label": "Devices Online"},
                {"key": "device_offline", "label": "Devices Offline"},
            ],
            "key_type": "string",
        }

        devices = {}
        for d in dev_stat:
            if d["serial"] in devices:
                devices[d["serial"]]["status"] = d
            else:
                devices[d["serial"]] = {"status": d}

        for d in dev_list:
            if d["serial"] in devices:
                devices[d["serial"]]["info"] = d
            else:
                devices[d["serial"]] = {"info": d}

        tile_data = [
            {
                "key": "MG",
                "values": [
                    {"key": "device_online", "value": 0, "tooltip": "Devices Online: 0"},
                    {"key": "device_offline", "value": 0, "tooltip": "Devices Offline: 0"},
                ],
            },
            {
                "key": "MX",
                "values": [
                    {"key": "device_online", "value": 0, "tooltip": "Devices Online: 0"},
                    {"key": "device_offline", "value": 0, "tooltip": "Devices Offline: 0"},
                ],
            },
            {
                "key": "MS",
                "values": [
                    {"key": "device_online", "value": 0, "tooltip": "Devices Online: 0"},
                    {"key": "device_offline", "value": 0, "tooltip": "Devices Offline: 0"},
                ],
            },
            {
                "key": "MR",
                "values": [
                    {"key": "device_online", "value": 0, "tooltip": "Devices Online: 0"},
                    {"key": "device_offline", "value": 0, "tooltip": "Devices Offline: 0"},
                ],
            },
            {
                "key": "MV",
                "values": [
                    {"key": "device_online", "value": 0, "tooltip": "Devices Online: 0"},
                    {"key": "device_offline", "value": 0, "tooltip": "Devices Offline: 0"},
                ],
            },
            {
                "key": "MT",
                "values": [
                    {"key": "device_online", "value": 0, "tooltip": "Devices Online: 0"},
                    {"key": "device_offline", "value": 0, "tooltip": "Devices Offline: 0"},
                ],
            },
            {
                "key": "Other",
                "values": [
                    {"key": "device_online", "value": 0, "tooltip": "Devices Online: 0"},
                    {"key": "device_offline", "value": 0, "tooltip": "Devices Offline: 0"},
                ],
            },
        ]

        for d in devices:
            dev_model = devices[d].get("info", {"model": "UNKNOWN"}).get("model", "")
            dev_stat = devices[d].get("status", {"status": "Unknown"}).get("status", "")
            if dev_model[:2] == "MG":
                if dev_stat == "online":
                    tile_data[0]["values"][0]["value"] += 1
                    tile_data[0]["values"][0]["tooltip"] = "Devices Online: " + str(tile_data[0]["values"][0]["value"])
                else:
                    tile_data[0]["values"][1]["value"] += 1
                    tile_data[0]["values"][1]["tooltip"] = "Devices Offline: " + str(tile_data[0]["values"][1]["value"])
            elif dev_model[:3] == "vMX" or dev_model[:2] == "MX" or dev_model[:1] == "Z":
                if dev_stat == "online":
                    tile_data[1]["values"][0]["value"] += 1
                    tile_data[1]["values"][0]["tooltip"] = "Devices Online: " + str(tile_data[1]["values"][0]["value"])
                else:
                    tile_data[1]["values"][1]["value"] += 1
                    tile_data[1]["values"][1]["tooltip"] = "Devices Offline: " + str(tile_data[1]["values"][1]["value"])
            elif dev_model[:2] == "MS":
                if dev_stat == "online":
                    tile_data[2]["values"][0]["value"] += 1
                    tile_data[2]["values"][0]["tooltip"] = "Devices Online: " + str(tile_data[2]["values"][0]["value"])
                else:
                    tile_data[2]["values"][1]["value"] += 1
                    tile_data[2]["values"][1]["tooltip"] = "Devices Offline: " + str(tile_data[2]["values"][1]["value"])
            elif dev_model[:2] == "MR":
                if dev_stat == "online":
                    tile_data[3]["values"][0]["value"] += 1
                    tile_data[3]["values"][0]["tooltip"] = "Devices Online: " + str(tile_data[3]["values"][0]["value"])
                else:
                    tile_data[3]["values"][1]["value"] += 1
                    tile_data[3]["values"][1]["tooltip"] = "Devices Offline: " + str(tile_data[3]["values"][1]["value"])
            elif dev_model[:2] == "MV":
                if dev_stat == "online":
                    tile_data[4]["values"][0]["value"] += 1
                    tile_data[4]["values"][0]["tooltip"] = "Devices Online: " + str(tile_data[4]["values"][0]["value"])
                else:
                    tile_data[4]["values"][1]["value"] += 1
                    tile_data[4]["values"][1]["tooltip"] = "Devices Offline: " + str(tile_data[4]["values"][1]["value"])
            elif dev_model[:2] == "MT":
                if dev_stat == "online":
                    tile_data[5]["values"][0]["value"] += 1
                    tile_data[5]["values"][0]["tooltip"] = "Devices Online: " + str(tile_data[5]["values"][0]["value"])
                else:
                    tile_data[5]["values"][1]["value"] += 1
                    tile_data[5]["values"][1]["tooltip"] = "Devices Offline: " + str(tile_data[5]["values"][1]["value"])
            else:
                if dev_stat == "online":
                    tile_data[6]["values"][0]["value"] += 1
                    tile_data[6]["values"][0]["tooltip"] = "Devices Online: " + str(tile_data[6]["values"][0]["value"])
                else:
                    tile_data[6]["values"][1]["value"] += 1
                    tile_data[6]["values"][1]["tooltip"] = "Devices Offline: " + str(tile_data[6]["values"][1]["value"])

        if tile_data[6]["values"][0]["value"] == 0 and tile_data[6]["values"][1]["value"] == 0:
            del tile_data[6]

        return tile_data, tile_extras
    elif tile_id == "meraki_security_events":
        dashboard = meraki.DashboardAPI(
            base_url=meraki_base_url,
            api_key=in_list["API_KEY"],
            print_console=False,
            output_log=False,
            caller=meraki_user_agent,
            suppress_logging=True,
        )

        ct = datetime.datetime.utcnow()
        start_time = (ct + datetime.timedelta(hours=-1)).isoformat() + "Z"
        end_time = ct.isoformat() + "Z"
        dev_stat = dashboard.appliance.getOrganizationApplianceSecurityEvents(
            in_list["ORG_ID"], total_pages=10, sortOrder="descending", perPage=1000, t0=start_time, t1=end_time
        )

        tile_data = [
            {"value": 0, "icon": "device-type", "link_uri": "https://dashboard.meraki.com", "label": "Total Events"},
            {"value": 0, "icon": "device-type", "link_uri": "https://dashboard.meraki.com", "label": "IDS/IPS Events"},
            {"value": 0, "icon": "device-type", "link_uri": "https://dashboard.meraki.com", "label": "Malware Events"},
            {"value": 0, "icon": "device-type", "link_uri": "https://dashboard.meraki.com", "label": "Other"},
        ]
        for d in dev_stat:
            tile_data[0]["value"] += 1
            if d["eventType"] == "IDS Alert":
                tile_data[1]["value"] += 1
            elif d["eventType"] == "File Scanned":
                tile_data[2]["value"] += 1
            else:
                tile_data[3]["value"] += 1

        if tile_data[3]["value"] == 0:
            del tile_data[3]

        return tile_data, None
    elif tile_id == "meraki_security_events_chart":
        dashboard = meraki.DashboardAPI(
            base_url=meraki_base_url,
            api_key=in_list["API_KEY"],
            print_console=False,
            output_log=False,
            caller=meraki_user_agent,
            suppress_logging=True,
        )

        ct = datetime.datetime.utcnow()
        if timespan == "last_hour":
            delta = -1
            increments = [0, 10, 20, 30, 40, 50]
            chart_range = "hours"
        elif timespan == "last_24_hours":
            delta = -24
            increments = [0, 240, 480, 720, 960, 1200]
            chart_range = "hours"
        elif timespan == "last_7_days":
            delta = -168
            increments = [0, 1440, 2880, 4320, 5760, 7200, 8640]
            chart_range = "days"
        elif timespan == "last_30_days":
            delta = -720
            increments = [0, 10080, 20160, 30240]
            chart_range = "days"
        elif timespan == "last_60_days":
            delta = -1440
            increments = [0, 20160, 40320, 60480]
            chart_range = "days"
        elif timespan == "last_90_days":
            delta = -2160
            increments = [0, 30240, 60480, 90720]
            chart_range = "days"
        else:
            delta = -1
            increments = [0]
            chart_range = "hours"

        start_time_obj = ct + datetime.timedelta(hours=delta)
        start_time = start_time_obj.isoformat() + "Z"
        end_time = ct.isoformat() + "Z"
        dev_stat = dashboard.appliance.getOrganizationApplianceSecurityEvents(
            in_list["ORG_ID"], total_pages=2, sortOrder="descending", perPage=1000, t0=start_time, t1=end_time
        )

        tile_extras = {
            "keys": [
                {"key": "event_ids", "label": "IDS/IPS Events"},
                {"key": "event_amp", "label": "Malware Events"},
                {"key": "event_unk", "label": "Unknown Events"},
            ],
            "key_type": "string",
        }

        tile_data = []
        ts_increments = []
        for increment in increments:
            ts_increments.append(start_time_obj + datetime.timedelta(minutes=increment))
            s_o = ts_increments[len(ts_increments) - 1]
            e_o = s_o + datetime.timedelta(minutes=increments[1])
            if chart_range == "hours":
                s_txt = str(s_o.hour) + ":" + str(s_o.minute).zfill(2)
                e_txt = str(e_o.hour) + ":" + str(e_o.minute).zfill(2)
            else:
                s_txt = str(s_o.month).zfill(2) + "/" + str(s_o.day).zfill(2)
                e_txt = str(e_o.month).zfill(2) + "/" + str(e_o.day).zfill(2)

            tile_data.append(
                {
                    # "key": (start_time_obj + datetime.timedelta(minutes=increment)),
                    "key": s_txt + "-" + e_txt,
                    "values": [
                        {"key": "event_ids", "value": 0, "tooltip": "IDS/IPS Events: 0"},
                        {"key": "event_amp", "value": 0, "tooltip": "Malware Events: 0"},
                        {"key": "event_unk", "value": 0, "tooltip": "Unknown Events: 0"},
                    ],
                }
            )
        ts_increments.append(ct)

        for d in dev_stat:
            ts = d.get("ts", "1970-01-01T00:00:00.000000Z")
            ev_type = d.get("eventType", "Unknown")
            ts_obj = dateutil.parser.parse(ts).replace(tzinfo=None)
            for increment in range(0, len(ts_increments) - 1):
                if ts_obj > ts_increments[increment] and ts_obj < ts_increments[increment + 1]:
                    if ev_type == "IDS Alert":
                        tile_data[increment]["values"][0]["value"] += 1
                        tile_data[increment]["values"][0]["tooltip"] = "IDS/IPS Events: " + str(
                            tile_data[increment]["values"][0]["value"]
                        )
                    elif ev_type == "File Scanned":
                        tile_data[increment]["values"][1]["value"] += 1
                        tile_data[increment]["values"][1]["tooltip"] = "Malware Events: " + str(
                            tile_data[increment]["values"][1]["value"]
                        )
                    else:
                        tile_data[increment]["values"][2]["value"] += 1
                        tile_data[increment]["values"][2]["tooltip"] = "Unknown Events: " + str(
                            tile_data[increment]["values"][2]["value"]
                        )

        return tile_data, tile_extras
    elif tile_id == "server_image":
        tile_data = ["![image](https://51e372f4310f.ngrok.io/static/server.png)"]
        return tile_data, None
    elif tile_id == "server_summary":
        tile_data = [
            "| **Parameter**    | **State**           |",
            "| ---------------- | ------------------- |",
            "| Health           | Critical            |",
            "| Name             | C220-FCH2038V37D    |",
            "| User Label       | -                   |",
            "| Management IP    | 192.168.250.22      |",
            "| Serial           | FCH2038V37D         |",
            "| PID              | UCSC-C220-M4S       |",
            "| Vendor           | Cisco Systems Inc   |",
            "| Revision         | -                   |",
            "| Asset Tag        | ESXI 6              |",
            "| License Tier     | Essentials          |",
            "| Contract Status  | Not Covered         |",
            "| Management Mode  | Standalone          |",
            "| Firmware Version | 4.0(1g)             |",
            "| Organizations    | default             |",
            "| Tags             | -                   |",
        ]
        return tile_data, None
    elif tile_id == "server_specs":
        tile_data = [
            "| **Component**         | **Detail**     |",
            "| --------------------- | -------------- |",
            "| CPUs                  | 2              |",
            "| Threads               | 40             |",
            "| CPU Cores             | 20             |",
            "| CPU Cores Enabled     | 20             |",
            "| Memory Capacity (GiB) | 128.0          |",
            "| CPU Capacity (GHz)    | 44.0           |",
        ]
        return tile_data, None
    elif tile_id == "server_events":
        tile_data = [
            "| **Date/Time**         | **Event** | **Message**                                                    |",
            "| --------------------- | --------- | -------------------------------------------------------------- |",
            "| Jul 21, 2020 1:21 PM  | UCS-F0743 | Power Supply redundancy is lost or non-redundant               |",
            "| Jul 21, 2020 1:22 PM  | UCS-F0717 | Management Interface Link Down : LOM_EXT_LOM_P1                |",
            "| Jul 21, 2020 1:21 PM  | UCS-F0883 | Power supply 1 is in a degraded state or has bad input voltage |",
            "| Jul 21, 2020 1:21 PM  | UCS-F0374 | Power Supply 1 has lost input or input is out of range         |",
        ]
        return tile_data, None
    return {}, None


def get_tile_definition(tile_id):
    if tile_id == "meraki_device_summary":
        return {
            "description": "Meraki Device Status Summary provides an overview of the state "
            "of all of your configured devices from within the SecureX platform.",
            "periods": ["last_hour"],
            "tags": ["Meraki"],
            "type": "metric_group",
            "short_description": "Meraki Device Status Summary",
            "title": "Meraki Device Summary",
            "id": "meraki_device_summary",
        }
    elif tile_id == "meraki_device_summary_by_type":
        return {
            "description": "Meraki Device Type Summary provides an overview of the state "
            "of all of your configured devices from within the SecureX platform.",
            "periods": ["last_hour"],
            "tags": ["Meraki"],
            "type": "metric_group",
            "short_description": "Meraki Device Type Summary",
            "title": "Meraki Device Type Summary",
            "id": "meraki_device_summary_by_type",
        }
    elif tile_id == "meraki_device_bar_chart":
        return {
            "description": "Meraki Device Summary provides an overview of the state "
            "of all of your configured devices from within the SecureX platform.",
            "periods": ["last_hour"],
            "tags": ["Meraki"],
            "type": "vertical_bar_chart",
            "short_description": "Meraki Device Summary",
            "title": "Meraki Device Summary",
            "id": "meraki_device_bar_chart",
        }
    elif tile_id == "meraki_security_events":
        return {
            "description": "Meraki Security Events Summary provides an overview "
            "of the number of security events from Meraki Dashboard.",
            "periods": ["last_hour"],
            "tags": ["Meraki"],
            "type": "metric_group",
            "short_description": "Meraki Security Event Summary",
            "title": "Meraki Security Event Summary",
            "id": "meraki_security_events",
        }
    elif tile_id == "meraki_security_events_chart":
        return {
            "description": "Meraki Security Events provides an overview "
            "of the number of security events from Meraki Dashboard.",
            "periods": ["last_hour", "last_24_hours", "last_7_days", "last_30_days", "last_60_days", "last_90_days"],
            "tags": ["Meraki"],
            "type": "horizontal_bar_chart",
            "short_description": "Meraki Security Events",
            "title": "Meraki Security Events",
            "id": "meraki_security_events_chart",
        }
    elif tile_id == "server_image":
        return {
            "description": "Server Image test.",
            "periods": [
                "last_hour",
            ],
            "tags": ["UCS"],
            "type": "markdown",
            "short_description": "Server Image Test",
            "title": "Server Overview",
            "id": "server_image",
        }
    elif tile_id == "server_summary":
        return {
            "description": "Server Summary test.",
            "periods": [
                "last_hour",
            ],
            "tags": ["UCS"],
            "type": "markdown",
            "short_description": "Server Summary Test",
            "title": "Server Summary",
            "id": "server_summary",
        }
    elif tile_id == "server_specs":
        return {
            "description": "Server Spec test.",
            "periods": [
                "last_hour",
            ],
            "tags": ["UCS"],
            "type": "markdown",
            "short_description": "Server Spec Test",
            "title": "Server Specs",
            "id": "server_specs",
        }
    elif tile_id == "server_events":
        return {
            "description": "Server Events test.",
            "periods": [
                "last_hour",
            ],
            "tags": ["UCS"],
            "type": "markdown",
            "short_description": "Server Events Test",
            "title": "Server Events",
            "id": "server_events",
        }
    return {}


@dashboard_api.route("/tiles", methods=["POST"])
def get_tiles():
    tiles = []
    # tile_definitions = [
    #     "meraki_device_summary",
    #     "meraki_device_summary_by_type",
    #     "meraki_security_events",
    #     "meraki_device_bar_chart",
    #     "meraki_security_events_chart",
    # ]
    # tile_definitions = [
    #     "meraki_device_bar_chart",
    #     "meraki_security_events_chart",
    #     "server_image",
    #     "server_summary",
    #     "server_specs",
    #     "server_events",
    # ]
    tile_definitions = ["meraki_device_bar_chart", "meraki_security_events_chart"]
    for t in tile_definitions:
        tiles.append(get_tile_definition(t))

    return jsonify_data(tiles)


@dashboard_api.route("/tiles/tile", methods=["POST"])
def get_tiles_tile():
    json_data = request.json
    tid = json_data.get("tile_id")
    if tid:
        tile = get_tile_definition(tid)
    else:
        tile = {}

    return jsonify_data(tile)


@dashboard_api.route("/tiles/tile-data", methods=["POST"])
def get_tile_data():
    json_data = request.json
    tid = json_data.get("tile_id")
    tts = json_data.get("period")

    tile_data, tile_extras = get_tile_data_definition(tid, tts)

    ct = datetime.datetime.utcnow()
    tile_base = {
        "valid_time": {
            "start_time": ct.isoformat() + "Z",
            "end_time": (ct + datetime.timedelta(minutes=1)).isoformat() + "Z",
        },
        "observed_time": {"start_time": ct.isoformat() + "Z", "end_time": ct.isoformat() + "Z"},
        "cache_scope": "org",
        "period": "last_hour",
        "data": tile_data,
    }

    if tile_extras:
        return jsonify_data({**tile_base, **tile_extras})
    else:
        return jsonify_data(tile_base)
