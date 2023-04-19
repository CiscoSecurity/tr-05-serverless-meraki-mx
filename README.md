[![Gitter Chat](https://img.shields.io/badge/gitter-join%20chat-brightgreen.svg)](https://gitter.im/CiscoSecurity/Threat-Response "Gitter Chat")

# Meraki Relay Module for SecureX/XDR

### Developed By

Trey Everson, Mark Orszycki, Jordan Gumby, and Nathan Morgan - Associate Systems Engineers @ Cisco

## Introduction

This project provides a Meraki relay module for SecureX/XDR. It takes event data from the Meraki dashboard and converts it into the Cisco Threat Intelligence Model (CTIM) while using the Meraki API to enrich the sighting with additional data.

The module is built using Python 3.11.2 and includes a demo data feature.

### Implemented Relay Endpoints
- Meraki MX Security Appliance

### Supported Types of Observables
- IP Address
- MAC Address
- Serial Number
- URL
- File Hash
- File Type
- File Canonical Name

## Installation and Setup

Follow these steps to set up the Meraki relay module:

1. Clone the repository onto your local machine:

    `git clone <repo_url>`

2. Install dependencies using `pipenv`. If you don't have `pipenv` installed, you can install it using the following command:

    `pip install pipenv`

    Then, navigate to the project directory and install packages from the `Pipfile`:
    ```
    cd <project_directory>
    pip install --no-cache-dir --upgrade pipenv && pipenv install --dev
    ```
    Enter the virtual environment by running:
    `pipenv shell`

    **Note**: In some cases, certain packages may not install. If this occurs, use `pip` to install them. Some common packages that may fail to install include `flask`, `jwt`, `requests`, `pyjwt`, and `marshmallow`.

4. Run Flask App:
    ```
    cd code
    python app.py
    ```

3. Install `ngrok` using `pip`:
    `pip install ngrok`

4. Start an `ngrok` tunnel with the following command:
    `ngrok http http://127.0.0.1:5000`

5. Copy the `ngrok` public URL into `module_template.json` under the `properties/url` variable.

6. Create a new module in your SecureX/XDR organization by navigating to [this URL](https://visibility.amp.cisco.com/iroh/iroh-int/index.html#/ModuleType/post_iroh_iroh_int_module_type) and pasting in the `module_template.json` from the root of the git repository.
    **Note**: You will need to be authorized into your organization. Ensure you authenticate by clicking the 'authorize' button in the top right of the window.

7. Once the module type is posted, integrate it by supplying the necessary information in SecureX/XDR, such as:

    - Meraki API key
    - Org ID
    - Network ID
    - Entity limit (keep below 20)
    - Demo mode (true/false)

8. You should now be able to run an investigation. If demo mode is selected, you can supply your own demo data or use the provided data and run an investigation on the source/destination IP, MAC, filehash, etc.

## Limitations

- **Meraki API limitation**: When enriching sightings with more information, we obtain some data from the `getOrganizationDevices` and `getOrganizationClientsSearch` APIs. Currently, we make a request per device. We are developing an updated version that will call the API once and save the output to be queried locally instead.
- **Meraki API limitation**: We have implemented two Meraki APIs to get events (`getNetworkEvents` and `getNetworkApplianceSecurityEvents`). These APIs only allow querying one event type, so we must make three calls to get events. This bug has been reported to the Meraki API team.
- Some refer actions may not populate correctly if the device is not within the network.
- Some packages may not install through `pipenv` for an unknown reason. We may transition to using a `requirements.txt` file with `pip` in the future.
- Currently not verifying JWT audience token because we are hosting locally. When hosted on `visibility.amp.cisco.com` we will be able to verify.


## Testing (Optional)

Open the code folder in your terminal.
```
cd code
```

You can perform two kinds of testing:

- Run static code analysis checking for any semantic discrepancies and
[PEP 8](https://www.python.org/dev/peps/pep-0008/) compliance:

  `flake8 .`

- Run the suite of unit tests and measure the code coverage:

  `coverage run --source api/ -m pytest --verbose tests/unit/ && coverage report`
