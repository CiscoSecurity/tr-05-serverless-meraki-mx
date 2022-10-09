[![Gitter Chat](https://img.shields.io/badge/gitter-join%20chat-brightgreen.svg)](https://gitter.im/CiscoSecurity/Threat-Response "Gitter Chat")

# Docker Relay Template (Cisco Hosted)

Generic Docker Relay template not bound to any real third-party Cyber Threat
Intelligence service provider.

**NOTE.** The template aims to show the general structure for future
implementations. It also provides a couple of utility functions that might be
handy. Keep in mind that the main idea here is to just give you a hint of a
possible approach rather than enforcing you to do everything exactly the same
way.

The Relay itself is just a simple application written in Python that can be
easily packaged and deployed in docker container.

## Rationale

- We need an application that will translate API requests from SecureX Threat Response to the third-party integration, and vice versa.
- We need an application that can be completely self contained within a virtualized container using Docker.

## Testing (Optional)

Open the code folder in your terminal.
```
cd code
```

If you want to test the application you have to install dependencies from the [Pipfile](code/Pipfile) file:
```
pip install --no-cache-dir --upgrade pipenv && pipenv install --dev
```

You can perform two kinds of testing:

- Run static code analysis checking for any semantic discrepancies and
[PEP 8](https://www.python.org/dev/peps/pep-0008/) compliance:

  `flake8 .`

- Run the suite of unit tests and measure the code coverage:

  `coverage run --source api/ -m pytest --verbose tests/unit/ && coverage report`

### Building the Docker Container
In order to build the application, we need to use a `Dockerfile`.  

 1. Open a terminal.  Build the container image using the `docker build` command.

```
docker build -t tr-05-docker-relay .
```

 2. Once the container is built, and an image is successfully created, start your container using the `docker run` command and specify the name of the image we have just created.  By default, the container will listen for HTTP requests using port 9090.

```
docker run -dp 9090:9090 --name tr-05-docker-relay tr-05-docker-relay
```

 3. Watch the container logs to ensure it starts correctly.

```
docker logs tr-05-docker-relay
```

 4. Once the container has started correctly, open your web browser to http://localhost:9090.  You should see a response from the container.

```
curl http://localhost:9090
```

## Implementation Details

This application was developed and tested under Python version 3.9.

**NOTE.** Remember that this application is just a template so here `N/A` means
that it has no implemented Relay endpoints and supported types of observables.
That will not be the case for real integrations with third-party services so
you may consider the following sections as some placeholders.

### Implemented Relay Endpoints

`N/A`

### Supported Types of Observables

`N/A`
