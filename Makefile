NAME_SHORT:="tr-05-meraki-mx"
NAME:=ciscosecurity/$(NAME_SHORT)
PORT:="9090"
PLATFORM=--platform linux/amd64,linux/arm64
VERSION:=$(shell jq '.VERSION' code/container_settings.json | tr -d '"')

all: env stop build test scout

run: # app locally
	cd code; python -m app; cd -

# Docker
build: stop
	docker buildx build $(PLATFORM) -t $(NAME):$(VERSION) -t $(NAME):latest .
start: build
	docker run -dp $(PORT):$(PORT) --name $(NAME_SHORT) $(NAME):$(VERSION)
stop:
	docker stop $(NAME_SHORT); docker rm $(NAME_SHORT); true
release: build
	docker login
	docker image push --all-tags $(NAME)

# Tools
env:
	pip install --no-cache-dir --upgrade pipenv && pipenv install --dev
black:
	black code/ -l 120 -t py311 --exclude=payloads_for_tests.py
lint: black
	flake8 code/

# Tests
check: lint
	curl -sSfL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh | sh -s --
	docker scout cves $(NAME) --only-fixed
	pip-audit
test: lint
	cd code; coverage run --source api/ -m pytest --verbose tests/unit/ && coverage report --fail-under=80; cd -
test_lf: lint
	cd code; coverage run --source api/ -m pytest --verbose -vv --lf tests/unit/ && coverage report -m --fail-under=80; cd -

