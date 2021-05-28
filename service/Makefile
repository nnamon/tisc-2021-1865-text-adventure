tag = tisc-2021-wonderland
port = 1337

build:
	docker build -t $(tag) --file Dockerfile .

run:
	docker run -it --rm -p 31337:31337 $(tag)

dev:
	docker run -it --rm -p 31337:31337 -v `pwd`:/opt/wonderland/ $(tag) /bin/bash
