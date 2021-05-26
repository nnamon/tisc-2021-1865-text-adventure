tag = tisc-2021-wonderland-soln

build:
	docker build -t $(tag) --file Dockerfile .

run:
	docker run -it --rm -v `pwd`:/opt/wonderland/ $(tag)
