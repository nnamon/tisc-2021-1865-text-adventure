# 1865 Text Adventure Services

## Setup

### Requirements

1. Docker
2. Make

### Updates to the Codebase

1. Update the flags in `service/flags/`. There should be four flags in total named `flag1` to
`flag4`.

2. Check that the process limits in `service/Dockerfile` are suitable for the CTF load. A lower
   number helps to prevent resource exhaustion attacks by annoying players but may interfere with
   the number of concurrent users supported.

```dockerfile
# Some protections
RUN echo "$USER1     hard    nproc       50" >> /etc/security/limits.conf
RUN echo "$USER2     hard    nproc       50" >> /etc/security/limits.conf
RUN echo "$USER3     hard    nproc       50" >> /etc/security/limits.conf
```

3. The default entry port is set to `31337`. To change this, the host bind port in
`service/Makefile` can be changed. The tag can be changed here as well.

```makefile
tag = tisc-2021-wonderland
port = <port>
```

### Building the Service

To build the Docker container hosting the service run the following in the `service` directory:

```shell
$ make build
```

The default tag of the image is `tisc-2021-wonderland`.

## Running

### Running for Production

To run the container in the background.

```shell
$ make daemon
```

To run the container in the forground:

```shell
$ make run
```

### Running for Development

If a development session is required, the following command will drop you into a `/bin/bash` root
shell with the `services` directory mounted so that edits to the files will be reflected in the
container:

```shell
$ make dev
```

To run all of the services, run the following command in the root shell:

```shell
root@1e96ab81dc2f:/opt/wonderland# ./utils/main.sh
```
