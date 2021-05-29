# 1865 Text Adventure Services

## Setup

### Updates to the Codebase

1. Update the flags in `../service/flags`. There should be four flags in total named `flag1` to
`flag4`.

2. Check that the process limits in `service/Dockerfile` are suitable for the CTF load. A lower number
helps to prevent resource exhaustion attacks by annoying players but may interfere with the number
of concurrent users supported.

```dockerfile
# Some protections
RUN echo "$USER1     hard    nproc       50" >> /etc/security/limits.conf
RUN echo "$USER2     hard    nproc       50" >> /etc/security/limits.conf
RUN echo "$USER3     hard    nproc       50" >> /etc/security/limits.conf
```

3. The default entry port is set to `31337`. To change this, the host bind port in
`service/Makefile` can be changed.

```makefile
run:
	docker run -it --rm -p <port>:31337 $(tag)
```

### Building the Service


## Running
