# 1865 Text Adventure Services

This README contains quick start instructions for setting up the challenge and running it, as well
as general information about each of the services.

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

### Building the Container

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

The service should now be available at `0.0.0.0:31337` (by default).

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

### Quick Caveats to Note

* The `/bin/ps` and `/usr/bin/ps` tool has been disabled to non-root users on the Docker container
    to make it more difficult for players to view other player activity.
* A script is run periodically to clean the known temp directories as well as
    `/opt/wonderland/logs/` so that player files do not persist for too long. Players may experience
    their files disappearing in these clean up sessions. The clean up occurs every 4 minutes.
* The player should never be expected to escalate to root and especially not with a kernel exploit.
    Please ensure that the host kernel is up to date and hardened.
* Some files in the container such as `/home/hatter/invitation_code`,
    `/home/mouse/an-unbirthday-invitation.letter`, and `/home/hatter/secret` are generated at Docker
    container build time. Exploits should be written to take into account the unknowability of these
    files.

## Services

This directory is structured like the following:

* `down-the-rabbithole/` - The Rabbithole Service: Provides the text game entry point for the
    challenge. Written in Python.
* `pool-of-tears/` - The Pool of Tears Service: Provides the auxillary logger server logging
    Rabbithole Service accomplishments. Written in Ruby.
* `a-mad-tea-party/` - The Mad Tea Party Service: Provides an internal target intended for privilege
    escalation. Written in Java.
* `flags/` - Contains the flag files (`flagX`) intended for modification as required.
* `utils/` - Contains the utility scripts used by the Docker container at runtime.
* `xinetd-services/` - Contains the xinetd service definitions used in the Docker container.

### Down the Rabbithole

This is a Python based application that interacts with STDIN and STDOUT to offer a text based
adventure interface. It is exposed on the network via xinetd. The intended vulnerabilities in the
script include a directory traversal bug, an arbitrary read vulnerability, and an instance of
insecure Dill deserialization leading to remote code execution.

This service listens on port 31337 in the container and is the only port forwarded on the host. It
acts as the ingress point for the challenge.

#### Directory Structure

The important files in the service's directory are:

* `art/` - Contains the ANSI art files used in the connection banner.
* `generate_items.py` - The script to generate the serialized in-game objects. Run during the
    container build time.
* `rabbit_conf.py` - Contains some configuration switches. Leaving it default is recommended.
* `rabbithole.py` - The main game logic.
* `requirements.txt` - The Python dependencies file.
* `stories/` - Contains the story tree used by the game to generate the rooms.

### Pool of Tears


### Mad Tea Party
