# 1865 Text Adventure

## Overview



### Required Knowledge

These are some of the topics required to solve the entire challenge.

* General Scripting
* Directory Traversal
* Source Code Review
    * Shell Script
    * Python
    * Ruby
    * Java
* Linux Privilege Escalation
    * Between different user accounts.
    * Identify viable strategies to create SUID binaries, obtain reverse shells, etc.
* Python Pickle/Dill Exploitation
    * Unfortunately, the common Internet payloads will not work due to a filter.
    * Need to know how to modify the `__reduce__` method to return bytecode to pass the filter.
    * Alternatively, need to know how to use Dill and setup the environment such that payloads
        containing arbitrary hooks are called.
* URL Encoding
    * To abuse an arbitrary file write with filename suffix control.
* Ruby and Rails Reflection
    * Need to understand how `constantize` and `public_send` can be used to invoke arbitrary
        methods.
* Hash Length Extension Attack
    * Applied against the Base64 format where non-valid bytes are ignored.
* Protobuf Wire Protocol
    * In order to fake a serialized byte field and append it to the originally generated binary
        dump.
* FST Serialization
    * This is actually a novel deserialization vector, so this requirement is actually a trick!
    * Requires the player to research the library and apply it to previously known Java
        deserialization gadgets.

## Recommend Challenge Descriptions

### 1865 Text Adventure - Down the Rabbit Hole

### 1865 Text Adventure - Pool of Tears

### 1865 Text Adventure - Advice from a Caterpillar

### 1865 Text Adventure - A Mad Tea Party

## Setup

### Updates to the Codebase

Update the flags in `../service/flags`. There should be four flags in total named `flag1` to
`flag4`.

Check that the process limits in `service/Dockerfile` are suitable for the CTF load. A lower number
helps to prevent resource exhaustion attacks by annoying players but may interfere with the number
of concurrent users supported.`

```dockerfile
# Some protections
RUN echo "$USER1     hard    nproc       50" >> /etc/security/limits.conf
RUN echo "$USER2     hard    nproc       50" >> /etc/security/limits.conf
RUN echo "$USER3     hard    nproc       50" >> /etc/security/limits.conf
```

### Testing

AAAA
