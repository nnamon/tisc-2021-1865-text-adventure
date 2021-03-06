# 1865 Text Adventure

*for TISC 2021 by Jeremy Heng*

## Overview

This exploitation and crypto challenge takes the form of a text adventure based on Lewis Caroll's
Alice in Wonderland. The challenge primarily revolves around different forms of insecure
deserialization. Both the services and solutions are packaged in docker containers.

It is broken up into four stages which require the participant to obtain distinct flags by
leveraging bugs in three different applications. Each stage is designed to represent the acquisition
of a new attacker capability and ramps up in difficulty heavily. The final stage involves the
exploitation of a novel deserialization vector in which no public payload generation tool currently
exists.

The initial text adventure game is written in Python which runs the story based on a structure
closely tied to the Unix file system. This design leads to a directory traversal vulnerability which
allows arbitrary file reads as well as a dill deserialization bug when interacting with in-world
items. The caveat here is that the standard Pickle payload will not work as there is some moderate
filtering of the bytecode through disassembly before deserialization. This is the
`down-the-rabbithole` service.

This application is serviced by a 'logger' written in Ruby that contains a controlled file write
primitive that allows the attacker to create arbitrary game items. It also has Ruby reflection
issues (`constantize` and `public_send`) which can lead to the invocation of arbitrary code. This is
the `pool-of-tears` service.

Finally, there is a locally running Java service that presents a 'tea party' interface that allows
for the creation of a fancy cake. This cake object is mostly represented as a protobuf message but
contains a bytes field encapsulating a `Fireworks` object. This object is stored as FST serialized
data. The cake object can be exported as base64 encoded protobuf but is signed with an insecure
keyed hash scheme allowing for hash length extension attacks. Since the base64 decoder drops invalid
bytes and the protobuf wire format allows for the concatenation of new fields, the attacker can
coerce the application into deserializing the FST payload, allowing for arbitrary code execution.
This is the `a-mad-tea-party` service.

To exploit the final novel FST deserialization vector, an accompanying private fork of ysoserial is
included with the solutions in this submission.

![Introduction to the Game](img/alice_in_wonderland_intro.gif)

### Challenge Theme

The challenge was written for TISC 2021. The storyline for the CTF involves a major cyber attack
disrupting several of Singapore's critical infrastructure and cyber space assets. The participants
are cybersecurity experts pursuing the malicious and mischevious threat actor, PALINDROME. This
challenge loosely follows this premise and contains references to the entity.

### Summary of the Stages

The following stages each have a corresponding flag:

1. Arbitrary File Read in the `down-the-rabbithole` service as the `rabbit` user via the Teleport
    command granted by the `looking-glass` object.
    * Read the flag `/home/rabbit/flag1`.
2. Arbitrary Code Execution in the `down-the-rabbithole` service as the `rabbit` user via insecure
    deserialization of properly crafted dill serialized data written via an suffix controlled file
    write.
    * Execute the SUID binary `/home/rabbit/flag2.bin`.
3. Arbitrary Code Execution in the `pool-of-tears` service as the `mouse` user via insecure
   reflection.
   * Execute the SUID binary `/home/mouse/flag3.bin`.
4. Arbitrary Code Execution in the `a-mad-tea-party` service as the `hatter` user via insecure FST
   deserialization where the keyed hash authenticated protobuf data is forged with the hash length
   extension attack.
   * Read the flag `/home/mouse/flag4`.

### Required Knowledge

These are some of the topics required to solve the entire challenge.

* General Scripting and Exploit Development
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

## Recommended Challenge Stage Descriptions

This section contains the recommended challenge stage descriptions as well as optional hints.

### 1865 Text Adventure - 1. Down the Rabbit Hole

**Description**

```
Text adventures are fading ghosts of a faraway past but this one looks suspiciously brand new... and
it has the signs of PALINDROME all over it.

Our analysts believe that we need to learn more about the White Rabbit but when we connect to the
game, we just keep getting lost!

Can you help us access the secrets left in the Rabbit's burrow?

The game is hosted at <CHANGE ME>:31337.

No kernel exploits are required for this challenge.
```

**Hint 1**

```
The goal is to read /home/rabbit/flag1.
```

**Hint 2**

```
Can you find a way to break out of the illusionary fantasy? Instant travel can be a very good way of
defying the laws of (video game) physics.
```

**Default Flag**

`TISC{r4bbb1t_kn3w_1_pr3f3r_p1}`

### 1865 Text Adventure - 2. Pool of Tears

**Description**

```
It looks like the Rabbit knew too much about PALINDROME. Within his cache of secrets lies a special
device that might just unlock clues to tracking down the elusive trickster. However, our attempts
read it yield pure gibberish.

It appears to require... activation. To activate it, we must first become the Rabbit.

Please assume the identity of the Rabbit.

The game is hosted at <CHANGE ME>:31337.

No kernel exploits are required for this challenge.
```

**Hint 1**

```
The goal is to execute the SUID binary /home/rabbit/flag2.bin.
```

**Hint 2**

```
Find a way to write what you want then take it. If sauerkraut doesn't work, try kimchi.
```

**Default Flag**

`TISC{dr4b_4s_a_f00l_as_al00f_a5_A_b4rd}`

### 1865 Text Adventure - 3. Advice from a Caterpillar

**Description**

```
PALINDROME's taunts are clear: they await us at the Tea Party hosted by the Mad Hatter and
the March Hare. We need to gain access to it as soon as possible before it's over.

The flowers said that the French Mouse was invited. Perhaps she hid the invitation in her warren. It
is said that her home is decorated with all sorts of oddly shaped mirrors but the tragic thing is
that she's afraid of her own reflection.

The game is hosted at <CHANGE ME>:31337.

No kernel exploits are required for this challenge.
```

**Hint 1**

```
The goal is to execute the SUID binary /home/mouse/flag3.bin.
```

**Hint 2**

```
Can you make strings into constants somehow? Do those constants mean anything to Ruby?
```

**Default Flag**

`TISC{mu5t_53ll_4t_th3_t4l13sT_5UM}`

### 1865 Text Adventure - 4. A Mad Tea Party

**Description**

```
Great! We have all we need to attend the Tea Party!

To get an idea of what to expect, we've consulted with our informant (initials C.C) who advised:

"Attend the Mad Tea Party.
Come back with (what's in) the Hatter's head.
Sometimes the end of a tale might not be the end of the story.
Things that don't make logical sense can safely be ignored.
Do not eat that tiny Hello Kitty."

This is nonsense to us, so you're on your own from here on out.

The game is hosted at <CHANGE ME>:31337.

No kernel exploits are required for this challenge.
```

**Hint 1**

```
The goal is to read /home/hatter/flag4.
```

**Hint 2**

```
You may not know the key but you know the length! Faster unpacking doesn't mean safer unpacking.
```

**Default Flag**

`TISC{W3_y4wN_A_Mor3_r0m4N_w4y}`

## Services

For more information on the services and how to setup, build, and run them, please see this
[README](service/README.md).

## Solutions

For the full writeup as well as more information on how to build and run the solutions, please see
this [README](solutions/README.md).
