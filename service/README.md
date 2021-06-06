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

#### Container

Some facts to know about the service in the container:

* The xinetd definition can be found in this [service file](../xinetd-services/down-the-rabbithole).
* The user used to run this service is `rabbit`.
* The service files will be located at `/opt/wonderland/down-the-rabbithole/`.
* The reachable flags:
    * `/home/rabbit/flag1` - A text file, intended to be read with an arbitrary file read.
    * `/home/rabbit/flag2.bin` - An executable, intended to be executed from a shell.

#### Description

The application first prints a banner and then eventually provides the user with a prompt:

```
You look around and see:
The bottom of a crummy tunnel.

You see exits to the:
  * a-shallow-deadend
  * deeper-into-the-burrow

[bottom-of-a-pit]
```

This is powered by the main loop of the game implemented by `Game.run_game`:

```python
    def run_game(self):
        '''Main loop for the game.
        '''
        self.move_to(START_LOCATION)
        while self.running:
            # Evaluate the user input.
            user_line = readline('[{}] '.format(self.location.name))
            try:
                self.evaluate(user_line)
            except:
                var = traceback.format_exc()
                pprint(var)
```

Typing in commands causes the user's input to be evaluated and invokes an action if it exists.
Otherwise it prints an error message hinting for the user to type 'help'.

```
[bottom-of-a-pit] look
You look around and see:
The bottom of a crummy tunnel.

You see exits to the:
  * a-shallow-deadend
  * deeper-into-the-burrow

[bottom-of-a-pit] lol
Don't know what you mean. Maybe try asking for 'help'.
[bottom-of-a-pit]
```

The evaluation tokenises the user's input line and checks for the presence of a keyword in the
command dictionary.

```python
    def get_command(self, arg):
        '''Get a command if it exists by key.
        '''
        for cmd in self.commands:
            if cmd.key(arg):
                return cmd
        return None

    def evaluate(self, user_line):
        '''Evaluate the user line.
        '''
        args = user_line.split()

        if len(args) < 1:
            return

        cmd = self.get_command(args[0])

        if cmd is None:
            pprint("Don't know what you mean. Maybe try asking for 'help'.")
        else:
            cmd.run(args)
```

To start with there are very few commands available to the user.

```
[bottom-of-a-pit] help
Available commands: help, look, move, back, read, get, exit
[bottom-of-a-pit]
```

These commands are implemented as `Command` objects. For example, the prototype as well as the
implementation of the `HelpCommand`:

```python
class Command:

    def __init__(self, game):
        '''Initialises a new command.
        '''
        self.game = game

    def run(self, args):
        '''Executes the command.
        '''
        raise NotImplementedError()

    def help(self):
        '''Returns the help string as a tuple of (name, text).
        '''
        raise NotImplementedError()

    def key(self, arg):
        '''Checks if the argument is a key to this command..
        '''
        raise NotImplementedError()


class HelpCommand(Command):
    '''Print the available commands and their help string.
    '''

    def __init__(self, game):
        super().__init__(game)

    def run(self, args):
        if len(args) < 2:
            # Print available commands.
            keys = ', '.join(i.help()[0] for i in self.game.commands)
            letterwise_print('Available commands: {}'.format(keys))
            return

        cmd = self.game.get_command(args[1])
        if cmd is None:
            letterwise_print("Unknown command '{}' to show help for.".format(args[0]))
            return
        letterwise_print(cmd.help()[1])

    def help(self):
        hstr = (
            'Usage: help [command]\n'
            'Prints the help documentation for a particular command.'
        )
        return ('help', hstr)

    def key(self, arg):
        return 'help' ==  arg
```

The default commands are registered during the initialisation of the `Game` object.

```python
class Game:

    def __init__(self):
        '''Initialise a new game.
        '''
        # Setup class variables.
        self.running = True
        self.location = STORIES_DIR
        self.history = []
        self.inventory = {}

        # Setup some default commands.
        self.commands = []
        self.commands.append(HelpCommand(self))
        self.commands.append(LookCommand(self))
        self.commands.append(MoveCommand(self))
        self.commands.append(BackCommand(self))
        self.commands.append(ReadCommand(self))
        self.commands.append(GetCommand(self))
        self.commands.append(ExitCommand(self))

        # Setup admin commands for cheats.
        if rabbit_conf.ENABLE_ADMIN:
            self.commands.append(TeleportCommand(self))
```

Using the `move` command, one can navigate the fantasy world.

```
[bottom-of-a-pit] move a-shallow-deadend
You have moved to a new location: 'a-shallow-deadend'.

You look around and see:
A sandy wall terminates the end of the claustrophobic passage. There is nothing here but a pile of old paper.

There are the following things here:
  * pocket-watch (item)
  * README (note)

[a-shallow-deadend]
```

This world is created by using the properties of the unix filesystem. The starting room is
`bottom-of-a-pit` which corresponds to the following directory:
`/opt/wonderland/down-the-rabbithole/stories/bottom-of-a-pit`. The `stories/` directory is the base
of where the story files are. Files and directories are treated with the following coding:

* `.` prefixed files are considered 'invisible' and never show up in the entity listing
* Directories are considered rooms.
* A room has a description in the corresponding `.description` file of the directory.
* Files ending with the suffix `.item` are considered 'gettable' items that can interact with the
    `get` command. These files contain Dill serialized data describing a custom Item object.
* All other files are considered 'Others' and can be `read` from.

For instance, the contents of `stories/bottom-of-a-pit/a-shallow-deadend` contains:

```
total 24
drwxr-xr-x  5 amon  staff  160 May 24 20:49 .
drwxr-xr-x  5 amon  staff  160 May 25 02:04 ..
-rw-r--r--  1 amon  staff  110 May 24 01:46 .description
-rw-r--r--  1 amon  staff  178 May 24 19:23 README
-rw-r--r--  1 amon  staff  710 May 25 07:04 pocket-watch.item
```

When the player navigates through the labyrinth of rooms in a fairy linear maze, they come across
the `looking-glass` which grants them the power to access the `teleport` command. Through this
command, they can teleport out to the root directory and navigate the file system like rooms in the
game by using a directory traversal attack.

```python
class TeleportCommand(Command):
    '''Teleport to a location.
    '''

    def __init__(self, game):
        super().__init__(game)

    def run(self, args):
        if len(args) < 2:
            # Print location.
            letterwise_print("You are currently at:")
            letterwise_print(str(self.game.location.relative_to(STORIES_DIR)))
            return

        for i in args[1].strip().split('/'):
            if i == '':
                letterwise_print('Cannot travel through empty rooms. Pay attention to this!')
                return
        rel_path = STORIES_DIR / args[1]
        if rel_path.exists() and rel_path.is_dir():
            self.game.teleport(rel_path)
            return

        letterwise_print("I don't know where that is.")

    def help(self):
        hstr = (
            'Usage: teleport [location]\n'
            'Views current location or teleport to another.'
        )
        return ('teleport', hstr)

    def key(self, arg):
        return 'teleport' ==  arg
```

It is through this primitive that the players are expected to start being able to introspect their
environment and read the source code to these applications.

Further on in the story, the player finds the `golden-hookah` left on the ground by a long-gone
Caterpillar. This item grants the `blowsmoke` command which basically leaves a 'X Was Here' message
in `/opt/wonderland/logs/`. This can be abused by the player to write a file that ends in `.item` so
that when the item is `get`, arbitrary code execution can happen. However there are a few checks
that the `GetCommand` does to prevent the standard payloads from running.

```python
class GetCommand(Command):
    '''Gets an item from the ground in the current room.
    '''

    def __init__(self, game):
        super().__init__(game)

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

The `validate_stream` function checks that the output came from a Dill and that some symbols are
present. This check is very lacking.

### Pool of Tears

This is a Ruby on Rails based application that provides logging functionality to the sister
`down-the-rabbithole` application. The intended vulnerabilities in this script are the arbitrary
file write primitive when logging invoked by the Rabbithole service and the use of a number of Ruby
reflection methods which allow for the calling of arbitrary Ruby methods.

This service listens on port 4000 in the container and is only bound to localhost.

#### Directory Structure

The important files in the service's directory are:

* `run.sh` - Contains the run script. The `RAILS_MASTER_KEY` being exposed in this file should not
    be a security issue as cookies are not used in the application.
* `pool-of-tears/config/routes.rb` - Contains the Rails routes mapping to the handlers.
* `pool-of-tears/config/application.rb` - Contains the configuration variables.
* `pool-of-tears/app/controllers/smoke_controller.rb` - Contains the handler for the important
    `/api/v1/smoke` endpoint.

#### Container

Some facts to know about the service in the container:

* The user change is managed via `runuser` in `utils/main.sh`.
* The user used to run this service is `mouse`.
* The service files will be located at `/opt/wonderland/down-the-rabbithole/`.
* The reachable flags:
    * `/home/mouse/flag3.bin` - An executable, intended to be executed from a shell.
* A file containing the invitation code for the next stage is located at
    `/home/mouse/an-unbirthday-invitation.letter`.

#### Description

The only useful endpoint for this service is `/api/v1/smoke`. This is intended for use by the
`rabbithole.py` script in the Rabbithole Service to log 'X Was Here' style messages in
`/opt/wonderland/logs`. The `BlowSmokeCommand` is implemented like so:

```python
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

This endpoint is handled by the `app/controllers/smoke_controller.rb` controller and has a very
simple implementation.

```ruby
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
```

The vulnerability here is that `ctype`, `cargs`, and `cop` are parameters that eventually get turned
into an arbitrary Ruby call. The default behaviour calls `File.new` to create the log files but can
be overriden to call `Kernel.system` to run arbitrary system commands.

### Mad Tea Party

This is a Java based console application that interacts with STDIN and STDOUT to offer a text-based
interface for designing a cake at a tea party. It is exposed on the network via xinetd. The intended
vulnerabilities are the use of an insecure keyed hash construction that is vulnerable to the hash
length extension attack and the deserialization of untrusted FST binary data which leads to
arbitrary code execution.

This service listens on port 4714 in the container and is only bound to localhost.

#### Directory Structure

The important files in the service's directory are:


#### Container

Some facts to know about the service in the container:

* The xinetd definition can be found in this [service file](../xinetd-services/a-mad-tea-party).
* The user used to run this service is `hatter`.
* The service files will be located at `/opt/wonderland/a-mad-tea-party/`.
* The reachable flags:
    * `/home/hatter/flag4` - A text file, intended to be read with an arbitrary file read.

#### Description


