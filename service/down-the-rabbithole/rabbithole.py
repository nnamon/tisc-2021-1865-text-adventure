#!/usr/bin/env python
# Tested on Python 3.8.5

'''
Wonderland MUD

A very exciting text adventure.
'''

import pathlib
import sys
import time
import os


# Constants

CURRENT_DIR = pathlib.Path(__file__).parent.absolute()
STORIES_DIR = CURRENT_DIR / 'stories'
ART = open(CURRENT_DIR / 'art' / 'art.ansi', 'rb').read()
ENABLE_SLEEPS = False if os.getenv('ENABLE_SLEEPS', 'True') == 'False' else True
START_LOCATION = 'bottom-of-a-pit'


# Utilities

def pprint(data, endl=b'\n'):
    '''Standardise writes as byte buffers.
    '''
    if type(data) is str:
        data = data.encode('utf-8')
    if type(endl) is str:
        endl = endl.encode('utf-8')
    sys.stdout.buffer.write(data + endl)
    sys.stdout.flush()


def sleep(duration=0.5):
    '''Configurable sleep.
    '''
    if ENABLE_SLEEPS:
        time.sleep(duration)


def letterwise_print(data):
    '''Prints a string with a nice console effect.
    '''
    for letter in data:
        if type(letter) is int:
            letter = bytes([letter])
        pprint(letter, endl='')
        sleep(0.008)

    pprint('')


def linewise_print(data):
    '''Prints a multiline byte string with a nice console effect.
    '''
    for line in data.split(b'\n'):
        pprint(line)
        sleep(0.012)


def readline(prompt=None):
    '''Reads a line from the user with optional prompt.
    '''
    if prompt:
        pprint(prompt, endl=b'')

    data = sys.stdin.readline()
    return data


# Game Functions

def print_banner():
    '''Print a welcome banner for players.
    '''
    pprint('Connected.')
    sleep()
    pprint('Fracture Runtime Environment v0.0.13 -- (c) 2021 -- Steel Worlds Entertainment')
    pprint('Multi-User License: 100-0000-000')
    sleep()
    letterwise_print('Loading assets...')
    sleep()
    letterwise_print('Generating world...')
    sleep(1.5)
    linewise_print(ART)

    # Start of the story.
    letterwise_print('Alice was beginning to get very tired of sitting by her sister on the bank,')
    letterwise_print('when suddenly a White Rabbit with pink eyes ran close by her.\n')

    letterwise_print('There was nothing so very remarkable in that;')
    letterwise_print('nor did Alice think it so very much out of the way to hear the Rabbit say to'
                     ' itself,')
    letterwise_print('"Oh dear! Oh dear! I shall be late!";')
    letterwise_print('but when the Rabbit actually *took a watch out of its waistcoat-pocket*,')
    letterwise_print('and looked at it, and then hurried on,')
    letterwise_print('Alice started to her feet,')
    letterwise_print('for she had never before seen a rabbit with either a waistcoat-pocket,')
    letterwise_print('or a watch to take out of it.\n')

    letterwise_print('Burning with curiosity, she ran across the field after it, ')
    letterwise_print('and fortunately was just in time to see it pop down a large rabbit-hole '
                     'under the hedge.\n')

    letterwise_print('In another moment down went Alice after it, ')
    letterwise_print('never once considering how in the world she was to get out again...\n')

    sleep()

    letterwise_print('Down, down, down...')
    letterwise_print('Would the fall never come to an end?\n')

    sleep(1.5)

    letterwise_print('BUMP!\n')


def main():
    print_banner()
    game = Game()
    game.run_game()


# Commands

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


class LookCommand(Command):
    '''Looks in the current room.
    '''

    def __init__(self, game):
        super().__init__(game)

    def run(self, args):
        desc = 'Darkness fills your senses. Nothing can be discerned from your environment.'
        for ent in self.game.get_invis():
            if '.description' in ent.name:
                desc = open(ent, 'rb').read()
        letterwise_print('You look around and see:')
        letterwise_print(desc)
        things = []
        things += ['  * ' + i.name + ' (item)'for i in self.game.get_items()]
        things += ['  * ' + i.name + ' (note)'for i in self.game.get_others()]
        if len(things):
            letterwise_print('There are the following things here:\n{}\n'.format('\n'.join(things)))
        next_moves = ['  * ' + i.name for i in self.game.get_moves()]
        if len(next_moves):
            letterwise_print('You see exits to the:\n{}\n'.format('\n'.join(next_moves)))

    def help(self):
        hstr = (
            'Usage: look\n'
            'Looks around the room'
        )
        return ('look', hstr)

    def key(self, arg):
        return 'look' ==  arg


class MoveCommand(Command):
    '''Moves to another room.
    '''

    def __init__(self, game):
        super().__init__(game)

    def run(self, args):
        if len(args) < 2:
            letterwise_print('Where do you want to move to?')
            return
        self.game.move_to(args[1])

    def help(self):
        hstr = (
            'Usage: move [to room]\n'
            'Moves to another room'
        )
        return ('move', hstr)

    def key(self, arg):
        return 'move' ==  arg


class BackCommand(Command):
    '''Moves to back to the previous room.
    '''

    def __init__(self, game):
        super().__init__(game)

    def run(self, args):
        # There should always be the root of the story tree in the history.
        if len(self.game.history) > 1:
            prev_location = self.game.history.pop()
            self.game.teleport(prev_location, add_history=False)
        else:
            letterwise_print('There is nowhere else for you to run to, lost one.')

    def help(self):
        hstr = (
            'Usage: back\n'
            'Goes back to the previous room.'
        )
        return ('back', hstr)

    def key(self, arg):
        return 'back' ==  arg


class ReadCommand(Command):
    '''Moves to back to the previous room.
    '''

    def __init__(self, game):
        super().__init__(game)

    def run(self, args):
        if len(args) < 2:
            letterwise_print("You don't see that here.")
            return
        others = self.game.get_others()
        read_something = False
        for other in others:
            if other.name == args[1]:
                read_something = True
                letterwise_print('You read the writing on the note:')
                letterwise_print(open(other, 'rb').read())
        if not read_something:
            letterwise_print("You don't see that here.")

    def help(self):
        hstr = (
            'Usage: read [note]\n'
            'Reads a note on the ground.'
        )
        return ('read', hstr)

    def key(self, arg):
        return 'read' ==  arg



# Game Classes

class Item:
    '''Represents a usable item prototype.

    Intended to be scattered around the story tree and deserialized dynamically from items with the
    suffix '.item'.
    '''

    def __init__(self):
        '''Initialise a new instance of the item.
        '''
        pass



class Game:

    def __init__(self):
        '''Initialise a new game.
        '''
        # Setup class variables.
        self.running = True
        self.location = STORIES_DIR
        self.history = []

        # Setup some default commands.
        self.commands = []
        self.commands.append(HelpCommand(self))
        self.commands.append(LookCommand(self))
        self.commands.append(MoveCommand(self))
        self.commands.append(BackCommand(self))
        self.commands.append(ReadCommand(self))

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

    def get_ents(self):
        '''Get the entities within the current directory.
        '''
        moves = []
        items = []
        invis = []
        others = []
        for ent in self.location.iterdir():
            if ent.name.startswith('.'):
                invis.append(ent)
            elif ent.is_dir():
                moves.append(ent)
            elif ent.name.endswith('.item'):
                items.append(ent)
            else:
                others.append(ent)

        return (moves, items, invis, others)

    def get_moves(self):
        '''Get the valid next legal moves.
        '''
        return self.get_ents()[0]

    def get_items(self):
        '''Get the Items in the current location.
        '''
        return self.get_ents()[1]

    def get_invis(self):
        '''Get the invisible things from the current location.
        '''
        return self.get_ents()[2]

    def get_others(self):
        '''Get the other things from the current location.
        '''
        return self.get_ents()[3]

    def move_to(self, next_location):
        '''Moves to another location within the story tree.
        '''
        moves = self.get_moves()
        next_path = self.location / next_location
        if not next_path in moves:
            # We cannot proceed.
            letterwise_print("Cannot move to '{}'.".format(next_location))
            return
        # Make the move.
        self.history.append(self.location)
        self.location = next_path
        letterwise_print("You have moved to a new location: '{}'.\n".format(self.location.name))
        self.get_command('look').run(['look'])

    def teleport(self, next_location, add_history=True):
        '''Moves to another location regardless of story tree.

        Must be a full path.
        '''
        path = pathlib.Path(next_location)
        if not path.is_dir():
            # We cannot proceed.
            letterwise_print("Cannot move to '{}'.".format(next_location))
            return
        # Make the move.
        if add_history:
            self.history.append(self.location)
        self.location = path
        letterwise_print("You have moved to a new location: '{}'.\n".format(self.location.name))
        self.get_command('look').run(['look'])

    def run_game(self):
        '''Main loop for the game.
        '''
        self.move_to(START_LOCATION)
        while self.running:
            # Evaluate the user input.
            user_line = readline('[{}] '.format(self.location.name))
            self.evaluate(user_line)

        letterwise_print('Goodbye!')


# Run Main as a Script

if __name__ == '__main__':
    main()
