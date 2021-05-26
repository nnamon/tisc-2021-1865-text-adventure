#!/usr/bin/env python

'''
Contains the common functions required for the various exploits.
'''

from pwn import *
from config import TARGET_IP, TARGET_PORT


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

    # Game Related Helpers

    def init_connection(self):
        '''Gets rid of all the starting stuff.
        '''
        log.progress('Initialising connection. This will take a moment...')
        self.get_until_prompt()

    def get_until_prompt(self):
        '''Receives until the prompt is found.
        '''
        self.recvuntil(b'] ')

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
