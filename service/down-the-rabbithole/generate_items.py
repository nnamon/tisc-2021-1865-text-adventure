#!/usr/bin/env python

'''
Helper script to generate Dill-based items for the story tree.
'''

from rabbithole import Command

# The Pocket Watch - at bottom-of-a-pit/a-shallow-deadend
# Intended to give players a way to access the options menu.

class OptionsCommand(Command):
    '''Set some game options.
    '''

    def __init__(self, game):
        self.opts = {
            'enable_sleeps': True
        }
        super().__init__(game)

    def run(self, args):
        if len(args) < 3:
            # Print all options.
            letterwise_print("The following options are available:")
            for i, v in self.opts.items():
                letterwise_print('  * {}: {}'.format(i, v))
            return
        if args[1] in self.opts:
            if args[1] == 'enable_sleeps':
                global ENABLE_SLEEPS
                if args[2].lower() == 'false' or args[2].lower() == 'f' or args[2] == '0':
                    self.opts['enable_sleeps'] = False
                    ENABLE_SLEEPS = False
                else:
                    self.opts['enable_sleeps'] = True
                    ENABLE_SLEEPS = True
        else:
            letterwise_print("I don't know what that option is.")

    def help(self):
        hstr = (
            'Usage: options [key] [value]\n'
            'Views and modifies game options.'
        )
        return ('options', hstr)

    def key(self, arg):
        return 'options' ==  arg


def setup_pocket_watch():
    pass

# Main Function

def main():
    setup_pocket_watch()

if __name__ == '__main__':
    main()
