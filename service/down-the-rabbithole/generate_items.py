#!/usr/bin/env python

'''
Helper script to generate Dill-based items for the story tree.

Run in the directory it is in.
'''

from rabbithole import Item, letterwise_print, OptionsCommand, sleep
import pathlib
import dill
import types


# Constants

dill.settings['recurse'] = True
STORY_BASE = pathlib.Path('./stories').absolute()


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


# The Pocket Watch - at bottom-of-a-pit/a-shallow-deadend
# Intended to give players a way to access the options menu.

def pocket_watch_on_get(self):
    '''Add the options command when picked up.
    '''
    letterwise_print('The pocket watch glows with a warm waning energy and you feel less '
                     'muddled in mind.')
    self.game.commands.append(OptionsCommand(self.game))

def setup_pocket_watch():
    item = make_item('pocket-watch', pocket_watch_on_get)
    path = STORY_BASE / 'bottom-of-a-pit/a-shallow-deadend/pocket-watch.item'
    write_object(path, item)


# The Pink Bottle - at a-curious-hall
# Intended to allow the player to progress past the hall of doors by shrinking small enough.

def pink_bottle_on_get(self):
    '''Teleport the player to a separate zone through a tiny door.
    '''
    letterwise_print('As you examine the bottle, an overwhelming urge to tip the contents into '
                     'your mouth overwhelms you. When the pink liquid touches your lips, the '
                     'croying taste of cakes, and pastries, and pies fills your senses.\n')
    letterwise_print('However, you realise with horror that the entire world is growing larger...')
    sleep(1)
    letterwise_print('Or was it you that was growing smaller?')
    self.game.teleport(STORY_BASE / 'a-massive-hall')

def setup_pink_bottle():
    item = make_item('pink-bottle', pink_bottle_on_get)
    path = (STORY_BASE / 'bottom-of-a-pit/deeper-into-the-burrow/a-curious-hall/pink-bottle.item')
    write_object(path, item)


## The Cake - at a-fancy-pavillion
# Intended to allow the player to progress out of the maze and into the pool of tears.

# Main Function

def main():
    setup_pocket_watch()
    setup_pink_bottle()


if __name__ == '__main__':
    main()
