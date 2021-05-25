#!/usr/bin/env python

'''
Helper script to generate Dill-based items for the story tree.

Run in the directory it is in.
'''

from rabbithole import (Item, letterwise_print, OptionsCommand, TeleportCommand, BlowSmokeCommand,
                        sleep)
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


# The Fluffy Cake - at a-fancy-pavillion
# Intended to allow the player to progress out of the maze and into the pool of tears.

def fluffy_cake_on_get(self):
    '''Teleport the player to a separate zone through a-fancy-pavillion.
    '''
    letterwise_print('You pick up the nice fluffy slice of cake, and promptly stuff it into your '
                     'mouth. This time, the world flits away downwards as your neck grows longer '
                     'and longer, rising high above the trees...')
    sleep(1.5)
    letterwise_print('Feeling utterly confused, you begin to cry. Each tear that falls grows '
                     'bigger and bigger in proportion with your gigantic body...')
    sleep(1.5)
    letterwise_print('The tears pool at your feet creating a tiny puddle...')
    sleep(1.5)
    letterwise_print('... a medium puddle...')
    sleep(1.5)
    letterwise_print('... a large puddle...')
    sleep(1.5)
    letterwise_print('... a large lake...')
    sleep(1.5)
    letterwise_print('Eventually, the tears form a large sea and you float away in the brine.')
    self.game.teleport(STORY_BASE / 'sea-of-tears')

def setup_fluffy_cake():
    item = make_item('fluffy-cake', fluffy_cake_on_get)
    path = (STORY_BASE / 'a-massive-hall/a-pink-door/maze-entrance/knotted-boughs/dazzling-pines'
            '/a-pause-in-the-trees/confusing-knot/green-clearing/a-fancy-pavillion/'
            'fluffy-cake.item')
    write_object(path, item)


# The Looking Glass - at a-mystical-cove
# Grants the player the power of teleportation.

def looking_glass_on_get(self):
    '''Grants the player teleportation powers.
    '''
    letterwise_print('You pick up the looking glass and look through the lens. Through it you '
                     'see a multitude of infinite worlds, infinite Universes. Suddenly, you feel '
                     'much more powerful.')
    self.game.commands.append(TeleportCommand(self.game))

def setup_looking_glass():
    item = make_item('looking-glass', looking_glass_on_get)
    path = (STORY_BASE / 'sea-of-tears/along-the-rolling-waves/a-sandy-shore/a-mystical-cove/'
            'looking-glass.item')
    write_object(path, item)


# Morning Glory - at clearing-of-flowers
# Does nothing, just dies.

def morning_glory_on_get(self):
    '''Does some useless things.
    '''
    letterwise_print('The morning glory in your hands suddenly bursts into song.\n')
    letterwise_print('    "Little bread-and-butterflies kiss the tulips"')
    letterwise_print('    "And the sun is like a toy balloon"')
    letterwise_print('    "There are get-up-in-the-morning glories"')
    letterwise_print('    "In the golden --"\n')
    letterwise_print('Suddenly, the plant just dies though.')

def setup_morning_glory():
    item = make_item('morning-glory', morning_glory_on_get)
    path = (STORY_BASE / 'sea-of-tears/along-the-rolling-waves/a-sandy-shore/into-the-woods/'
            'further-into-the-woods/nearing-a-clearing/clearing-of-flowers/'
            'morning-glory.item')
    write_object(path, item)


# Golden Hookah - at under-a-giant-mushroom
# Grants the player the ability to blow smoke into words.

def golden_hookah_on_get(self):
    '''Grants the blow smoke command.
    '''
    letterwise_print('Placing the mouthpiece of the hookah to your lips, a rush of rainbow '
                     'smoke bellows suddenly into your lungs without even inhaling.')
    letterwise_print('The smoke glows brightly as you try to get it out.')
    letterwise_print('It floats heavily and lazily arranges itself into the words:')
    smoke = '''

▄▄▌ ▐ ▄▌ ▄ .▄           ▄▄▄· • ▌ ▄ ·.     ▪
██· █▌▐███▪▐█▪         ▐█ ▀█ ·██ ▐███▪    ██
██▪▐█▐▐▌██▀▐█ ▄█▀▄     ▄█▀▀█ ▐█ ▌▐▌▐█·    ▐█·
▐█▌██▐█▌██▌▐▀▐█▌.▐▌    ▐█ ▪▐▌██ ██▌▐█▌    ▐█▌
 ▀▀▀▀ ▀▪▀▀▀ · ▀█▄▀▪     ▀  ▀ ▀▀  █▪▀▀▀    ▀▀▀

    '''
    letterwise_print(smoke)
    self.game.commands.append(BlowSmokeCommand(self.game))
    self.game.teleport(STORY_BASE / 'vast-emptiness')

def setup_golden_hookah():
    item = make_item('golden-hookah', golden_hookah_on_get)
    path = (STORY_BASE / 'sea-of-tears/along-the-rolling-waves/a-sandy-shore/into-the-woods/'
            'further-into-the-woods/nearing-a-clearing/clearing-of-flowers/under-a-giant-mushroom/'
            'golden-hookah.item')
    write_object(path, item)


# Main Function

def main():
    setup_pocket_watch()
    setup_pink_bottle()
    setup_fluffy_cake()
    setup_looking_glass()
    setup_morning_glory()
    setup_golden_hookah()


if __name__ == '__main__':
    main()
