#!/bin/bash

# Generates an invitation for the 4th challenge - to be placed in the mouse home and used to block
# access before the 3rd flag is gained.

python -c 'import uuid;print(uuid.uuid4())' > invitation_code
