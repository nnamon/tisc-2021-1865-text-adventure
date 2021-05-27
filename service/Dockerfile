FROM ubuntu:focal

# Global Constants
ENV BASE_DIR=/opt/wonderland
ENV LISTEN_PORT=31337
ENV USER1=rabbit
ENV USER2=mouse
ENV USER3=hatter
ENV DEBIAN_FRONTEND="noninteractive"

# Some protections
RUN echo "$user     hard    nproc       40" >> /etc/security/limits.conf

# Global Dependencies
RUN apt-get update
RUN apt-get install -y python3.8 python3-pip
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.8 1
RUN apt-get install -y ruby ruby-dev rails
RUN apt-get install -y net-tools
RUN apt-get install -y build-essential
RUN apt-get install -y xinetd
RUN apt-get install -y openjdk-8-jdk-headless maven
RUN apt-get install -y protobuf-compiler

# Some cool tools for hackers.
RUN apt-get install -y curl netcat wget tmux vim

# Setup the users.
RUN useradd -m $USER1
RUN useradd -m $USER2
RUN useradd -m $USER3

# Create and setup the base directory containing the vulnerable services.
RUN mkdir $BASE_DIR
ADD down-the-rabbithole $BASE_DIR/down-the-rabbithole
ADD pool-of-tears $BASE_DIR/pool-of-tears
ADD a-mad-tea-party $BASE_DIR/a-mad-tea-party
ADD utils $BASE_DIR/utils
WORKDIR $BASE_DIR
RUN chown -R root:root $BASE_DIR
RUN chmod -R 755 $BASE_DIR
RUN chmod +x $BASE_DIR/utils/*

# Setup the down-the-rabbithole service.
RUN chmod +x $BASE_DIR/down-the-rabbithole/rabbithole.py
RUN pip install -r $BASE_DIR/down-the-rabbithole/requirements.txt
RUN cd $BASE_DIR/down-the-rabbithole/ && python generate_items.py

# Setup the pool-of-tears service.
RUN mkdir $BASE_DIR/logs
RUN chown root:$USER2 $BASE_DIR/logs
RUN chmod 775 $BASE_DIR/logs
RUN chown -R root:$USER2 $BASE_DIR/pool-of-tears
RUN chmod -R 770 $BASE_DIR/pool-of-tears/tmp
RUN chmod -R 770 $BASE_DIR/pool-of-tears/log
RUN chmod +x $BASE_DIR/pool-of-tears/run.sh
RUN cd $BASE_DIR/pool-of-tears/ && bundle install
RUN echo '*/4 * * * * mouse /usr/bin/rm '$BASE_DIR'/logs/*' > /etc/crontab
RUN echo '*/4 * * * * mouse '$BASE_DIR'/utils/clean_tmp.sh' > /etc/crontab

# Setup the a-mad-tea-party service.
RUN python -c 'import uuid;print(uuid.uuid4())' > /home/$USER3/invitation_code
RUN python -c 'import os, sys;sys.stdout.buffer.write(os.urandom(32))' > /home/$USER3/secret
COPY a-mad-tea-party/an-unbirthday-invitation.letter /home/$USER2/an-unbirthday-invitation.letter
RUN cat /home/$USER3/invitation_code >> /home/$USER2/an-unbirthday-invitation.letter
RUN cd $BASE_DIR/a-mad-tea-party && ./build.sh

# Setup the flags.
# Flag 1 is from Arbitrary File Read from down-the-rabbithole.
COPY flags/flag1 /home/$USER1/flag1
# Flag 2 is from Arbitrary Code Execution from down-the-rabbithole.
COPY flags/flag2 /home/$USER2/flag2
# Flag 3 is from Arbitrary Code Execution from pool-of-tears. User needs to run the flag wrapper.
COPY flags/flag3 /home/$USER3/flag3
# Flag 4 is from Arbitrary Code Execution from a-mad-tea-party.
COPY flags/flag4 /home/$USER3/flag4
COPY flags/congratulations.txt /home/$USER3/congratulations.txt
RUN chown -R root:$USER1 /home/$USER1
RUN chown -R root:$USER2 /home/$USER2
RUN chown -R root:$USER3 /home/$USER3
RUN chmod -R 440 /home/*
RUN chmod 550 /home/*
RUN chmod 440 /home/*/flag*

# Setup the SUID mouse binary in the rabbit home to read the second flag.
RUN printf '#include<stdio.h>\n#include <stdlib.h>\n\n \
void main() \n \
{ \n \
FILE *f = fopen("/home/'$USER2'/flag2", "rb"); \n \
fseek(f, 0, SEEK_END); \n \
long fsize = ftell(f); \n \
fseek(f, 0, SEEK_SET); \n \
char *string = malloc(fsize + 1); \n \
fread(string, 1, fsize, f); \n \
fclose(f); \n \
string[fsize] = 0; \n \
puts(string); \n \
}' | gcc -o /home/$USER1/flag2.bin -xc -
RUN chown root:$USER2 /home/$USER1/flag2.bin
RUN chmod 755 /home/$USER1/flag2.bin
RUN chmod g+s /home/$USER1/flag2.bin

# Setup the SUID hatter binary in the mouse home to read the third flag.
RUN printf '#include<stdio.h>\n#include <stdlib.h>\n\n \
void main() \n \
{ \n \
FILE *f = fopen("/home/'$USER3'/flag3", "rb"); \n \
fseek(f, 0, SEEK_END); \n \
long fsize = ftell(f); \n \
fseek(f, 0, SEEK_SET); \n \
char *string = malloc(fsize + 1); \n \
fread(string, 1, fsize, f); \n \
fclose(f); \n \
string[fsize] = 0; \n \
puts(string); \n \
}' | gcc -o /home/$USER2/flag3.bin -xc -
RUN chown root:$USER3 /home/$USER2/flag3.bin
RUN chmod 755 /home/$USER2/flag3.bin
RUN chmod g+s /home/$USER2/flag3.bin

# Setup xinetd services.
COPY ./xinetd-services/* /etc/xinetd.d/

# Create a directory for players use.
RUN mkdir -p /tmp/hackers_use_me
RUN chmod 773 /tmp/hackers_use_me

# Expose the single port for the only entry point (down-the-rabbithole)
EXPOSE $LISTEN_PORT

# Finally run the services.
# CMD ["$BASE_DIR/utils/main.sh"]
