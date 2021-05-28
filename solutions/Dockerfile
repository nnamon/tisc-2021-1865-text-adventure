FROM ubuntu:focal

# Global Constants
ENV BASE_DIR=/opt/wonderland
ENV DEBIAN_FRONTEND="noninteractive"

# Global Dependencies
RUN apt-get update
RUN apt-get install -y python3.8 python3-pip
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.8 1
RUN apt-get install -y net-tools
RUN apt-get install -y build-essential
RUN apt-get install -y openjdk-8-jdk-headless maven
RUN apt-get install -y libssl-dev

# Some cool tools for hackers.
RUN apt-get install -y curl netcat wget tmux vim

# Create and setup the base directory containing the vulnerable services.
RUN mkdir $BASE_DIR
ADD * $BASE_DIR/

# Setup the scripts.
RUN pip install -r $BASE_DIR/requirements.txt

# Setup volume.
VOLUME $BASE_DIR

# Setup workdir
WORKDIR $BASE_DIR
