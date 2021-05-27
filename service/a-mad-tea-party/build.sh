#!/bin/bash

rm -f tea-party/src/main/java/com/mad/hatter/proto/*.java
protoc -I=proto/ --java_out=tea-party/src/main/java/ proto/cake.proto
cd tea-party
mvn clean compile assembly:single
