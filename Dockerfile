FROM ubuntu:16.04

RUN \
	apt-get update &&\
	apt-get install -y vim gcc nasm make file

RUN mkdir /pestilence

COPY ./* /pestilence/

CMD ["bash"]
