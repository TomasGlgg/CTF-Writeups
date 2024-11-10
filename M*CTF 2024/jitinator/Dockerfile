FROM ubuntu:24.04

RUN apt-get -y update
RUN apt install -y socat 

RUN mkdir /app

RUN useradd -m ctf

COPY . /app

WORKDIR /app
RUN chmod +x  ./run.sh

USER ctf

CMD ["./run.sh"]
