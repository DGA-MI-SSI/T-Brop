FROM debian:stretch-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    unzip \
    make \
    gcc \
    libc6-dev \
    ipython3 \
    python3-pip

RUN curl -L https://github.com/aquynh/capstone/archive/next.zip > next.zip \
 && unzip next.zip \
 && rm -rf next.zip

WORKDIR /capstone-next/
RUN CAPSTONE_ARCHS="x86" ./make.sh
RUN CAPSTONE_ARCHS="x86" ./make.sh install

WORKDIR /capstone-next/bindings/python/
RUN pip3 install setuptools
RUN CAPSTONE_ARCHS="x86" make install3

RUN pip3 install wheel
RUN pip3 install lief
RUN pip3 install numpy
RUN pip3 install scipy

COPY t-brop /app/t-brop/.
WORKDIR /app/t-brop

ENTRYPOINT ["python3", "t-brop.py"]
CMD ["-h"]