FROM gcc:latest
WORKDIR /root
COPY patch.diff lvl1.c lvl2.c /root/
RUN git clone --branch OpenSSL_1_1_0h https://github.com/openssl/openssl.git \
    && cd openssl \
    && git apply ../patch.diff \
    && ./Configure linux-x86_64 no-async \
    && make \
    && make install
RUN gcc lvl1.c -g -lssl -lcrypto -o oracle
RUN gcc lvl2.c -g -lssl -lcrypto -o client

FROM debian:buster-slim
WORKDIR /root
RUN apt update && apt install -y socat
COPY --from=0 /root/oracle /root/client /root/
COPY --from=0 /root/openssl/libssl.so.1.1 /root/openssl/libcrypto.so.1.1 /usr/lib/x86_64-linux-gnu/
COPY cert.pem key.pem /root/
CMD ./oracle
