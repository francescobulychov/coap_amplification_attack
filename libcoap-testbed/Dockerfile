FROM debian:12-slim

# libcoap3-bin provides coap-server-notls / coap-server-openssl (DTLS) and
# coap-client-*. python3 is only for the (implementation-agnostic) attacker,
# victim and measurement scripts. tcpdump for the live `watch` view.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libcoap3-bin python3 tcpdump iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY coap.py rawsend.py attacker.py victim.py compute_af.py /app/

# Default command is the unsecured libcoap reflector (overridden per role).
CMD ["coap-server-notls", "-A", "0.0.0.0", "-p", "5683", "-d", "100", "-g", "224.0.1.187", "-N"]
