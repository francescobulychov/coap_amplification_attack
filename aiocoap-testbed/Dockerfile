FROM python:3.12-slim

# tcpdump is optional (for IP-layer pcap cross-checks); aiocoap is the CoAP stack.
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir "aiocoap>=0.4.7"

WORKDIR /app
COPY coap.py rawsend.py reflector.py attacker.py victim.py compute_af.py /app/

CMD ["python3", "reflector.py"]
