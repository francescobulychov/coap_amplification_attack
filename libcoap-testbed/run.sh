#!/usr/bin/env bash
# CoAP amplification lab — libcoap edition (server = libcoap's coap-server-notls).
# Same isolated design and same attacker/victim/measurement as ../testbed, so the
# two are directly comparable. Plain docker CLI (no compose needed).
#
#   ./run.sh up [N]              build/start network, victim, N libcoap reflectors, attacker
#   ./run.sh attack MODE [ARGS]  modes: discovery|simple|observe|multicast
#   ./run.sh af                  print amplification factor from the last attack
#   ./run.sh watch               live tcpdump of traffic hitting the victim
#   ./run.sh down                tear everything down
#
# Examples:
#   ./run.sh up 5
#   ./run.sh attack simple ; sleep 2 ; ./run.sh af
#   ./run.sh attack observe ; sleep 10 ; ./run.sh af          # /time notifies ~1/s
#   ./run.sh attack multicast ; sleep 3 ; ./run.sh af
set -euo pipefail
cd "$(dirname "$0")"

NET=coaplab2
SUBNET=10.81.0.0/24
VICTIM_IP=10.81.0.250
ATTACKER_IP=10.81.0.251
IMG=coaplab2
BIG_SIZE="${BIG_SIZE:-1000}"   # bytes seeded into /big for the simple/multicast attack

case "${1:-}" in
up)
  N="${2:-1}"
  docker build -t "$IMG" . >/dev/null
  docker network inspect "$NET" >/dev/null 2>&1 || \
    docker network create --driver bridge --internal --subnet "$SUBNET" "$NET" >/dev/null
  mkdir -p results
  docker rm -f victim2 attacker2 >/dev/null 2>&1 || true
  docker ps -aq --filter "name=reflector2_" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker run -d --name victim2 --network "$NET" --ip "$VICTIM_IP" \
    -v "$PWD/results:/results" "$IMG" python3 victim.py >/dev/null
  for i in $(seq 1 "$N"); do
    # NoSec libcoap server: dynamic resources (-d), multicast group joined (-g),
    # Non-confirmable observe (-N). This is the unhardened amplifier.
    docker run -d --name "reflector2_$i" --network "$NET" --cap-add NET_RAW "$IMG" \
      coap-server-notls -A 0.0.0.0 -p 5683 -d 100 -g 224.0.1.187 -G eth0 -N >/dev/null
  done
  docker run -d --name attacker2 --network "$NET" --ip "$ATTACKER_IP" \
    --cap-add NET_RAW --cap-add NET_ADMIN -e VICTIM_IP="$VICTIM_IP" \
    -v "$PWD/results:/results" "$IMG" sleep infinity >/dev/null
  docker exec attacker2 ip route add 224.0.0.0/4 dev eth0 >/dev/null 2>&1 || true
  IPS=$(for i in $(seq 1 "$N"); do \
    docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "reflector2_$i"; \
    done | paste -sd,)
  echo "$IPS" > results/reflectors.txt
  # Seed a BIG_SIZE-byte resource /big on every reflector (simple/multicast target).
  docker exec attacker2 sh -c "head -c $BIG_SIZE /dev/zero | tr '\\0' Q > /tmp/big.txt"
  for ip in $(echo "$IPS" | tr ',' ' '); do
    docker exec attacker2 coap-client-notls -m put -f /tmp/big.txt "coap://$ip/big" >/dev/null 2>&1 || true
  done
  echo "up: $N libcoap reflector(s) at $IPS ; victim $VICTIM_IP ; attacker $ATTACKER_IP ; /big=${BIG_SIZE}B"
  ;;
attack)
  shift
  MODE="${1:-simple}"; shift || true
  REFL=$(cat results/reflectors.txt 2>/dev/null || echo reflector2)
  case "$MODE" in
    simple)    DEF="--path big";;
    observe)   DEF="--path time";;   # libcoap /time: a notification ~every second
    multicast) DEF="--path big";;
    *)         DEF="";;              # discovery uses attacker default (/.well-known/core)
  esac
  docker kill -s HUP victim2 >/dev/null   # reset counters without restart
  sleep 0.3
  docker exec attacker2 python3 attacker.py --mode "$MODE" --reflectors "$REFL" $DEF "$@"
  ;;
af)
  docker exec attacker2 python3 compute_af.py
  ;;
watch)
  echo "watching traffic INTO victim $VICTIM_IP (Ctrl-C to stop) ..."
  docker exec victim2 tcpdump -i eth0 -n -l "udp and dst host $VICTIM_IP"
  ;;
down)
  docker rm -f victim2 attacker2 >/dev/null 2>&1 || true
  docker ps -aq --filter "name=reflector2_" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  echo "down"
  ;;
*)
  grep '^#' "$0" | sed 's/^# \{0,1\}//'
  ;;
esac
