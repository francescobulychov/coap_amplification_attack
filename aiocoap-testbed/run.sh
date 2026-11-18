#!/usr/bin/env bash
# Orchestrate the CoAP amplification lab with plain docker (no compose needed).
#
#   ./run.sh up [N]              build/start network, victim, N reflectors, attacker
#   ./run.sh attack MODE [ARGS]  run an attack (modes: discovery|simple|observe|multicast)
#   ./run.sh af                  print the amplification factor from the last attack
#   ./run.sh down                tear everything down
#
# Examples:
#   ./run.sh up 5
#   ./run.sh attack simple --count 1
#   ./run.sh attack observe --count 1 ; sleep 12 ; ./run.sh af
#   ./run.sh attack discovery
set -euo pipefail
cd "$(dirname "$0")"

NET=coaplab
SUBNET=10.80.0.0/24
VICTIM_IP=10.80.0.250
ATTACKER_IP=10.80.0.251
IMG=coaplab

case "${1:-}" in
up)
  N="${2:-1}"
  docker build -t "$IMG" . >/dev/null
  docker network inspect "$NET" >/dev/null 2>&1 || \
    docker network create --driver bridge --internal --subnet "$SUBNET" "$NET" >/dev/null
  mkdir -p results
  docker rm -f victim attacker >/dev/null 2>&1 || true
  docker ps -aq --filter "name=reflector_" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker run -d --name victim --network "$NET" --ip "$VICTIM_IP" \
    -v "$PWD/results:/results" "$IMG" python3 victim.py >/dev/null
  for i in $(seq 1 "$N"); do
    docker run -d --name "reflector_$i" --network "$NET" \
      -e QUOTE_SIZE="${QUOTE_SIZE:-1000}" -e OBS_COUNT="${OBS_COUNT:-50}" \
      -e OBS_SIZE="${OBS_SIZE:-200}" -e OBS_INTERVAL="${OBS_INTERVAL:-0.2}" \
      -e MULTICAST_IFACE="${MULTICAST_IFACE:-eth0}" \
      --cap-add NET_RAW "$IMG" python3 reflector.py >/dev/null
  done
  docker run -d --name attacker --network "$NET" --ip "$ATTACKER_IP" \
    --cap-add NET_RAW --cap-add NET_ADMIN -e VICTIM_IP="$VICTIM_IP" -e REFLECTORS=reflector \
    -v "$PWD/results:/results" "$IMG" sleep infinity >/dev/null
  # Route the All-CoAP-Nodes multicast range out eth0 (raw sockets need a route).
  docker exec attacker ip route add 224.0.0.0/4 dev eth0 >/dev/null 2>&1 || true
  # Build a comma-separated reflector IP list for the attacker.
  IPS=$(for i in $(seq 1 "$N"); do \
    docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "reflector_$i"; \
    done | paste -sd,)
  echo "$IPS" > results/reflectors.txt
  echo "up: $N reflector(s) at $IPS ; victim $VICTIM_IP ; attacker $ATTACKER_IP"
  ;;
attack)
  shift
  MODE="${1:-simple}"; shift || true
  REFL=$(cat results/reflectors.txt 2>/dev/null || echo reflector)
  docker kill -s HUP victim >/dev/null   # reset counters without restart (keeps MAC/ARP)
  sleep 0.3
  docker exec attacker python3 attacker.py --mode "$MODE" --reflectors "$REFL" "$@"
  ;;
af)
  docker exec attacker python3 compute_af.py
  ;;
watch)
  # Live view of the reflected flood arriving at the victim (Ctrl-C to stop).
  echo "watching traffic INTO victim $VICTIM_IP (Ctrl-C to stop) ..."
  docker exec victim tcpdump -i eth0 -n -l "udp and dst host $VICTIM_IP"
  ;;
down)
  docker rm -f victim attacker >/dev/null 2>&1 || true
  docker ps -aq --filter "name=reflector_" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  echo "down"
  ;;
*)
  grep '^#' "$0" | sed 's/^# \{0,1\}//'
  ;;
esac
