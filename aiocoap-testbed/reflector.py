"""Unsecured ("NoSec") CoAP reflector server — the amplifier under study.

Exposes resources that let you choose the amplification factor c, plus an
observable resource for the Observe (c*n) attack and the automatic
/.well-known/core resource for the Oliveira-style discovery baseline.

Config via env:
  QUOTE_SIZE   bytes of payload returned by GET /quote            (default 1000)
  OBS_INTERVAL seconds between observe notifications               (default 0.2)
  OBS_COUNT    number of notifications to push per registration    (default 50)
  OBS_SIZE     bytes of payload per observe notification           (default 200)
"""
import asyncio
import os

import aiocoap
import aiocoap.resource as resource


QUOTE_SIZE = int(os.environ.get("QUOTE_SIZE", "1000"))
OBS_INTERVAL = float(os.environ.get("OBS_INTERVAL", "0.2"))
OBS_COUNT = int(os.environ.get("OBS_COUNT", "50"))
OBS_SIZE = int(os.environ.get("OBS_SIZE", "200"))


class QuoteResource(resource.Resource):
    """A large static representation — the simple-amplification vector."""
    async def render_get(self, request):
        return aiocoap.Message(code=aiocoap.CONTENT, payload=b"Q" * QUOTE_SIZE)


class TempResource(resource.Resource):
    """Small discovery-style resource so /.well-known/core is non-trivial."""
    async def render_get(self, request):
        return aiocoap.Message(code=aiocoap.CONTENT, payload=b"21.4 ppbv")


class ObserveResource(resource.ObservableResource):
    """Observable resource: one registration -> OBS_COUNT notifications (c*n)."""
    def __init__(self):
        super().__init__()
        self.value = 0
        self.handle = None

    def notify(self):
        self.updated_state()
        self.value += 1
        if self.value < OBS_COUNT:
            self.handle = asyncio.get_event_loop().call_later(OBS_INTERVAL, self.notify)

    def update_observation_count(self, count):
        # Start streaming as soon as the first observer registers.
        if count > 0 and self.handle is None:
            self.value = 0
            self.handle = asyncio.get_event_loop().call_later(OBS_INTERVAL, self.notify)
        elif count == 0 and self.handle is not None:
            self.handle.cancel()
            self.handle = None

    async def render_get(self, request):
        return aiocoap.Message(code=aiocoap.CONTENT, payload=b"N" * OBS_SIZE)


async def main():
    root = resource.Site()
    root.add_resource([".well-known", "core"],
                      resource.WKCResource(root.get_resources_as_linkheader))
    root.add_resource(["quote"], QuoteResource())
    root.add_resource(["temperature"], TempResource())
    root.add_resource(["obs"], ObserveResource())
    mcast_iface = os.environ.get("MULTICAST_IFACE")  # e.g. "eth0" to join All-CoAP-Nodes
    kwargs = {"bind": ("0.0.0.0", 5683)}
    if mcast_iface:
        kwargs["multicast"] = [mcast_iface]
    try:
        await aiocoap.Context.create_server_context(root, **kwargs)
    except Exception as e:
        print("multicast join failed (%r); retrying unicast-only" % e, flush=True)
        await aiocoap.Context.create_server_context(root, bind=("0.0.0.0", 5683))
    print("reflector up on :5683  QUOTE_SIZE=%d OBS_COUNT=%d OBS_SIZE=%d mcast=%s"
          % (QUOTE_SIZE, OBS_COUNT, OBS_SIZE, mcast_iface or "off"), flush=True)
    await asyncio.get_event_loop().create_future()


if __name__ == "__main__":
    asyncio.run(main())
