"""
unifi_controller.py
------------

Classes to represent the configuration and functionality for devices
that can be controlled via a UniFi controller.

"""
import asyncio
from dataclasses import dataclass

from aiohttp import ClientSession
from typing_extensions import Annotated as A
from typing_extensions import Literal

from maaspower.maas_globals import desc
from maaspower.maasconfig import RegexSwitchDevice

from .errors import APIInvalidGrant, APIResponseError


class LoggedInException(Exception):
    def __init__(self, *args, **kwargs):
        super(LoggedInException, self).__init__(*args, **kwargs)


@dataclass(kw_only=True)
class UnifiController(RegexSwitchDevice):
    """A device controlled via the unifi controller API"""

    on: A[str, desc("command line string to switch device on")] = "none"
    off: A[str, desc("command line string to switch device off")] = "none"
    query: A[str, desc("command line string to query device state")] = "none"
    query_on_regex: A[str, desc("match the on status return from query")] = "on"
    query_off_regex: A[str, desc("match the off status return from query")] = "off"

    type: Literal["UnifiController"] = "UnifiController"

    port_idx: A[int, desc("The port index to control")] = 1

    api_username: A[str, desc("The UniFi API username")] = "none"
    api_password: A[str, desc("The UniFi API password")] = "none"
    api_host: A[str, desc("The UniFi API host")] = "none"

    network_id: A[str, desc("The UniFi network id to control")] = "none"

    device_mac: A[str, desc("The UniFi device mac address to control")] = "none"

    site: A[str, desc("The UniFi site to connect to")] = "default"

    verify_ssl: A[bool, desc("Verify SSL certificate")] = False

    def __post_init__(self):
        self._csrf_token = None
        self._cookie_token = None
        self._id = None

        self._base_url = f"https://{self.api_host}:443"

        # proxy/network/api/s/default/rest/device/d8:b3:70:7b:7b:68

        self._api_endpoint = f"proxy/network/api/s/{self.site}"

        self._login = "api/auth/login"

        if self.on == "none":
            self.on = self.port_idx

        if self.off == "none":
            self.off = self.port_idx

        if self.query == "none":
            self.query = self.port_idx

    async def request(self, method: str, url: str, data: dict = {}):
        """Perform a request against the specified parameters."""
        if self._csrf_token is not None:
            print("Update CSRF Token")
            self._session.headers.update({"X-CSRF-Token": self._csrf_token})
            print("...done.")
        else:
            print("CSRF Token is None.")
        async with self._session.request(
            method,
            url,
            json=data,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-CSRF-TOKEN": self._csrf_token,
            },
        ) as resp:
            if resp.status == 200:
                for h in resp.headers:
                    if h.upper() == "X-CSRF-TOKEN":
                        self._csrf_token = resp.headers[h]
                    if h.upper() == "SET-COOKIE":
                        self._cookie_token = resp.headers[h]

                return await resp.json()
            if resp.status in (400, 422, 429, 500):
                data = {}
                try:
                    data = await resp.json()
                except Exception:  # pylint: disable=broad-except
                    pass
                raise APIResponseError(
                    resp.request_info,
                    resp.history,
                    status=resp.status,
                    message=resp.reason,
                    headers=resp.headers,
                    data=data,
                )
            resp.raise_for_status()

    async def get(self, path: str):
        """Get a resource."""
        return self.request("get", f"{self._api_endpoint}/{path}")

    async def put(self, path: str, json_data: dict):
        return self.request("put", f"{self._api_endpoint}/{path}", json_data)

    async def login(self):
        """Login to unifi controller."""
        payload = {"username": self.api_username, "password": self.api_password}
        async with self._session.request(
            "post",
            self._login,
            data=payload,
        ) as resp:
            if resp.status == 200:
                for h in resp.headers:
                    if h.upper() == "X-CSRF-TOKEN":
                        self._csrf_token = resp.headers[h]
                    if h.upper() == "SET-COOKIE":
                        self._cookie_token = resp.headers[h]
                return await resp.json()
            if resp.status == 400:
                data = {}
                try:
                    data = await resp.json()
                except Exception:  # pylint: disable=broad-except
                    pass
                raise APIInvalidGrant(data.get("error_description"))
            resp.raise_for_status()

    async def get_status(self) -> dict:
        r = await self.get(f"rest/device/{self.device_mac}")

        return r.json()["data"][0]

    async def get_port(self, port) -> dict:
        status = await self.get_status()
        if "port_table" in status:
            return next(p for p in status["port_table"] if p["port_idx"] == int(port))

        return {}

    async def get_port_state(self, port) -> str:
        async with ClientSession() as session:
            self._session = session

            if self._csrf_token is None:
                await self.login()

            port = await self.get_port(port)

            if "up" in port:
                return "on" if port["up"] is True else "off"
            return "unknown"

    async def set_port_state(self, port, state):
        async with ClientSession() as session:
            self._session = session

            if self._csrf_token is None:
                await self.login()

            if self._id is None:
                status = await self.get_status()
                self._id = status["_id"]

                print(f"id: {self._id}")

            des = {
                "poe_enable": True if state == "on" else False,
                "poe_mode": "auto" if state == "on" else "off",
            }

            cur = await self.get_port(port)

            if (
                cur["poe_enable"] is des["poe_enable"]
                and cur["poe_mode"] == des["poe_mode"]
            ):
                print(f"Port {port} already {state}")
                return

            new_state = cur.update(des)

            print(f"Setting port {port} to {state}")

            asyncio.run(
                self.put(
                    f"rest/device/{self._id}",
                    {"port_overrides": [new_state]},
                )
            )

    def turn_on(self):
        asyncio.run(self.set_port_state(self.port_idx, "on"))

    def get_url(self, path):
        return f"{self._base_url}/{path}"

    def turn_off(self):
        asyncio.run(self.set_port_state(self.port_idx, "off"))

    def run_query(self) -> str:
        return asyncio.run(self.get_port_state(self.query))
