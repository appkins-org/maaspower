"""
unifi_controller.py
------------

Classes to represent the configuration and functionality for devices
that can be controlled via a UniFi controller.

"""
import asyncio
from dataclasses import dataclass

import urllib3
from requests import Request
from requests_threads import AsyncSession
from typing_extensions import Annotated as A
from typing_extensions import Dict, Literal
from urllib3.exceptions import InsecureRequestWarning

from maaspower.maas_globals import desc
from maaspower.maasconfig import RegexSwitchDevice


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
        urllib3.disable_warnings(InsecureRequestWarning)

        self._headers: Dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        self._csrf_token = None
        self._cookie_token = None
        self._id = None

        self._s = AsyncSession()

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

        asyncio.run(self.connect())

    def __del__(self):
        asyncio.run(self.disconnect())

    async def call_api(self, method, path, json_data=None):
        if self._csrf_token is not None:
            print("Update CSRF Token")
            self._s.headers.update({"X-CSRF-Token": self._csrf_token})
            print("...done.")
        else:
            print("CSRF Token is None.")

        req = Request(
            method,
            f"{self._base_url}/{path}",
            headers={"Content-Type": "application/json"},
        )

        if json_data is not None:
            req.json = json_data

        r = await self._s.send(req.prepare(), verify=self.verify_ssl, timeout=10)

        resp_headers = r.headers

        for h in resp_headers:
            if h.upper() == "X-CSRF-TOKEN":
                self._csrf_token = resp_headers[h]
            if h.upper() == "SET-COOKIE":
                self._cookie_token = resp_headers[h]

        return r

    async def get(self, path):
        return self.call_api("GET", f"{self._api_endpoint}/{path}")

    async def put(self, path, json_data):
        return self.call_api("PUT", f"{self._api_endpoint}/{path}", json_data)

    async def connect(self, retries=2):
        await self.login()

        status = await self.get_status()
        self._id = status["_id"]

        print(f"id: {self._id}")

    async def disconnect(self):
        await self.call_api("POST", "api/logout")
        try:
            self._s.close()
        except Exception:
            pass

    async def login(self):
        data = {"username": self.api_username, "password": self.api_password}

        r = await self.call_api("POST", self._login, data)

        if r.status_code == 400:
            raise LoggedInException("Failed to log in to api with provided credentials")

    async def get_status(self) -> dict:
        r = await self.get(f"rest/device/{self.device_mac}")

        return r.json()["data"][0]

    async def get_port(self, port) -> dict:
        status = await self.get_status()
        if "port_table" in status:
            return next(p for p in status["port_table"] if p["port_idx"] == int(port))

        return {}

    async def get_port_state(self, port) -> bool:
        port = await self.get_port(port)

        if "up" in port:
            return port["up"]
        return False

    async def set_port_state(self, port, state):
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
        port_state = self.get_port_state(self.query)

        return "on" if port_state is True else "off"
