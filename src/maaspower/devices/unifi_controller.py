"""
unifi_controller.py
------------

Classes to represent the configuration and functionality for devices
that can be controlled via a UniFi controller.

"""
import json
from dataclasses import dataclass

import requests
import urllib3
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

    device_mac: A[str, desc("The UniFi device mac address to control")] = "none"

    site: A[str, desc("The UniFi site to connect to")] = "default"

    verify_ssl: A[bool, desc("Verify SSL certificate")] = False

    def __post_init__(self):
        urllib3.disable_warnings(InsecureRequestWarning)

        self._headers: Dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        self.session = requests.Session()

        self._base_url = f"https://{self.api_host}:443"

        # proxy/network/api/s/default/rest/device/d8:b3:70:7b:7b:68

        self._endpoint = f"{self._base_url}/proxy/network/api/s/{self.site}"

        self._login = f"{self._base_url}/api/auth/login"

        if self.on == "none":
            self.on = self.port_idx

        if self.off == "none":
            self.off = self.port_idx

        if self.query == "none":
            self.query = self.port_idx

        self.connect()

    def __del__(self):
        self.disconnect()

    def connect(self, retries=2):
        r = self.session.post(
            self._login,
            headers=self._headers,
            json={"username": self.api_username, "password": self.api_password},
            verify=self.verify_ssl,
            timeout=1,
        )
        self._current_status_code = r.status_code

        if self._current_status_code == 400:
            raise LoggedInException("Failed to log in to api with provided credentials")

        d = r.json()

        status = self.get_status()
        self._id = status["_id"]

        print(f"id: {self._id}")

        self._auth_headers: Dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Dest": "empty",
            "TE": "trailers",
        }

        if "unique_id" in d:
            self._auth_headers["X-CSRF-Token"] = d["unique_id"]

        if "deviceToken" in d:
            self._auth_headers["Set-Cookie"] = f"TOKEN={d['deviceToken']}"

    def disconnect(self):
        self.session.post(
            f"{self._base_url}/api/logout",
            headers=self._headers,
            verify=self.verify_ssl,
            timeout=1,
        )
        try:
            self.session.close()
        except Exception:
            pass

    def get_status(self) -> dict:
        r = self.session.get(
            f"{self._endpoint}/stat/device/{self.device_mac}",
            headers=self._headers,
            verify=self.verify_ssl,
            timeout=1,
        )
        return r.json()["data"][0]

    def get_port_table(self) -> dict:
        status = self.get_status()
        if "port_table" in status:
            return status["port_table"]
        else:
            return {}

    def turn_on(self):
        print(f"turning on device: {self._id} on port {self.on}")
        json_data = {"port_overrides": [{"port_idx": int(self.on), "poe_enable": True}]}
        print(json.dumps(json_data))
        r = self.session.put(
            f"{self._endpoint}/rest/device/{self._id}",
            headers=self._auth_headers,
            json=json_data,
            verify=self.verify_ssl,
            timeout=10,
        )
        print(f"status code: {r.status_code}")

    def turn_off(self):
        print(f"turning off device: {self._id} on port {self.on}")
        json_data = {
            "port_overrides": [{"port_idx": int(self.off), "poe_enable": False}]
        }
        print(json.dumps(json_data))
        r = self.session.put(
            f"{self._endpoint}/rest/device/{self._id}",
            headers=self._auth_headers,
            json=json_data,
            verify=self.verify_ssl,
            timeout=10,
        )
        print(f"status code: {r.status_code}")

    def run_query(self) -> str:
        port_table = self.get_port_table()
        port = next(p for p in port_table if p["port_idx"] == int(self.query))

        if "up" in port:
            return "on" if port["up"] is True else "off"
        return "error"
