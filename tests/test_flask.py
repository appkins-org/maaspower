"""
Test the full software stack with the backend switch services mocked
out.
"""

from base64 import b64encode
from pathlib import Path

from mock import patch
from ruamel.yaml import YAML

# import all sublasses of SwitchDevice so ApiSchema sees them
from maaspower.devices.shell_cmd import CommandLine
from maaspower.devices.smart_thing import SmartThing
from maaspower.maasconfig import MaasConfig
from maaspower.webhook import app, load_web_hook

# from unittest.mock import patch


# avoid linter complaints
required_to_find_subclasses = [SmartThing, CommandLine]

userpass = "a_user:a_pass"
encoded_u = b64encode(userpass.encode()).decode()
headers = {"Authorization": "Basic %s" % encoded_u}


def test_web_root():
    """
    Test that the web server responds to its root URL
    """
    with app.test_client() as test_client:
        response = test_client.get("/")
        assert response.status_code == 200
        assert b"MAAS Power Web Hooks Server" == response.data


def test_webhook_cmdline(samples: Path):
    """
    Load a dummy command line controlled switch configuration and
    confirm that we can call it via the webhooks
    """

    dummypath = samples / "dummy_cmd.yaml"
    config_dict = YAML().load(dummypath)

    maas_config = MaasConfig.deserialize(config_dict)
    load_web_hook(maas_config)

    with app.test_client() as test_client:
        response = test_client.post("/maaspower/pi1/on", headers=headers)
        assert response.status_code == 200
        response = test_client.post("/maaspower/pi1/off", headers=headers)
        assert response.status_code == 200
        response = test_client.post("/maaspower/pi1/query", headers=headers)
        assert response.data == b"status : running"


def test_regex(tmp_path: Path, samples: Path):
    """
    Load up a config that tests regex in device names and call the webook
    with various matching names
    """

    samplepath = samples / "sampleregex.yaml"
    config_dict = YAML().load(samplepath)

    maas_config = MaasConfig.deserialize(config_dict)
    load_web_hook(maas_config)

    with app.test_client() as test_client:
        response = test_client.post("/maaspower/hello1/query", headers=headers)
        assert response.data == b"status : running"
        response = test_client.post("/maaspower/192_168_1_3/query", headers=headers)
        assert response.data == b"status : running"


@patch("maaspower.devices.shell_cmd.CommandLine.execute_command")
def test_substitution(command_line, tmp_path: Path, samples: Path):
    """
    Load up a config that tests regex in device names and call the webook
    with various matching names
    """

    samplepath = samples / "sampleregex.yaml"
    config_dict = YAML().load(samplepath)

    maas_config = MaasConfig.deserialize(config_dict)
    load_web_hook(maas_config)

    with app.test_client() as test_client:
        test_client.post("/maaspower/hello1/query", headers=headers)
        assert command_line.call_args.args[0] == "echo hello1 power"
        test_client.post("/maaspower/192_168_1_3/query", headers=headers)
        assert command_line.call_args.args[0] == "echo 192_168_1_3 power"


# @patch("pysmartthings.SmartThings")
# def test_webhook_smartthings(smarthings, samples: Path):
#     """
#     Load a smartthing controlled switch configuration and
#     confirm that we can call it via the webhooks, mock out the
#     smartthings backend
#     """

#     dummypath = samples / "dummy_cmd.yaml"
#     config_dict = YAML().load(dummypath)

#     maas_config = MaasConfig.deserialize(config_dict)
#     load_web_hook(maas_config)

#     with app.test_client() as test_client:
#         response = test_client.post("/maaspower/nuc1/on", headers=headers)
#         assert response.status_code == 200
#         response = test_client.post("/maaspower/nuc1/off", headers=headers)
#         assert response.status_code == 200
#         response = test_client.post("/maaspower/nuc1/query", headers=headers)
#         assert response.data == b"status : running"
