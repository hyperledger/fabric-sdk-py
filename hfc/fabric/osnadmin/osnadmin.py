import requests


class OSNOperationException(Exception):
    pass


class OSNAdmin:
    def __init__(self, url: str, client_cert_path: str, client_key_path: str, ca_cert_path: str):
        self.session = requests.Session()
        self.session.cert = (client_cert_path, client_key_path)
        self.session.verify = ca_cert_path
        self.osnUrl = url

    def _process_response(self, response: requests.Response):
        if response:
            return response.json() if response.content else response.content
        else:
            raise OSNOperationException(response.json())

    def list_all_channels(self):
        res = self.session.get(f"{self.osnUrl}/participation/v1/channels")
        return self._process_response(res)

    def list_single_channel(self, channel_name: str):
        res = self.session.get(f"{self.osnUrl}/participation/v1/channels/{channel_name}")
        return self._process_response(res)

    def remove(self, channel_name: str):
        res = self.session.delete(f"{self.osnUrl}/participation/v1/channels/{channel_name}")
        return self._process_response(res)

    def join(self, channel_config_block_path: str):
        with open(channel_config_block_path, "rb") as file:
            config_block_data = file.read()
        res = self.session.post(
            f"{self.osnUrl}/participation/v1/channels",
            files={"config-block": config_block_data}
        )
        return self._process_response(res)
