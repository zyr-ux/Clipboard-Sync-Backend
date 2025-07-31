from typing import Dict
from fastapi import WebSocket

class ConnectionManager:
    def __init__(self):
        # Structure: { user_id: { device_id: websocket } }
        self.active_connections: Dict[int, Dict[str, WebSocket]] = {}

    def connect(self, user_id: int, device_id: str, websocket: WebSocket):
        if user_id not in self.active_connections:
            self.active_connections[user_id] = {}
        self.active_connections[user_id][device_id] = websocket

    def disconnect(self, user_id: int, device_id: str):
        if user_id in self.active_connections:
            self.active_connections[user_id].pop(device_id, None)
            if not self.active_connections[user_id]:
                self.active_connections.pop(user_id, None)

    def get_user_devices(self, user_id: int) -> Dict[str, WebSocket]:
        return self.active_connections.get(user_id, {})

    async def broadcast_to_user(self, user_id: int, message: dict, exclude_device: str = None):
        for device_id, ws in self.get_user_devices(user_id).items():
            if device_id != exclude_device:
                await ws.send_json(message)