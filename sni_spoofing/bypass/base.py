"""Base class for bypass strategies."""

import abc
import socket
from typing import Optional


class BypassStrategy(abc.ABC):
    """Abstract base for DPI bypass strategies.

    Each strategy implements a different technique for evading
    Deep Packet Inspection when forwarding TCP connections.
    """

    name: str = "base"

    @abc.abstractmethod
    async def apply(
        self,
        client_sock: socket.socket,
        server_sock: socket.socket,
        fake_sni: str,
        first_data: bytes,
        loop=None,
    ) -> bool:
        """Apply the bypass strategy to an outgoing connection.

        This method is called after the TCP connection to the server
        is established but before any real data is forwarded.

        Args:
            client_sock: The incoming client socket
            server_sock: The outgoing socket to the real server
            fake_sni: The fake SNI hostname to use
            first_data: First data received from the client
            loop: asyncio event loop

        Returns:
            True if strategy was applied successfully, False otherwise
        """
        pass

    def __repr__(self):
        return f"<{self.__class__.__name__} strategy='{self.name}'>"
