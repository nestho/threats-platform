import unittest

from scripts import dev


class DevServerTests(unittest.TestCase):
    def test_handler_keeps_connections_alive(self):
        # The overview fetches ten feeds at once. Over HTTP/1.0 each fetch needs
        # its own connection, which overflows the listen backlog and surfaces in
        # the browser as ERR_CONNECTION_RESET for a page that is actually fine.
        self.assertEqual(dev.StaticHandler.protocol_version, "HTTP/1.1")

    def test_server_queue_tolerates_the_overview_fan_out(self):
        server = dev.make_server(0)
        try:
            self.assertGreaterEqual(server.request_queue_size, 32)
        finally:
            server.server_close()


if __name__ == "__main__":
    unittest.main()
