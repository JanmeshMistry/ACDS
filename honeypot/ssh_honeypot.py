import sys
import os
import socket
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import paramiko
from paramiko import Transport, ServerInterface, AUTH_FAILED, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

from utils.logger import get_logger
from utils.config import SSH_HONEYPOT_HOST, SSH_HONEYPOT_PORT
from utils.geoip import lookup as geo_lookup
from database.mongo import upsert_attacker, insert_log
from engine.decision import evaluate

logger = get_logger("honeypot.ssh")

HOST_KEY_PATH = os.path.join(os.path.dirname(__file__), "ssh_host_key")


def _ensure_host_key():
    """Loads or generates the RSA key that our fake SSH server presents."""
    if os.path.exists(HOST_KEY_PATH):
        return paramiko.RSAKey(filename=HOST_KEY_PATH)
    logger.info("Generating SSH host key at %s", HOST_KEY_PATH)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_PATH)
    return key


class HoneypotServer(ServerInterface):
    """
    Pretends to be an SSH server. Accepts connections, logs credentials,
    then always returns AUTH_FAILED so nobody actually gets in.
    """

    def __init__(self, client_ip: str):
        self.client_ip = client_ip

    def check_auth_password(self, username: str, password: str) -> int:
        geo = geo_lookup(self.client_ip)
        event_data = {
            "event_type": "login_attempt",
            "username": username,
            "password": password,
            "service": "ssh",
            "geo": geo,
        }

        logger.warning("SSH LOGIN ATTEMPT | IP=%-15s user=%-20s pass=%s",
                       self.client_ip, username, password[:20])

        insert_log(self.client_ip, "login_attempt", event_data)
        upsert_attacker(self.client_ip, {**event_data, **geo})

        threading.Thread(target=evaluate, args=(self.client_ip, event_data), daemon=True).start()

        return AUTH_FAILED  # always deny, no exceptions

    def check_auth_publickey(self, username: str, key) -> int:
        return AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username: str) -> str:
        return "password"


def _handle_client(client_socket: socket.socket, client_addr: tuple) -> None:
    client_ip = client_addr[0]
    logger.info("SSH connection from %s:%d", client_ip, client_addr[1])

    try:
        transport = Transport(client_socket)
        transport.add_server_key(_ensure_host_key())
        transport.set_subsystem_handler("sftp", paramiko.SFTPServer)

        server = HoneypotServer(client_ip)
        transport.start_server(server=server)

        # hold the connection open briefly to catch multiple auth attempts
        channel = transport.accept(timeout=20)
        if channel:
            channel.close()

    except (EOFError, paramiko.SSHException) as e:
        logger.debug("SSH session ended for %s: %s", client_ip, e)
    except Exception as e:
        logger.error("SSH handler error for %s: %s", client_ip, e)
    finally:
        try:
            client_socket.close()
        except Exception:
            pass


def run() -> None:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((SSH_HONEYPOT_HOST, SSH_HONEYPOT_PORT))
        server_socket.listen(10)
        logger.info("SSH Honeypot listening on %s:%d", SSH_HONEYPOT_HOST, SSH_HONEYPOT_PORT)

        while True:
            try:
                client_sock, client_addr = server_socket.accept()
                t = threading.Thread(target=_handle_client, args=(client_sock, client_addr), daemon=True)
                t.start()
            except KeyboardInterrupt:
                logger.info("SSH Honeypot shutting down")
                break
            except Exception as e:
                logger.error("Accept error: %s", e)
    finally:
        server_socket.close()


if __name__ == "__main__":
    run()
