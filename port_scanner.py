import socket
from prompt_toolkit import prompt
from prompt_toolkit.validation import Validator, ValidationError

class PortValidator(Validator):
    def validate(self, document):
        try:
            port = int(document.text)
            if not (1 <= port <= 65535):
                raise ValidationError(message="Port must be between 1 and 65535.")
        except ValueError:
            raise ValidationError(message="Invalid port number.")

def scan_tcp_ports(ip, start_port, end_port, log_file):
    with open(log_file, 'a') as file:
        file.write(f"Scanning TCP ports from {start_port} to {end_port} on {ip}\n")
        for port in range(start_port, end_port + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        file.write(f"TCP Port {port}: Open\n")
                    else:
                        file.write(f"TCP Port {port}: Closed\n")
            except Exception as e:
                file.write(f"Error scanning TCP Port {port}: {e}\n")

def scan_udp_ports(ip, start_port, end_port, log_file):
    with open(log_file, 'a') as file:
        file.write(f"Scanning UDP ports from {start_port} to {end_port} on {ip}\n")
        for port in range(start_port, end_port + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(1)
                    result = sock.sendto(b'', (ip, port))
                    try:
                        data, _ = sock.recvfrom(1024)
                        file.write(f"UDP Port {port}: Open\n")
                    except socket.timeout:
                        file.write(f"UDP Port {port}: Closed\n")
            except Exception as e:
                file.write(f"Error scanning UDP Port {port}: {e}\n")

def main():
    ip = prompt("Enter the IP address to scan: ")
    start_port = int(prompt("Enter the starting port number: ", validator=PortValidator()))
    end_port = int(prompt("Enter the ending port number: ", validator=PortValidator()))
    log_file = prompt("Enter log file name (default: scan_results.log): ") or "scan_results.log"
    
    print(f"Scanning TCP ports from {start_port} to {end_port} on {ip}")
    scan_tcp_ports(ip, start_port, end_port, log_file)
    
    print(f"\nScanning UDP ports from {start_port} to {end_port} on {ip}")
    scan_udp_ports(ip, start_port, end_port, log_file)
    
    print(f"Results logged to {log_file}")

if __name__ == "__main__":
    main()

