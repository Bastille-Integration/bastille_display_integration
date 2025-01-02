import socket
import ssl

class Freeport:
    def __init__(self, host: str, port: int, username: str, password: str):
        self.host = host
        self.port = port
        self.username = username
        self.password = password

    def screen_change(self, option: str, protocol: str = None, device: str = None, zone: str = None):
        self.option = option
        self.protocol = protocol
        self.device = device
        self.zone = zone
        def wait_for_response(sock, buffer_size=4096, expected_keyword="SUCCESS"):
            """Wait for a complete response from the server."""
            response = ""
            while True:
                data = sock.recv(buffer_size).decode()
                response += data
                #print("Server response fragment:")
                #print(data)
                if expected_keyword in response or not data.strip():
                    break
            return response
        try:
            # Create a raw socket
            raw_socket = socket.create_connection((self.host, self.port))

            # Create an SSL context
            context = ssl.create_default_context()
            context.check_hostname = False  # Disable hostname checking (optional for testing)
            context.verify_mode = ssl.CERT_NONE  # Disable certificate validation (optional for testing)

            # Wrap the socket with SSL for TLS
            tls_socket = context.wrap_socket(raw_socket, server_hostname=self.host)

            print(f"Connected to {self.host}:{self.port} using TLS")

            # Read server prompts and authenticate
            buffer_size = 4096  # Adjust as needed
            authenticated = False
            while True:
                response = tls_socket.recv(buffer_size).decode()
                print("Server says:")
                print(response)

                if "login:" in response.lower():  # Check if the server asks for login
                    tls_socket.sendall(f"{self.username}\n".encode())
                    print(f"Sent username: {self.username}")
                elif "password:" in response.lower():  # Check if the server asks for password
                    tls_socket.sendall(f"{self.password}\n".encode())
                    print(f"Sent password: {'*' * len(self.password)}")
                elif "welcome" in response.lower():  # Check for a successful login message (customize as needed)
                    authenticated = True
                    print("Login successful.")
                    break

            if self.option == "alert":
                commands = [
                    'set feature background visible: false',
                    'set feature message 1 text: ALERT',
                    'set feature message 1 font color: #D30000',
                    'set feature message 1 font size: 220',
                    'set feature message 2 visible: true',
                    'set feature message 2 font color: #D30000',
                    'set feature message 2 font size: 160',
                    f'set feature message 2 text: "Protocol:{self.protocol}-Device:{self.device}-Zone:{self.zone}"',
                    'set feature clock 0 visible: false',
                    'set feature clock 1 visible: false',
                    'set feature clock 2 visible: false',
                    'set feature clock 3 visible: false'

                ]
            else:
                commands = [
                    'set feature background visible: true',
                    'set feature message 1 text: CLEAR',
                    'set feature message 1 font color: #3CB043',
                    'set feature message 1 font size: 180',
                    'set feature message 2 visible: false',
                    'set feature clock 0 visible: true',
                    'set feature clock 1 visible: true',
                    'set feature clock 2 visible: true',
                    'set feature clock 3 visible: true'

                ]

            if authenticated:
                # Run multiple commands
                for command in commands:
                    print(f"Running command: {command}")
                    tls_socket.sendall(f"{command}\n".encode())

                    # Wait for the server's response
                    response = wait_for_response(tls_socket, expected_keyword="SUCCESS")
                    #print(f"Output for '{command}':")
                    print(response)

                    # Check for SUCCESS in the response
                    if "SUCCESS" not in response:
                        print(f"Command '{command}' did not return SUCCESS. Stopping further execution.")
                        break
                    else:
                        print("Moving on to next command.")

            # Close the connection
            tls_socket.close()
            print("Connection closed.")
        except Exception as e:
            print(f"Failed to connect to {self.host}:{self.port}")
            print(f"Error: {e}")