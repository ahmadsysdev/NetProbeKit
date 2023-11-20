# ARP Spoofing Script

Perform an ARP spoofing on a target networkusing this Python script powered by scapy library.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Options](#options)
- [Disclaimer](#disclaimer)
- [Contributing](#contributing)
- [License](#license)

## Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/ahmadsysdev/NetProbeKit.git
    ```

2. **Navigate to the project directory:**

    ```bash
    cd NetProbeKit
    ```

3. **Install the required dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

## Usage

Ensure you have the necessary permissions to run the script, as ARP poisoning requires administrative privileges.

```bash
sudo python arp_spoof.py --cidr 192.168.0.0/24
```

Replace `192.168.0.0/24` with the target CIDR or IP range you want to perform ARP spoofing on.

## Options

The following options is available when running the ARP spoofing script:

- `-c, --cidr`: Specify the target CIDR or IP range for ARP spoofing.

Example:

```bash
sudo python arp_spoof.py --cidr 192.168.0.0/24
```

## Disclaimer

This script is for educational purposes only. Misus of this script for unauthorized to computer networks is illegal and strictly prohibited. Use it responsibly and only on networks that you own or have explicit permission to test.

## Contributing

Feel free to contribute by submitting issues or pull requests. Your feedback and suggestions are welcome.

## License

This project is licensed under the [GNU General Public License (GPL)](LICENSE).