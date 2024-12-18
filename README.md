# System Security Checker

A Python-based utility to perform security checks on a system based on a specified configuration file. It evaluates file permissions, checks for unwanted running services, and verifies the usage of default credentials.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Logging](#logging)
- [Error Handling](#error-handling)
- [Contributing](#contributing)
- [License](#license)
  
## Features

- Checks file permissions for critical system files.
- Identifies unwanted running services.
- Verifies if any default credentials are being used.
- Configurable via a JSON configuration file.

## Requirements

- Python 3.6 or higher
- `psutil` library (for process management)
  
Install the required library using pip:

```bash
pip install psutil
```

## Installation

1. Clone the repository:

   ```bash
   https://github.com/fish-hue/System-Security-Checker.git
   cd security-checker
   ```

2. Create a virtual environment (optional but recommended):

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Configuration

Create a `config.json` configuration file in the project directory. An example has been inluded in the package. Here’s a sample configuration:

```json
{
    "files_to_check": [
        "/etc/passwd",
        "/etc/shadow"
    ],
    "unwanted_services": [
        "telnet",
        "ftp",
        "apache2",
        "mysql"
    ],
    "default_credentials": {
        "admin": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd51b33bfbaaf86aa3f",
        "root": "63a9f0ea7bb98050796b649e85481845"
    }
}
```

### Keys

- `files_to_check`: List of file paths to check for permissions.
- `unwanted_services`: List of services to check if they are running.
- `default_credentials`: Dictionary of usernames mapped to their hashed passwords.

## Usage

Run the security checker by executing the following command in your terminal:

```bash
python security_checker.py --config path/to/config.json
```

Replace `path/to/config.json` with the actual path to your configuration file.

## Logging

The script logs messages to the console at various levels (INFO, WARNING, ERROR) depending on the situation. Ensure you observe the console output to get the summary of checks performed.

## Error Handling

The script raises errors for:
- Missing configuration files.
- Invalid JSON configuration.
- Security issues found during checks.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes. Be sure to include tests for any new functionality.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
