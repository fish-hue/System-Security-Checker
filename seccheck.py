import os
import stat
import psutil
import logging
import argparse
import json
import hashlib
from typing import List, Dict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

class SecurityChecker:
    """A class to perform security checks on the system based on a configuration file."""
    
    def __init__(self, config_file: str):
        self.load_config(config_file)
        self.running_services_cache: List[str] = []

    def load_config(self, config_file: str) -> None:
        """Load and validate the configuration from the given JSON file."""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
        except FileNotFoundError:
            raise ValueError(f"Configuration file '{config_file}' not found.")
        except json.JSONDecodeError:
            raise ValueError(f"Configuration file '{config_file}' is not a valid JSON.")

        self.validate_config(config)
        
        # Set attributes from configuration
        self.files_to_check: List[str] = config.get("files_to_check", [])
        self.unwanted_services: List[str] = config.get("unwanted_services", [])
        self.default_credentials: Dict[str, str] = config.get("default_credentials", {})

    def validate_config(self, config: Dict) -> None:
        """Validate configuration structure."""
        # Ensure required keys are present
        required_keys = ["files_to_check", "unwanted_services", "default_credentials"]
        for key in required_keys:
            if key not in config:
                raise ValueError(f"Configuration must include '{key}'.")

        # Validate each component of the configuration
        if not isinstance(config["files_to_check"], list):
            raise ValueError("'files_to_check' must be a list.")
        if not isinstance(config["unwanted_services"], list):
            raise ValueError("'unwanted_services' must be a list.")
        if not isinstance(config["default_credentials"], dict):
            raise ValueError("'default_credentials' must be a dictionary.")

    def log_message(self, level: str, message: str) -> None:
        """Log messages at the specified log level."""
        log_method = logging.info if level != "warning" else logging.warning
        log_method(message)

    def check_permissions(self, file_path: str) -> bool:
        """Check permissions of a specified file."""
        if os.path.exists(file_path):
            permissions = os.stat(file_path).st_mode
            if (permissions & stat.S_IRGRP) or (permissions & stat.S_IROTH) or \
               (permissions & stat.S_IWGRP) or (permissions & stat.S_IWOTH):
                self.log_message("warning", f"{file_path} has insecure permissions.")
                return False
            else:
                self.log_message("info", f"{file_path} permissions are secure.")
                return True
        else:
            self.log_message("warning", f"{file_path} does not exist.")
            return False

    def get_running_services(self) -> List[str]:
        """Get a list of currently running services, with caching."""
        if not self.running_services_cache:
            try:
                self.running_services_cache = [p.name() for p in psutil.process_iter(['name'])]
            except psutil.AccessDenied:
                self.log_message("warning", "Access denied while enumerating processes.")
                self.running_services_cache = []
            except Exception as e:
                self.log_message("warning", f"Error while checking running services: {e}")
                self.running_services_cache = []
        return self.running_services_cache

    def check_default_credentials(self, username: str, password: str) -> bool:
    """Check if default credentials are being used."""
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    stored_hashed = self.default_credentials.get(username)
    if stored_hashed is not None:
        if stored_hashed == hashed_password:
            self.log_message("warning", f"Default credentials in use for '{username}'.")
            return False
        else:
            self.log_message("info", f"Custom credentials for '{username}' are provided.")
            return True
    else:
        self.log_message("info", f"Username '{username}' not found in default credentials, treat as custom.")
        return True

        else:
            self.log_message("info", f"Username '{username}' not found in default credentials, treat as custom.")
            return True

    def run_checks(self) -> None:
        """Run all security checks."""
        issues: List[str] = []

        self.log_message("info", "Checking file permissions...")
        for file in self.files_to_check:
            if not self.check_permissions(file):
                issues.append(f"Insecure permissions: {file}")

        self.log_message("info", "Checking running services...")
        unwanted_services_found = [service for service in self.unwanted_services if service in self.get_running_services()]
        for service in unwanted_services_found:
            issues.append(f"Unwanted service running: {service}")

        self.log_message("info", "Checking for default credentials...")
        for username, password in self.default_credentials.items():
            if not self.check_default_credentials(username, password):
                issues.append(f"Default credentials in use for: {username}")

        if issues:
            self.log_message("warning", "Summary of Issues Found:")
            for issue in issues:
                self.log_message("warning", issue)
            raise RuntimeError("Security issues found")  # Use exceptions instead of exit
        else:
            self.log_message("info", "No issues found. System is secure.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run security checks on the system.")
    parser.add_argument('--config', type=str, help='Path to the configuration file', required=True)
    args = parser.parse_args()

    try:
        checker = SecurityChecker(args.config)
        checker.run_checks()
    except ValueError as e:
        logging.error(f"Error: {e}")
        exit(1)
    except RuntimeError as e:
        logging.error(f"Error: {e}")
        exit(2)
