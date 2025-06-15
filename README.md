# OSSEC Config Manager

A Python package for managing Wazuh OSSEC configurations.

## Features

- Manage OSSEC integrations
- Update configuration sections
- Backup and restore configurations
- Debian package support

## Installation

### From Debian Package

1. Build the Debian package:
```bash
./build_deb.sh
```

2. Install the package:
```bash
sudo apt install ./python3-ossec-config-manager_*.deb
```

### From GitHub

```bash
pip install git+https://github.com/yourusername/ossec-config-manager.git
```

## Usage

```python
from ossec_config_manager import OSSECConfigManager

# Initialize the manager
manager = OSSECConfigManager()

# Get all integrations
integrations = manager.get_integrations()

# Add a new integration
manager.add_integration('slack', {
    'webhook_url': 'https://hooks.slack.com/services/...',
    'channel': '#alerts'
})

# Update a configuration section
manager.update_section('global', {
    'email_notification': 'yes',
    'email_to': 'admin@example.com'
})

# Save changes with backup
manager.save_changes(backup=True)
```

## Build Process

The `build_deb.sh` script automates the Debian package creation process:

1. Checks for required build tools
2. Installs missing dependencies
3. Updates the changelog
4. Cleans previous build artifacts
5. Builds the package
6. Provides installation instructions

### Build Artifacts

- `python3-ossec-config-manager_*.deb`: The Debian package
- `python3-ossec-config-manager_*.dsc`: Package description
- `python3-ossec-config-manager_*.tar.gz`: Source tarball
- `python3-ossec-config-manager_*.changes`: Package changes

## License

This project is licensed under the MIT License. 