# OSSEC Config Manager

A Python package for managing Wazuh OSSEC configurations. This package provides a simple and efficient way to manage OSSEC configuration files programmatically.

## Features

- Parse and modify OSSEC configuration files
- Manage integrations
- Update XML blocks
- Insert and delete configuration elements
- Backup and restore configurations

## Installation

You can install the package using pip:

```bash
pip install git+https://github.com/yourusername/ossec-config-manager.git
```

## Usage

```python
from ossec_config_manager import OSSECConfigManager

# Initialize the manager with your OSSEC config file
manager = OSSECConfigManager('/path/to/ossec.conf')

# Read integrations
integrations = manager.read_ossec_integrations()

# Add a new integration
new_integration = {
    'name': 'slack',
    'hook_url': 'https://hooks.slack.com/services/...',
    'level': '12'
}
manager.insert_ossec_integration(new_integration)

# Update a configuration block
updates = {
    'enabled': 'yes',
    'interval': '1h'
}
manager.update_xml_block('ossec_config/vulnerability-detection', updates)

# Save changes
manager.save_tree()
```

## License

This project is licensed under the MIT License - see the LICENSE file for details. 