#!/usr/bin/env python3
"""
Example script demonstrating how to use the ossec-config-manager package.
"""

from ossec_config_manager import OSSECConfigManager
import os

def main():
    # Initialize the manager with your OSSEC config file
    config_path = '/var/ossec/etc/ossec.conf'
    manager = OSSECConfigManager(config_path)

    # Example 1: Get all integrations
    print("\nGetting all integrations:")
    integrations = manager.get_integrations()
    for integration in integrations:
        print(f"- {integration}")

    # Example 2: Add a new Slack integration
    print("\nAdding Slack integration:")
    new_integration = {
        'name': 'slack',
        'hook_url': 'https://hooks.slack.com/services/...',
        'level': '12'
    }
    manager.add_integration(new_integration)

    # Example 3: Update vulnerability detection settings
    print("\nUpdating vulnerability detection settings:")
    updates = {
        'enabled': 'yes',
        'interval': '1h'
    }
    manager.update_config_section('ossec_config/vulnerability-detection', updates)

    # Example 4: Add a new list to ruleset
    print("\nAdding new list to ruleset:")
    manager.add_ruleset_list('ossec_config/ruleset', 'etc/lists/blacklist-alienvault')

    # Example 5: Save with different backup options
    print("\nSaving with different backup options:")
    
    # Option 1: Save to original file with automatic backup
    print("\nOption 1: Save to original file with automatic backup")
    manager.save_config()  # Will create backup with timestamp
    
    # Option 2: Save to original file with custom backup path
    print("\nOption 2: Save to original file with custom backup path")
    custom_backup = '/var/ossec/etc/backups/ossec.conf.backup'
    manager.save_config(backup_path=custom_backup)
    
    # Option 3: Save to new file without backup
    print("\nOption 3: Save to new file without backup")
    new_config = '/var/ossec/etc/ossec_new.conf'
    manager.save_config(file_path=new_config, create_backup=False)
    
    # Option 4: Save to new file with backup
    print("\nOption 4: Save to new file with backup")
    manager.save_config(
        file_path='/var/ossec/etc/ossec_updated.conf',
        backup_path='/var/ossec/etc/backups/ossec_updated.backup'
    )

if __name__ == "__main__":
    main() 