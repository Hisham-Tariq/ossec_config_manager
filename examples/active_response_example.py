#!/usr/bin/env python3
"""
Example script demonstrating how to use the ActiveResponseManager class.
"""

from ossec_config_manager import ActiveResponseManager
import os

def main():
    # Initialize the manager with your OSSEC config file
    config_path = '/var/ossec/etc/ossec.conf'
    manager = ActiveResponseManager(config_path)

    # Example 1: Get all commands
    print("\nGetting all commands:")
    commands = manager.get_commands()
    for command in commands:
        print(f"- {command}")

    # Example 2: Add a new command
    print("\nAdding new command:")
    manager.add_command(
        name="custom-block",
        executable="custom-block.sh",
        timeout_allowed=True
    )

    # Example 3: Add a new active response
    print("\nAdding new active response:")
    manager.add_active_response(
        command="custom-block",
        location="local",
        level=10,
        timeout=300,
        rules_id="1001,1002,1003"
    )

    # Example 4: Create SSH block response
    print("\nCreating SSH block response:")
    manager.create_ssh_block_response(
        location="local",
        level=7,
        timeout=600,
        rules_id="5763,5761,5762"
    )

    # Example 5: Create agent restart response
    print("\nCreating agent restart response:")
    manager.create_agent_restart_response(
        location="local",
        level=12,
        timeout=300
    )

    # Example 6: Create user disable response
    print("\nCreating user disable response:")
    manager.create_user_disable_response(
        location="local",
        level=10,
        timeout=3600,
        rules_group="authentication_failure,"
    )

    # Example 7: Update an active response
    print("\nUpdating active response:")
    manager.update_active_response(
        command="custom-block",
        updates={
            "level": "12",
            "timeout": "600",
            "rules_group": "authentication_failure,|pci_dss_11.4,"
        }
    )

    # Example 8: Get all active responses
    print("\nGetting all active responses:")
    active_responses = manager.get_active_responses()
    for ar in active_responses:
        print(f"- {ar}")

    # Example 9: Remove an active response
    print("\nRemoving active response:")
    # Remove by command only (original behavior)
    manager.remove_active_response(command="custom-block")
    
    # Remove by multiple parameters
    manager.remove_active_response(
        command="host-deny",
        location="local",
        level=7,
        timeout=600
    )
    
    # Remove by rules group
    manager.remove_active_response(
        rules_group="authentication_failure,"
    )
    
    # Remove by location and level
    manager.remove_active_response(
        location="local",
        level=12
    )

    # Example 10: Save changes
    print("\nSaving changes:")
    manager.save_config()

if __name__ == "__main__":
    main() 