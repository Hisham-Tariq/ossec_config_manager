"""
Active Response Manager for Wazuh OSSEC

This module provides a class for managing Wazuh OSSEC active responses.
It allows for managing commands and active responses in the OSSEC configuration.
"""

from typing import List, Dict, Any, Optional
from enum import Enum
import xml.etree.ElementTree as ET
from .ossec_config import OSSECConfigManager


class LocationType(Enum):
    """Enum for active response location types."""
    LOCAL = "local"
    SERVER = "server"
    DEFINED_AGENT = "defined-agent"
    ALL = "all"


class ActiveResponseManager(OSSECConfigManager):
    """
    A class for managing Wazuh OSSEC active responses.
    
    This class provides methods to manage commands and active responses
    in the OSSEC configuration file.
    
    Attributes:
        file_path (str): Path to the OSSEC configuration file
        tree (ElementTree): The parsed XML tree
        root (Element): The root element of the XML tree
    """
    
    def __init__(self, file_path: str):
        """
        Initialize the ActiveResponseManager with a configuration file.
        
        Args:
            file_path (str): Path to the OSSEC configuration file
        """
        super().__init__(file_path)
        self._validate_commands()

    def _validate_commands(self) -> None:
        """
        Validate that all commands referenced in active responses exist.
        Raises ValueError if any command is missing.
        """
        active_responses = self.root.findall('.//active-response')
        for ar in active_responses:
            command = ar.find('command')
            if command is not None and not self.command_exists(command.text):
                raise ValueError(f"Command '{command.text}' referenced in active response does not exist")

    def _validate_rules_group(self, rules_group: str) -> bool:
        """
        Validate the format of a rules group string.
        
        Args:
            rules_group (str): Rules group string to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        if not rules_group:
            return False
        
        # Check if groups end with comma
        groups = rules_group.split('|')
        return all(group.strip().endswith(',') for group in groups)

    def _validate_rules_id(self, rules_id: str) -> bool:
        """
        Validate the format of a rules ID string.
        
        Args:
            rules_id (str): Rules ID string to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        if not rules_id:
            return False
        
        # Check if all IDs are numeric
        ids = rules_id.split(',')
        return all(id.strip().isdigit() for id in ids)

    def _validate_level(self, level: int) -> bool:
        """
        Validate a severity level.
        
        Args:
            level (int): Level to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        return 1 <= level <= 16

    def get_commands(self) -> List[Dict[str, str]]:
        """
        Get all commands from the OSSEC configuration.
        
        Returns:
            List[Dict[str, str]]: List of dictionaries containing command details
        """
        commands = []
        for command in self.root.findall('.//command'):
            command_info = {}
            for element in command:
                command_info[element.tag] = element.text
            commands.append(command_info)
        return commands

    def add_command(self, name: str, executable: str, timeout_allowed: bool = True) -> bool:
        """
        Add a new command to the OSSEC configuration.
        
        Args:
            name (str): Name of the command
            executable (str): Executable to run
            timeout_allowed (bool): Whether timeout is allowed
            
        Returns:
            bool: True if command was added, False if it already exists
        """
        if self.command_exists(name):
            print(f"Command '{name}' already exists.")
            return False

        new_command = ET.SubElement(self.root.find('ossec_config'), 'command')
        
        name_elem = ET.SubElement(new_command, 'name')
        name_elem.text = name
        
        exec_elem = ET.SubElement(new_command, 'executable')
        exec_elem.text = executable
        
        timeout_elem = ET.SubElement(new_command, 'timeout_allowed')
        timeout_elem.text = 'yes' if timeout_allowed else 'no'
        
        print(f"New command '{name}' has been added.")
        return True

    def update_command(self, name: str, updates: Dict[str, Any]) -> bool:
        """
        Update an existing command in the OSSEC configuration.
        
        Args:
            name (str): Name of the command to update
            updates (Dict[str, Any]): Dictionary of updates to apply
            
        Returns:
            bool: True if command was updated, False otherwise
        """
        for command in self.root.findall('.//command'):
            command_name = command.find('name')
            if command_name is not None and command_name.text == name:
                for tag, value in updates.items():
                    element = command.find(tag)
                    if element is not None:
                        element.text = str(value)
                    else:
                        new_element = ET.SubElement(command, tag)
                        new_element.text = str(value)
                print(f"Command '{name}' has been updated.")
                return True
        print(f"No command found with name '{name}'.")
        return False

    def remove_command(self, name: str) -> bool:
        """
        Remove a command from the OSSEC configuration.
        
        Args:
            name (str): Name of the command to remove
            
        Returns:
            bool: True if command was removed, False otherwise
        """
        for command in self.root.findall('.//command'):
            command_name = command.find('name')
            if command_name is not None and command_name.text == name:
                self.root.remove(command)
                print(f"Command '{name}' has been removed.")
                return True
        print(f"No command found with name '{name}'.")
        return False

    def command_exists(self, name: str) -> bool:
        """
        Check if a command exists in the OSSEC configuration.
        
        Args:
            name (str): Name of the command to check
            
        Returns:
            bool: True if command exists, False otherwise
        """
        for command in self.root.findall('.//command'):
            command_name = command.find('name')
            if command_name is not None and command_name.text == name:
                return True
        return False

    def get_active_responses(self) -> List[Dict[str, Any]]:
        """
        Get all active responses from the OSSEC configuration.
        
        Returns:
            List[Dict[str, Any]]: List of dictionaries containing active response details
        """
        active_responses = []
        for ar in self.root.findall('.//active-response'):
            ar_info = {}
            for element in ar:
                ar_info[element.tag] = element.text
            active_responses.append(ar_info)
        return active_responses

    def add_active_response(self,
        command: str,
        location: str,
        level: Optional[int] = None,
        timeout: Optional[int] = None,
        agent_id: Optional[str] = None,
        rules_group: Optional[str] = None,
        rules_id: Optional[str] = None
    ) -> bool:
        """
        Add a new active response to the OSSEC configuration.
        
        Args:
            command (str): Name of the command to execute
            location (str): Where to execute the command
            level (Optional[int]): Minimum severity level
            timeout (Optional[int]): Timeout in seconds
            agent_id (Optional[str]): Agent ID for defined-agent location
            rules_group (Optional[str]): Rule group(s) to trigger on
            rules_id (Optional[str]): Rule ID(s) to trigger on
            
        Returns:
            bool: True if active response was added, False otherwise
        """
        if not self.command_exists(command):
            print(f"Command '{command}' does not exist.")
            return False

        if location not in [lt.value for lt in LocationType]:
            print(f"Invalid location type '{location}'.")
            return False

        if location == LocationType.DEFINED_AGENT.value and not agent_id:
            print("Agent ID is required for defined-agent location.")
            return False

        if level is not None and not self._validate_level(level):
            print(f"Invalid level value: {level}. Must be between 1 and 16.")
            return False

        if rules_group is not None and not self._validate_rules_group(rules_group):
            print("Invalid rules group format. Groups must end with comma and be pipe-separated.")
            return False

        if rules_id is not None and not self._validate_rules_id(rules_id):
            print("Invalid rules ID format. IDs must be numeric and comma-separated.")
            return False

        new_ar = ET.SubElement(self.root.find('ossec_config'), 'active-response')
        
        command_elem = ET.SubElement(new_ar, 'command')
        command_elem.text = command
        
        location_elem = ET.SubElement(new_ar, 'location')
        location_elem.text = location
        
        if level is not None:
            level_elem = ET.SubElement(new_ar, 'level')
            level_elem.text = str(level)
        
        if timeout is not None:
            timeout_elem = ET.SubElement(new_ar, 'timeout')
            timeout_elem.text = str(timeout)
        
        if agent_id is not None:
            agent_id_elem = ET.SubElement(new_ar, 'agent_id')
            agent_id_elem.text = agent_id
        
        if rules_group is not None:
            rules_group_elem = ET.SubElement(new_ar, 'rules_group')
            rules_group_elem.text = rules_group
        
        if rules_id is not None:
            rules_id_elem = ET.SubElement(new_ar, 'rules_id')
            rules_id_elem.text = rules_id
        
        print(f"New active response for command '{command}' has been added.")
        return True

    def update_active_response(self, command: str, updates: Dict[str, Any]) -> bool:
        """
        Update an existing active response in the OSSEC configuration.
        
        Args:
            command (str): Command name of the active response to update
            updates (Dict[str, Any]): Dictionary of updates to apply
            
        Returns:
            bool: True if active response was updated, False otherwise
        """
        for ar in self.root.findall('.//active-response'):
            ar_command = ar.find('command')
            if ar_command is not None and ar_command.text == command:
                for tag, value in updates.items():
                    # Validate values before updating
                    if tag == 'level' and not self._validate_level(int(value)):
                        print(f"Invalid level value: {value}. Must be between 1 and 16.")
                        return False
                    elif tag == 'rules_group' and not self._validate_rules_group(value):
                        print("Invalid rules group format. Groups must end with comma and be pipe-separated.")
                        return False
                    elif tag == 'rules_id' and not self._validate_rules_id(value):
                        print("Invalid rules ID format. IDs must be numeric and comma-separated.")
                        return False
                    
                    element = ar.find(tag)
                    if element is not None:
                        element.text = str(value)
                    else:
                        new_element = ET.SubElement(ar, tag)
                        new_element.text = str(value)
                print(f"Active response for command '{command}' has been updated.")
                return True
        print(f"No active response found for command '{command}'.")
        return False

    def remove_active_response(self, command: str) -> bool:
        """
        Remove an active response from the OSSEC configuration.
        
        Args:
            command (str): Command name of the active response to remove
            
        Returns:
            bool: True if active response was removed, False otherwise
        """
        for ar in self.root.findall('.//active-response'):
            ar_command = ar.find('command')
            if ar_command is not None and ar_command.text == command:
                self.root.remove(ar)
                print(f"Active response for command '{command}' has been removed.")
                return True
        print(f"No active response found for command '{command}'.")
        return False

    def active_response_exists(self, command: str) -> bool:
        """
        Check if an active response exists for a command.
        
        Args:
            command (str): Command name to check
            
        Returns:
            bool: True if active response exists, False otherwise
        """
        for ar in self.root.findall('.//active-response'):
            ar_command = ar.find('command')
            if ar_command is not None and ar_command.text == command:
                return True
        return False

    def create_ssh_block_response(self,
        location: str = LocationType.LOCAL.value,
        level: int = 7,
        timeout: int = 600,
        rules_id: str = "5763,5761,5762"
    ) -> bool:
        """
        Create an active response for blocking SSH brute force attempts.
        
        Args:
            location (str): Where to execute the command
            level (int): Minimum severity level
            timeout (int): Timeout in seconds
            rules_id (str): Rule IDs to trigger on
            
        Returns:
            bool: True if active response was created, False otherwise
        """
        # First ensure the command exists
        if not self.command_exists("host-deny"):
            self.add_command("host-deny", "host-deny", timeout_allowed=True)
        
        return self.add_active_response(
            command="host-deny",
            location=location,
            level=level,
            timeout=timeout,
            rules_id=rules_id
        )

    def create_agent_restart_response(self,
        location: str = LocationType.LOCAL.value,
        level: int = 12,
        timeout: int = 300
    ) -> bool:
        """
        Create an active response for restarting the Wazuh agent.
        
        Args:
            location (str): Where to execute the command
            level (int): Minimum severity level
            timeout (int): Timeout in seconds
            
        Returns:
            bool: True if active response was created, False otherwise
        """
        # First ensure the command exists
        if not self.command_exists("restart-ossec"):
            self.add_command("restart-ossec", "restart-ossec", timeout_allowed=False)
        
        return self.add_active_response(
            command="restart-ossec",
            location=location,
            level=level,
            timeout=timeout
        )

    def create_user_disable_response(self,
        location: str = LocationType.LOCAL.value,
        level: int = 10,
        timeout: int = 3600,
        rules_group: str = "authentication_failure,"
    ) -> bool:
        """
        Create an active response for disabling user accounts.
        
        Args:
            location (str): Where to execute the command
            level (int): Minimum severity level
            timeout (int): Timeout in seconds
            rules_group (str): Rule group to trigger on
            
        Returns:
            bool: True if active response was created, False otherwise
        """
        # First ensure the command exists
        if not self.command_exists("disable-account"):
            self.add_command("disable-account", "disable-account", timeout_allowed=True)
        
        return self.add_active_response(
            command="disable-account",
            location=location,
            level=level,
            timeout=timeout,
            rules_group=rules_group
        ) 