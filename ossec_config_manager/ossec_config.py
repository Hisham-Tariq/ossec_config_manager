"""
OSSEC Configuration Manager

This module provides a class for managing Wazuh OSSEC configurations.
It allows for parsing, modifying, and saving OSSEC configuration files.
"""

import xml.etree.ElementTree as ET
import os
import shutil
import datetime
from pathlib import Path


class OSSECConfigManager:
    """
    A class for managing Wazuh OSSEC configurations.
    
    This class provides methods to parse, modify, and save OSSEC configuration files.
    It supports operations like managing integrations, updating XML blocks,
    and handling configuration backups.
    
    Attributes:
        file_path (str): Path to the OSSEC configuration file
        tree (ElementTree): The parsed XML tree
        root (Element): The root element of the XML tree
    """
    
    def __init__(self, file_path):
        """
        Initialize the OSSECConfigManager with a configuration file.
        
        Args:
            file_path (str): Path to the OSSEC configuration file
        """
        self.file_path = file_path
        self.tree, self.root = self._parse_with_single_root()
        self.organize_ossec_config()

    def _parse_with_single_root(self):
        """
        Parse the OSSEC configuration file and wrap it in a root element.
        
        Returns:
            tuple: (ElementTree, Element) containing the parsed tree and root element
        """
        with open(self.file_path, 'r') as file:
            content = file.read()

        wrapped_content = f"<root>{content}</root>"

        tree = ET.ElementTree(ET.fromstring(wrapped_content))
        root = tree.getroot()
        return tree, root

    def organize_ossec_config(self):
        """
        Organize the OSSEC configuration by combining multiple ossec_config blocks.
        If multiple ossec_config blocks exist, they are combined into the first one.
        """
        ossec_config_elements = self.root.findall('ossec_config')
        if len(ossec_config_elements) > 1:
            primary_ossec_config = ossec_config_elements[0]
            for extra_ossec_config in ossec_config_elements[1:]:
                for child in list(extra_ossec_config):
                    primary_ossec_config.append(child)
                self.root.remove(extra_ossec_config)
            print("All ossec_config blocks have been combined into the first one.")
        else:
            print("No extra ossec_config blocks to combine.")

    def get_integrations(self):
        """
        Get all integrations from the OSSEC configuration.
        
        Returns:
            list: List of dictionaries containing integration details
        """
        integrations = []
        for integration in self.root.findall('.//integration'):
            integration_info = {}
            for element in integration:
                integration_info[element.tag] = element.text
            integrations.append(integration_info)
        return integrations

    def remove_integration(self, name, hook_url=None):
        """
        Remove an integration from the OSSEC configuration.
        
        Args:
            name (str): Name of the integration to remove
            hook_url (str, optional): Hook URL of the integration to remove
            
        Returns:
            bool: True if integration was removed, False otherwise
        """
        removed = False
        for integration in self.root.findall('.//integration'):
            integration_name = integration.find('name').text if integration.find('name') is not None else None
            integration_hook_url = integration.find('hook_url').text if integration.find('hook_url') is not None else None

            if integration_name == name and (hook_url is None or integration_hook_url == hook_url):
                self.root.remove(integration)
                removed = True
                break

        if removed:
            print(f"Integration with name '{name}' and hook_url '{hook_url}' has been removed.")
        else:
            print(f"No integration found with name '{name}' and hook_url '{hook_url}'.")
        return removed

    def update_integration(self, name, updates, hook_url=None):
        """
        Update an existing integration in the OSSEC configuration.
        
        Args:
            name (str): Name of the integration to update
            updates (dict): Dictionary of updates to apply
            hook_url (str, optional): Hook URL of the integration to update
            
        Returns:
            bool: True if integration was updated, False otherwise
        """
        updated = False
        for integration in self.root.findall('.//integration'):
            integration_name = integration.find('name').text if integration.find('name') is not None else None
            integration_hook_url = integration.find('hook_url').text if integration.find('hook_url') is not None else None

            if integration_name == name and (hook_url is None or integration_hook_url == hook_url):
                for tag, value in updates.items():
                    element = integration.find(tag)
                    if element is not None:
                        element.text = value
                    else:
                        new_element = ET.SubElement(integration, tag)
                        new_element.text = value
                updated = True
                break

        if updated:
            print(f"Integration with name '{name}' and hook_url '{hook_url}' has been updated.")
        else:
            print(f"No integration found with name '{name}' and hook_url '{hook_url}'.")
        return updated

    def add_integration(self, integration_details):
        """
        Add a new integration to the OSSEC configuration.
        
        Args:
            integration_details (dict): Dictionary containing integration details
            
        Returns:
            Element: The newly created integration element
        """
        new_integration = ET.SubElement(self.root.find('ossec_config'), 'integration')
        for tag, value in integration_details.items():
            new_element = ET.SubElement(new_integration, tag)
            new_element.text = value
        print(f"New integration with name '{integration_details.get('name')}' has been added.")
        return new_integration

    def update_config_section(self, path, updates):
        """
        Update a configuration section in the OSSEC configuration.
        
        Args:
            path (str): The path to the section that needs to be updated
            updates (dict): A dictionary containing the updates
        """
        def apply_updates(element, updates):
            for tag, value in updates.items():
                if isinstance(value, dict):
                    child = element.find(tag)
                    if child is None:
                        child = ET.SubElement(element, tag)
                    apply_updates(child, value)
                elif isinstance(value, list):
                    parent = element.find(tag)
                    if parent is None:
                        parent = ET.SubElement(element, tag)
                    parent.clear()
                    for item in value:
                        child = ET.SubElement(parent, item['tag'])
                        child.text = item['text']
                else:
                    child = element.find(tag)
                    if child is None:
                        child = ET.SubElement(element, tag)
                    child.text = value

        target_element = self.root.find(path)
        if target_element is not None:
            apply_updates(target_element, updates)
        else:
            tags = path.split('/')
            current_element = self.root
            for tag in tags:
                next_element = current_element.find(tag)
                if next_element is None:
                    next_element = ET.SubElement(current_element, tag)
                current_element = next_element
            apply_updates(current_element, updates)
    
    def add_config_section(self, path, new_section):
        """
        Add a new configuration section to the OSSEC configuration.
        
        Args:
            path (str): The path where the new section should be added
            new_section (dict): A dictionary representing the new section to be added
        """
        def create_section(element, section):
            for tag, value in section.items():
                if isinstance(value, dict):
                    child = ET.SubElement(element, tag)
                    create_section(child, value)
                elif isinstance(value, list):
                    parent = ET.SubElement(element, tag)
                    for item in value:
                        child = ET.SubElement(parent, item['tag'])
                        child.text = item['text']
                else:
                    child = ET.SubElement(element, tag)
                    child.text = value

        parent_element = self.root.find(path)
        if parent_element is not None:
            create_section(parent_element, new_section)
        else:
            tags = path.split('/')
            current_element = self.root
            for tag in tags:
                next_element = current_element.find(tag)
                if next_element is None:
                    next_element = ET.SubElement(current_element, tag)
                current_element = next_element
            create_section(current_element, new_section)

    def remove_config_section(self, path):
        """
        Remove a configuration section from the OSSEC configuration.
        
        Args:
            path (str): The path to the section that needs to be removed
        """
        parent_path = '/'.join(path.split('/')[:-1])
        section_name = path.split('/')[-1]

        parent_element = self.root.find(parent_path)
        if parent_element is not None:
            for child in parent_element.findall(section_name):
                parent_element.remove(child)
            print(f"Section '{section_name}' at path '{path}' has been removed.")
        else:
            print(f"No section found at path '{path}' to remove.")
    
    def section_exists(self, path):
        """
        Check if a configuration section exists.
        
        Args:
            path (str): The path to the section to check
            
        Returns:
            bool: True if the section exists, False otherwise
        """
        element = self.root.find(path)
        return element is not None

    def _format_config(self, element, indent="  "):
        """
        Format the OSSEC configuration for better readability.
        
        Args:
            element (Element): The root element to format
            indent (str): The indentation string to use
        """
        queue = [(0, element)]
        while queue:
            level, element = queue.pop(0)
            children = [(level + 1, child) for child in list(element)]
            if children:
                element.text = "\n" + indent * (level + 1)
            if queue:
                element.tail = "\n" + indent * queue[0][0]
            else:
                element.tail = "\n" + indent * (level - 1)
            queue[0:0] = children

    def create_backup(self, backup_path=None):
        """
        Create a backup of the current OSSEC configuration.
        
        Args:
            backup_path (str, optional): Path where to save the backup.
                                       If None, creates backup in the same directory
                                       with timestamp in the filename.
                                       
        Returns:
            str: Path to the created backup file
        """
        if backup_path is None:
            # Create backup in the same directory with timestamp
            file_dir = os.path.dirname(self.file_path)
            file_name = os.path.basename(self.file_path)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = os.path.join(file_dir, f"{file_name}.{timestamp}.bak")
        
        # Ensure the backup directory exists
        os.makedirs(os.path.dirname(backup_path), exist_ok=True)
        
        # Create the backup
        shutil.copy2(self.file_path, backup_path)
        print(f"Backup created at: {backup_path}")
        return backup_path

    def save_config(self, file_path=None, create_backup=True, backup_path=None):
        """
        Save the current OSSEC configuration to a file.
        
        Args:
            file_path (str, optional): Path to save the configuration to.
                                     If None, updates the original file.
            create_backup (bool): Whether to create a backup before saving.
            backup_path (str, optional): Path where to save the backup.
                                       If None and create_backup is True,
                                       creates backup in the same directory
                                       with timestamp in the filename.
        """
        # Create backup if requested
        if create_backup:
            self.create_backup(backup_path)
            
        # Determine the target file path
        target_path = file_path if file_path is not None else self.file_path
        
        # Ensure the target directory exists
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        
        # Save the configuration
        self._format_config(self.root)
        tree_str = ET.tostring(self.root, encoding='unicode')
        with open(target_path, 'w') as file:
            file.write(tree_str[7:-8])
        print(f"Updated configuration saved to '{target_path}'")
    
    def add_ruleset_list(self, path, new_list_value):
        """
        Add a new list to the ruleset configuration.
        
        Args:
            path (str): The path to the ruleset section
            new_list_value (str): The value of the new list to be added
        """
        ruleset_element = self.root.find(path)
        if ruleset_element is not None:
            existing_lists = [list_elem.text for list_elem in ruleset_element.findall('list')]
            if new_list_value not in existing_lists:
                new_list_element = ET.SubElement(ruleset_element, 'list')
                new_list_element.text = new_list_value
                print(f"New list with value '{new_list_value}' has been added to ruleset.")
            else:
                print(f"List with value '{new_list_value}' already exists in ruleset.")
        else:
            print(f"Ruleset section at '{path}' does not exist.") 