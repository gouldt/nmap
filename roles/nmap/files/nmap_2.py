import csv
import asyncio
import concurrent.futures
import time
import subprocess
import re
from netmiko.ssh_autodetect import SSHDetect
from netmiko.ssh_dispatcher import ConnectHandler
import os
from concurrent.futures import ThreadPoolExecutor
import nmap
import yaml
#import requests
import aiohttp
import ssl
import requests
import xml.etree.ElementTree as ET
import cProfile
import pstats

VMANAGE_CONFIGS = [
    {
        'host': 'https://vmanage-1376865.viptela.net',
        'username': 'svc-gnssolarwinds',
        'password': 'Th1nkOutSiDe7h3B0x#'
    },
    {
        'host': 'https://china-vmanage.corporate.ingrammicro.com',
        'username': 'admin',
        'password': 'd3RuC3$3tR0F123'
    }
]
async def login(session, host, username, password):
    login_url = f'{host}/j_security_check'
    data = {'j_username': username, 'j_password': password}
    # Disable SSL verification
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    async with session.post(login_url, data=data, ssl=ssl_context) as response:
        if response.status != 200:
            raise Exception(f"Login Failed with status: {response.status}")
        return await response.text()

async def fetch_devices(session, host):
    device_url = f'{host}/dataservice/device'
    # Disable SSL verification
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    async with session.get(device_url, ssl=ssl_context) as response:
        if response.status != 200:
            raise Exception(f"Failed to fetch devices: {response.status}")
        return await response.json()

def extract_vmanage_device_info(device, config):
    return {
        'Device Name': device.get('host-name', 'N/A'),
        'Device IP': device.get('system-ip', 'N/A'),
        'Detected Type': 'cisco.viptela',
        'Model': device.get('device-model', 'N/A'),
        'Version': device.get('version', 'N/A'),
        'Serial Number': device.get('uuid', 'N/A'),
        'Hostname': device.get('host-name', 'N/A'),
        'Credentials': f"{config['username']}/{config['password']}"
    }
async def fetch_vmanage_data():
    all_vmanage_data = []
    for config in VMANAGE_CONFIGS:
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(verify_ssl=False)) as session:
                await login(session, config['host'], config['username'], config['password'])
                response = await fetch_devices(session, config['host'])
                devices = response.get('data', [])
                for device in devices:
                    device_info = extract_vmanage_device_info(device, config)
                    all_vmanage_data.append(device_info)
        except Exception as e:
            error_message = f"Failed to fetch data from {config['host']}: {e}"
            print(error_message)  # Log to console
            # Alternatively, log to a file:
            with open('error_log.txt', 'a') as error_file:
                error_file.write(error_message + '\n')
    return all_vmanage_data



API_KEY = '0ea261cb3a34e71af7d13d336d10be7063e433b0'
BASE_URL = 'https://api.meraki.com/api/v1'

headers = {
    'X-Cisco-Meraki-API-Key': API_KEY,
    'Content-Type': 'application/json'
}

async def get_organizations(session):
    response = await session.get(f'{BASE_URL}/organizations', headers=headers)
    if response.status == 200:
        return await response.json()
    else:
        return []  # Return an empty list if the request fails

async def get_networks(session, org_id):
    response = await session.get(f'{BASE_URL}/organizations/{org_id}/networks', headers=headers)
    if response.status == 200:
        return await response.json()
    else:
        return []  # Return an empty list if the request fails

async def get_devices(session, network_id):
    response = await session.get(f'{BASE_URL}/networks/{network_id}/devices', headers=headers)
    if response.status == 200:
        return await response.json()
    else:
        return []  # Return an empty list if the request fails

async def fetch_meraki_data():
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(verify_ssl=False)) as session:
        organizations = await get_organizations(session)
        results = []
        for org in organizations:
            networks = await get_networks(session, org['id'])
            for network in networks:
                devices = await get_devices(session, network['id'])
                for device in devices:
                    device_info = {
                        'Device Name': device.get('name', 'N/A'),
                        'Device IP': device.get('lanIp', 'N/A'),
                        'Detected Type': 'cisco.meraki',
                        'Model': device.get('model'),
                        'Version': device.get('productType', 'N/A'),
                        'Serial Number': device.get('serial'),
                        'Hostname': network['id'],
                        'Credentials': API_KEY
                    }
                    results.append(device_info)
        return results


# Global set to keep track of completed subnets
completed_subnets = set()
# Function to run Nmap version detection with OS scan
def run_nmap_version_detection(host):
    command = ["nmap", "-sV", "-O", "--osscan-guess", "-p", "22", host]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Regular expressions to match required fields from Nmap output
    version_regex = r"(\d+/\w+)\s+open\s+\w+\s+([^ ]+)"
    os_details_regex = r"OS details: ([^\n]+)"
    os_cpe_regex = r"OS CPE: ([^\n]+)"
    running_regex = r"Running: ([^\n]+)"

    # Extracting data using regular expressions
    version_match = re.search(version_regex, result.stdout)
    os_details_match = re.search(os_details_regex, result.stdout)
    os_cpe_match = re.search(os_cpe_regex, result.stdout)
    running_match = re.search(running_regex, result.stdout)

    version = version_match.group(2) if version_match else "Unknown"
    os_details = os_details_match.group(1) if os_details_match else "Unknown"
    os_cpe = os_cpe_match.group(1) if os_cpe_match else "Unknown"
    running = running_match.group(1) if running_match else "Unknown"

    # Combine all extracted information into a single string
    combined_output = f"SSH Version: {version}, OS Details: {os_details}, OS CPE: {os_cpe}, Running: {running}"
    return combined_output


def load_progress():
    if os.path.exists("/opt/dataGather/nmap/scan_results/completed_subnets.txt"):
        with open("/opt/dataGather/nmap/scan_results/completed_subnets.txt", "r") as file:
            for line in file:
                completed_subnets.add(line.strip())

def save_progress():
    with open("/opt/dataGather/nmap/scan_results/completed_subnets.txt", "w") as file:
        for subnet in completed_subnets:
            file.write(subnet + "\n")

def run_nmap(subnet):
    try:
        command = f"nmap -p 22,135 --open {subnet}"
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        completed_subnets.add(subnet)
        save_progress()
        return result.stdout.decode()
    except Exception as e:
        print(f"Error scanning {subnet}: {e}")
        return ""

def parse_nmap_output(output, csv_writer):
    current_ip = ""
    current_name = ""
    for line in output.split('\n'):
        if "Nmap scan report for" in line:
            if '(' in line and ')' in line:
                current_name, current_ip = re.findall(r'for (.+) \((.+)\)', line)[0]
            else:
                current_name = ""
                current_ip = line.split()[-1]
        elif "/tcp" in line and "open" in line:
            port, state, service = re.findall(r'(\d+/\w+)\s+(\w+)\s+(\w+)', line)[0]
            csv_writer.writerow([current_ip, current_name, port, state, service])

def run_nmap_on_subnets(subnets, csv_writer):
    with concurrent.futures.ThreadPoolExecutor(max_workers=70) as executor:
        future_to_subnet = {executor.submit(run_nmap, subnet): subnet for subnet in subnets}
        for future in concurrent.futures.as_completed(future_to_subnet):
            subnet = future_to_subnet[future]
            try:
                output = future.result()
                parse_nmap_output(output, csv_writer)
            except Exception as e:
                print(f"Error processing subnet {subnet}: {e}")

def read_subnets(file_name):
    with open(file_name, 'r') as file:
        return [line.strip() for line in file]


def get_ssh_hosts_from_csv(csv_file_path):
    ssh_hosts = []
    with open(csv_file_path, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            if row['Port'] == '22/tcp' and row['State'] == 'open':
                ssh_hosts.append((row['Device IP'], row['Device Name']))  # Tuple with IP and Name
    return ssh_hosts

credentials = [('svc-gnssolarwinds', 'Th1nkOutSiDe7h3B0x#'), ('GNSAdmin', 'd3RuC3$3tR0F123')]

# Path to your CSV file with Nmap scan results
CSV_FILE_PATH = 'scan_results.csv'

# Mapping of Netmiko detected device types to commands and Ansible modules
device_type_mapping = {
    'cisco_aci': ('show controller capacity detail', 'cisco.aci.aci'),
    'cisco_asa': ('show version', 'cisco.asa.asa'),
    'cisco_ios': ('show switch; show version; show inventory', 'cisco.ios.ios'),
    'cisco_xe': ('show switch; show version; show inventory', 'cisco.ios.ios'),
    'cisco_xr': ('show version', 'cisco.iosxr.iosxr'),
    'cisco_wlc': ('show sysinfo', 'cisco.ios.ios'),
    'cisco_WLC': ('show version', 'cisco.ios.ios'),
    'cisco_nxos': ('show version', 'cisco.nxos.nxos'),
    'cisco_viptela': ('show hardware inventory Chassis serial-number; show system status', 'cisco.viptela.viptela'),
    'netscaler': ('show hardware; show version; show ns hostname', 'netscaler_command_set'),
    'brocade_ironware': ('show version', 'community.brocade.ironware'),
    'fortinet': ('get system status', 'fortinet.fortios.fortios'),
    'hp_procurve': ('show system information' , 'ansible.netcommon.cli_command'),
    'frr': ('show version', 'frr.frr.frr'),
    'huawei': ('display version', 'community.h3c.h3c'),  # Test compatibility for H3C
    'paloalto_panos': ('show system info', 'paloaltonetworks.panos.panos'),
    'vyos': ('show version', 'vyos.vyos.vyos'),
    # Placeholders for vendors requiring testing or custom development:
    'generic_termserver': ('show version', 'Raw'),  # For Broadcom, HPE, etc.
    'ubnt_unms': ('show sysinfo', 'community.ubnt.unifi'),  # Might require custom development
    # Additional entries based on image and clarifications:
    'cisco_asa_compatible': ('show version', 'cisco.asa.asa'),  # For Tandberg ASA (test compatibility)
    'generic_termserver_hpe': ('show version', 'Raw')  # For HPE (test compatibility)
}
# Regular expressions for various device types
regex_patterns = {
    'cisco_aci': {
        'model': r"Model\s+:\s+(\S+)",
        'serial_number': r"Serial Number\s+:\s+(\S+)",
        'version': r"Software\s+Version\s+:\s+(\S+)",
        'hostname': r"Host\s+Name\s+:\s+(\S+)"
    },
    'cisco_asa': {
        'model': r"Hardware: +ASA(\S+),",
        'serial_number': r"Serial Number: (\S+)",
        'version': r"Software Version (\S+)",
        'hostname': r"(\S+) up"
    },
    'cisco_ios': {
        'model': r"Model number\s+:\s+(\S+)",
        'serial_number': r"Processor board ID (\S+)",
        'version': r"Cisco IOS Software, .+ Version (\S+),",
        'hostname': r"(\S+) uptime is"
    },
    'cisco_xr': {
        'model': r"Cisco (\S+) \(revision",
        'serial_number': r"Processor board ID (\S+)",
        'version': r"Cisco IOS XR Software, Version ([\d\.()]+)",
        'hostname': r"(\S+)\s+uptime"
    },
    'netscaler': {
        'model': r"Platform:\s+([^,]+)",  # Matches "Platform: NetScaler Virtual Appliance NSSDX-15000-25G 450097"
        'serial_number': r"Serial no:\s+(\S+)",  # Matches "Serial no: KEZ27D864S"
        'version': r"NetScaler\s+(NS[\d.]+):\s+Build\s+([\d.]+)",  # Matches "NetScaler NS13.1: Build 49.15.nc"
        'hostname': r"Hostname:\s+(\S+)"  # Matches "Hostname:  DEFRIZVPXLB0103"
    },
    'cisco_xe': {
        'model': r"Model\s+Number\s+:\s+(\S+)",
        'serial_number': r"Processor board ID (\S+)",
        'version': r"Cisco IOS XE Software, Version (\S+)",
        'hostname': r"(\S+) uptime is"
    },
    'cisco_nxos': {
        "model": r"cisco Nexus(\d+ .+?) Chassis",
        "serial_number": r"Processor Board ID (\S+)",
        "nxos_version": r"NXOS: version (\S+)",
        "hostname": r"Device name: (\S+)"
    },
    'hp_procurve': {
        'model': r"Software revision\s+:\s+([^\s]+)",  # Assuming model can be inferred from software revision
        'serial_number': r"Serial Number\s+:\s+(\S+)",
        'version': r"Software revision\s+:\s+(\S+)",
        'hostname': r"System Name\s+:\s+(\S+)",
    },
    'cisco_viptela': {
        'model': r"Model name:\s+(\S+)",  # Adjusted to match "Model name: vedge-2000"
        'serial_number': r"Chassis\s+0\s+(\S+)",  # To extract from "Chassis 0 26OE1312250045M"
        'version': r"Version: (\S+)",  # To extract from "Version: 20.6.5.2"
        'uptime': r"System uptime:\s+(.*)"  # To extract from "System uptime: 68 days 20 hrs 05 min 54 sec"
    },
    'brocade_ironware': {
        'model': r"IronWare Model\s+:\s+(\S+)",
        'serial_number': r"Serial Number\s+:\s+(\S+)",
        'version': r"IronWare Version ([\d\.]+)",
        'hostname': r"(\S+)\s+uptime"
    },
    'fortinet': {
        'model': r"Version: (\S+)",
        'serial_number': r"Serial-Number: (\S+)",
        'version': r"Version: FortiGate-\d+\w+\s+v([\d\.]+)",
        'hostname': r"Hostname: (\S+)"
    },
    'frr': {
        'model': r"Model\s+:\s+(\S+)",
        'serial_number': r"Serial Number\s+:\s+(\S+)",
        'version': r"FRRouting Version ([\d\.]+)",
        'hostname': r"(\S+)\s+uptime"
    },
    'huawei': {
        'model': r"Model\s+:\s+(\S+)",
        'serial_number': r"Serial Number\s+:\s+(\S+)",
        'version': r"Huawei Versatile Routing Platform Software Version ([\d\.]+)",
        'hostname': r"(\S+)\s+uptime"
    },
    'paloalto_panos': {
        'model': r"model: ([\S ]+)",
        'serial_number': r"serial: (\S+)",
        'version': r"sw-version: ([\S\-\.]+)",
        'hostname': r"hostname: (\S+)"
    },
    'vyos': {
        'model': r"Model\s+:\s+(\S+)",
        'serial_number': r"Serial Number\s+:\s+(\S+)",
        'version': r"VyOS Version ([\d\.]+)",
        'hostname': r"(\S+)\s+uptime"
    },
    'cisco_wlc': {
        'model': r"Product Name\s+:\s+(.+)",
        'serial_number': r"System Serial Number\s+:\s+(\S+)",
        'version': r"Product Version\s+:\s+([\d\.]+)",
        'hostname': r"System Name\s+:\s+(\S+)"
    },
    'cisco_WLC': {
        'model': r"cisco\s+(\S+)\s+\(.*?\)\s+processor",
        'serial_number': r"Processor board ID\s+(\S+)",
        'version': r"Cisco IOS XE Software, Version\s+([\d.]+)",
        'hostname': r"^(.*?)\s+uptime is"
    },
    # Add other device types and their regex patterns here
    # ...
}

# Function to extract device information based on device type
def extract_device_info(device_type, output):
    # device_type is already an argument, no need to extract it from 'device'
    patterns = regex_patterns.get(device_type, {})
    info = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, output)
        info[key] = match.group(1) if match else "Unknown"
    return info


def extract_from_output(output, pattern):
    match = re.search(pattern, output)
    return match.group(1) if match else "Unknown"

def parse_show_inventory_for_stacks(output):
    serial_numbers = []
    # Exclude entries with "Slot", "Power", or "Fan" in the NAME field.
    regex_pattern = r"NAME: \"([^\"]*Switch[^\"]*)\", DESCR: [^\n]+\nPID: [^\n]+, VID: [^\n]+, SN: (\S+)"
    
    matches = re.finditer(regex_pattern, output, re.MULTILINE)

    for match in matches:
        hostname_like, serial_num = match.groups()
        # Check if the entry should be excluded based on the hostname_like content
        if any(exclude_word in hostname_like for exclude_word in ["Slot", "Power", "Fan"]):
            continue  # Skip this entry
        # Directly add serial numbers to the list
        serial_numbers.append(serial_num)

    return serial_numbers




# Modify the run_ssh_command function with proper indentation and fixes
async def run_ssh_command(host_info, credentials):
    host_ip, host_name = host_info
    all_device_info = []  # Initialize outside the loop to collect info from all attempts
    successful_connection = False  # Flag to track successful connection
    for username, password in credentials:
        try:
            remote_device = {
                'device_type': 'autodetect',
                'host': host_ip,
                'username': username,
                'password': password,
                'timeout': 8
            }
            guesser = SSHDetect(**remote_device)
            best_match = guesser.autodetect()
            if not best_match:
                print(f"No device match for {host_ip} with {username}.")
                continue  # Skip to the next credential set if no match found 

            remote_device['device_type'] = best_match
            connection = ConnectHandler(**remote_device)
            successful_connection = True  # Set true on successful SSH connection
            if best_match in ['cisco_viptela', 'netscaler']:
                    commands = device_type_mapping[best_match][0].split(';')
                    output = [connection.send_command(command.strip()) for command in commands]
                    # Example logic for 'cisco_viptela' and 'netscaler' remains unchanged

            elif best_match in ['cisco_xe', 'cisco_ios']:
                connection.send_command("terminal length 0")
                # Execute commands to gather necessary information
                commands_to_execute = device_type_mapping[best_match][0].split(';')
                command_outputs = {command.strip(): connection.send_command(command.strip()) for command in commands_to_execute}

                # Extract version info from 'show version'
                version_info = extract_device_info(best_match, command_outputs['show version'])

                # Determine if the device is part of a stack
                if 'show switch' in command_outputs:
                    switch_info = command_outputs['show switch']
                    # Logic to determine stack presence and handle accordingly
                    is_stack = "Switch/Stack Mac Address" in switch_info
                else:
                    is_stack = False
                
                # Handle inventory and stack logic based on presence of a stack
                if is_stack:
                    # Parse for stack configurations if it's a stack
                    inventory_info = parse_show_inventory_for_stacks(command_outputs['show inventory'])
                    for serial_number in inventory_info:
                        all_device_info.append({
                            'host_name': host_name,  # This remains the device's hostname
                            'host_ip': host_ip,
                            'device_type': best_match,
                            'model': version_info.get('model', 'Unknown'),
                            'version': version_info.get('version', 'Unknown'),
                            'serial_number': serial_number,  # Serial number from 'show inventory'
                            'hostname': version_info.get('hostname', 'Unknown'),  # Include hostname-like identifier
                            'credentials': f'{username}/{password}'
                        })
                else:
                    # Non-stack configuration: All info from 'show version'
                    all_device_info.append({
                        'host_name': host_name,
                        'host_ip': host_ip,
                        'device_type': best_match,
                        'model': version_info.get('model', 'Unknown'),
                        'version': version_info.get('version', 'Unknown'),
                        'serial_number': version_info.get('serial_number', 'Unknown'),  # Serial number from 'show version'
                        'hostname': version_info.get('hostname', 'Unknown'),
                        'credentials': f'{username}/{password}'
                    })

                # Handle the 'cisco_xe' case
                if best_match == 'cisco_xe':
                    inventory_output = connection.send_command("show inventory")
                    if "C9800" in inventory_output:
                        best_match = 'cisco_WLC'
                        version_output = connection.send_command("show version")
                        # Fetch WLC details and append
                        wlc_device_info = extract_device_info('cisco_WLC', version_output)
                        all_device_info.append({
                        'Device Name': host_name,  # Assuming the host name represents the device name
                        'Device IP': host_ip,
                        'Detected Type': 'WLC',
                        'Model': wlc_device_info.get('model', 'Unknown'),
                        'Version': wlc_device_info.get('version', 'Unknown'),
                        'Serial Number': wlc_device_info.get('serial_number', 'Unknown'),
                        'Hostname': host_name,
                        'Credentials': f'{username}/{password}'
                    })
                        # Fetch AP details
                        ap_output = connection.send_command("show ap config general | include Cisco AP Name |IP Address                                      :|AP Serial Number |Software Version|AP Model |Software Version")
                        ap_details = process_ap_summary_output(ap_output, host_name, host_ip, best_match, username, password)
                        # Append AP details
                        all_device_info.extend(ap_details)


            # Assuming best_match identifies the device as a Cisco WLC
            elif best_match == 'cisco_wlc':
                    # Fetch controller information
                    version_output = connection.send_command("show sysinfo")
                    inventory_output = connection.send_command("show inventory")

                    # Extract version and hostname from 'show sysinfo'
                    controller_info = {
                        'version': re.search(r'Product Version\.*\s+([\S ]+)', version_output).group(1).strip(),
                        'hostname': re.search(r'System Name\.*\s+([\S ]+)', version_output).group(1).strip()
                    }

                    # Extract model and serial number from 'show inventory'
                    inventory_match = re.search(r'NAME: "Chassis".*?DESCR: "([\S ]+).*?PID: (\S+).*?SN: (\S+)', inventory_output, re.DOTALL)
                    if inventory_match:
                        controller_info['description'] = inventory_match.group(1).strip()
                        controller_info['model'] = inventory_match.group(2).strip()
                        controller_info['serial_number'] = inventory_match.group(3).strip()

                    # Append the controller information to all_device_info list
                    all_device_info.append({
                        'host_name': host_name,
                        'host_ip': host_ip,
                        'device_type': best_match,
                        'model': controller_info.get('model', 'Unknown'),
                        'version': controller_info.get('version', 'Unknown'),
                        'serial_number': controller_info.get('serial_number', 'Unknown'),
                        'hostname': controller_info.get('hostname', 'Unknown'),
                        'credentials': f'{username}/{password}'
                    })

                    # New block to fetch and process AP details
                    ap_summary_output = connection.send_command("show ap summary")
                    ap_inventory_output = connection.send_command("show ap inventory all")
                    ap_summary_details = parse_ap_summary(ap_summary_output)
                    ap_inventory_details = parse_ap_inventory(ap_inventory_output)
                    # Merge AP details based on AP Name
                    merged_ap_details = merge_ap_details(ap_summary_details, ap_inventory_details, host_name, host_ip, best_match, username, password)
                    # Extend all_device_info with merged AP details
                    all_device_info.extend(merged_ap_details)
            # If autodetect fails, try identifying as Netscaler
            elif not best_match:
                # Send Netscaler-specific commands
                commands = device_type_mapping['netscaler'][0].split(';')
                command_outputs = {command: connection.send_command(command.strip()) for command in commands}

                # Extract device information using regex patterns for Netscaler
                model = extract_from_output(command_outputs['show hardware'], regex_patterns['netscaler']['model'])
                serial_number = extract_from_output(command_outputs['show hardware'], regex_patterns['netscaler']['serial_number'])
                version = extract_from_output(command_outputs['show version'], regex_patterns['netscaler']['version'])
                hostname = extract_from_output(command_outputs.get('show ns hostname', ''), regex_patterns['netscaler']['hostname'])

                # Append Netscaler device information
                all_device_info.append({
                    'host_name': host_name,
                    'host_ip': host_ip,
                    'device_type': 'netscaler',
                    'model': model,
                    'version': version,
                    'serial_number': serial_number,
                    'hostname': hostname,
                    'credentials': f'{username}/{password}'
                })
            else:
                    command = device_type_mapping.get(best_match, ('Unknown Command',))[0]
                    output = connection.send_command(command)
                    device_info = extract_device_info(best_match, output)
                    all_device_info.append({
                        'host_name': host_name,
                        'host_ip': host_ip,
                        'device_type': best_match,
                        'model': device_info.get('model', 'Unknown'),
                        'version': device_info.get('version', 'Unknown'),
                        'serial_number': device_info.get('serial_number', 'Unknown'),
                        'hostname': device_info.get('hostname', 'Unknown'),
                        'credentials': f'{username}/{password}'
                    })

            connection.disconnect()
            break 
        except Exception as e:
            print(f"Error for host {host_ip} with credentials {username}: {e}")
            successful_connection = False  # Reset flag if an error occurs

    if not all_device_info:
        # If all credentials fail, return a 'Failed' status
        return [{
            'host_name': host_name,
            'host_ip': host_ip,
            'device_type': 'Failed',
            'model': 'Unknown',
            'version': 'Unknown',
            'serial_number': 'Unknown',
            'hostname': 'Unknown',
            'credentials': 'All credentials failed'
        }]
    else:
        return all_device_info
    
def parse_ap_summary(output):
    summary_regex = r"(?P<ap_name>\S+)\s+\d+\s+(?P<ap_model>\S+)\s+[a-fA-F0-9:]+\s+\S+.*?\s+(?P<ip_address>[\d\.]+)"
    ap_summary = []
    for match in re.finditer(summary_regex, output, re.DOTALL):
        ap_summary.append({
            "Device Name": match.group("ap_name"),
            "Device IP": match.group("ip_address"),
            "Model": match.group("ap_model"),
            "Detected Type": "AP",
            "Version": "N/A",  # Assuming version isn't available in summary
            "Serial Number": "Unknown",  # To be filled in from inventory data
            "Hostname": match.group("ap_name"),  # Assuming AP Name can serve as Hostname
            "Credentials": "N/A"  # Assuming credentials aren't applicable here
        })
    return ap_summary

def parse_ap_inventory(output):
    inventory_regex = r"Inventory for (?P<ap_name>\S+).*?PID:\s+\S+,\s+VID:\s+\S+,\s+SN:\s+(?P<serial_number>\S+)"
    ap_inventory = {}
    for match in re.finditer(inventory_regex, output, re.DOTALL):
        ap_inventory[match.group("ap_name")] = {
            "Serial Number": match.group("serial_number")
        }
    return ap_inventory
def merge_ap_details(summary, inventory, host_name, wlc_ip, best_match, username, password):
    merged_details = []
    for details in summary:
        ap_name = details["Device Name"]
        ap_ip = details["Device IP"]
        ap_serial = inventory.get(ap_name, {}).get("Serial Number", "Unknown")
        
        ap_details = {
            "host_name": host_name,
            "host_ip": ap_ip,
            "device_type": "cisco_ap",
            "model": details["Model"],
            "version": "N/A",
            "serial_number": ap_serial,
            "hostname": ap_name,
            "credentials": f"{username}/{password}"
        }
        merged_details.append(ap_details)
    return merged_details
def process_ap_summary_output(ap_output, host_name, host_ip, best_match, username, password):
    ap_details_list = []

    # Regex pattern to capture necessary details from the command output
    ap_info_pattern = re.compile(
        r"Cisco AP Name\s+:\s+(?P<hostname>[^\n]+)\n"
        r"IP Address\s+:\s+(?P<Device_IP>[^\n]+)\n"
        r"Software Version\s+:\s+(?P<version>[^\n]+)\n"
        r"AP Model\s+:\s+(?P<model>[^\n]+)\n"
        r"AP Serial Number\s+:\s+(?P<serial_number>[^\n]+)",
        re.DOTALL
    )
    
    # Find all matches and append them to the ap_details_list
    for match in re.finditer(ap_info_pattern, ap_output):
        ap_info = match.groupdict()
        # Adjust keys to match the specified format and include additional info
        adjusted_ap_info = {
            "host_name": host_name,
            "host_ip": ap_info["Device_IP"],
            "device_type": best_match,  # Assuming 'best_match' reflects the AP's broader category or type
            "model": ap_info["model"],
            "version": ap_info["version"],
            "serial_number": ap_info["serial_number"],
            "hostname": ap_info["hostname"],  # Assuming the AP name is the hostname
            "credentials": f'{username}/{password}'  # Placeholder for credentials; adjust as necessary
        }
        ap_details_list.append(adjusted_ap_info)
    
    return ap_details_list
def write_ssh_results_to_csv(results, csv_file):
    with open(csv_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Device Name", "Device IP", "Detected Type", "Model", "Version", "Serial Number", "Hostname", "Credentials"])
        
        for result_list in results:  # Each item here is a list of dictionaries
            for device_info in result_list:  # Each item here is a dictionary
                writer.writerow([
                    device_info.get('host_name', ''), 
                    device_info.get('host_ip', ''), 
                    device_info.get('device_type', ''), 
                    device_info.get('model', ''), 
                    device_info.get('version', ''), 
                    device_info.get('serial_number', ''), 
                    device_info.get('hostname', ''), 
                    device_info.get('credentials', '')
                ])

# Main function to run SSH tasks
async def main(ssh_hosts, credentials):
    tasks = [run_ssh_command(host_info, credentials) for host_info in ssh_hosts]
    try:
        results = await asyncio.gather(*tasks)
        return {result['host_ip']: result for result in results}  # Convert list to dictionary
    except Exception as e:
        print(f"An error occurred: {e}")
        return {}

# Function to create Ansible inventory from results
def create_ansible_inventory_from_results(results, inventory_file):
    inventory = {'all': {'hosts': {}}}
    for result_list in results:  # Assuming results is a list of lists
        for result in result_list:  # Each result is a dictionary
            if isinstance(result, dict):  # Ensure result is a dictionary
                host_key = result.get('host_name', '') or result.get('host_ip', '')
                creds = result.get('credentials', '')
                if '/' in creds:
                    username, password = creds.split('/', 1)
                    ansible_ssh_pass = password
                    ansible_user = username
                else:
                    # Assuming the presence of an API key instead of username/password
                    ansible_ssh_pass = creds  # For devices using API keys, this might be repurposed
                    ansible_user = 'api_key'  # Placeholder, adjust as needed

                ansible_network_os = device_type_mapping.get(result.get('device_type'), (None, 'unknown'))[1]
                inventory['all']['hosts'][host_key] = {
                    'ansible_host': result.get('host_ip', ''),
                    'ansible_network_os': ansible_network_os,
                    'ansible_user': username,
                    'ansible_ssh_pass': password,
                    'ansible_become': True,
                    'ansible_become_method': 'enable',
                    'ansible_become_pass': password,
                    'device_type': result.get('device_type', 'unknown'),
                    'model': result.get('model', 'Unknown'),
                    'version': result.get('version', 'Unknown'),
                    'serial_number': result.get('serial_number', 'Unknown'),
                    'hostname': result.get('hostname', 'Unknown')
                }

    with open(inventory_file, 'w') as file:
        yaml.dump(inventory, file, default_flow_style=False)


# Function to run Ansible playbook
def run_ansible_playbook(playbook_path, inventory_path):
    try:
        process = subprocess.Popen(
            ["ansible-playbook", "-i", inventory_path, playbook_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )
        # Real-time output capture
        while True:
            output = process.stdout.readline()
            if process.poll() is not None and output == b'':
                break
            if output:
                print(output.strip().decode())
        return process.poll()
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while running the Ansible playbook: {e}")
        return e.returncode


async def main():
    start_time = time.time()
    load_progress()  # Assuming this function shows the progress

    # Initialize empty list for combined data
    combined_data = []

    # Fetch data from Meraki and vManage asynchronously
    meraki_data = await fetch_meraki_data()
    vmanage_data = await fetch_vmanage_data()

    # Prepare to write initial scan results to CSV
    csv_file_path = '/opt/dataGather/nmap/scan_results/scan_results.csv'
    with open(csv_file_path, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(['Device IP', 'Device Name', 'Port', 'State', 'Service'])

        # Process files containing subnet information
        #files = ["/runner/project/roles/nmap/files/10.0.0.0.txt", "/runner/project/roles/nmap/files/172.16.0.0.txt", "/runner/project/roles/nmap/files/192.168.0.0.txt"]
        files = ["/runner/project/roles/nmap/files/192.168.0.0.txt"]
        for file_name in files:
            subnets = read_subnets(file_name)
            run_nmap_on_subnets(subnets, csv_writer)

    # Perform SSH/Netmiko and Nmap Analysis
    credentials = [('svc-gnssolarwinds', 'Th1nkOutSiDe7h3B0x#'), ('GNSAdmin', 'd3RuC3$3tR0F123')]
    ssh_hosts = get_ssh_hosts_from_csv(csv_file_path)
    ssh_tasks = [run_ssh_command(host_info, credentials) for host_info in ssh_hosts]
    ssh_results = await asyncio.gather(*ssh_tasks)

    #network_device_csv_file = '/opt/Network_Automation/Python_Projects/nmap_integration/Ansible_Serial_Model_Validation/Inventory/network_device_info.csv'
    network_device_csv_file = '/opt/dataGather/nmap/network_device_info.csv'

    if ssh_results:
        # Write SSH results to the CSV file first
        write_ssh_results_to_csv(ssh_results, network_device_csv_file)

    # Append combined data from Meraki and vManage to the CSV file
    with open(network_device_csv_file, 'a', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        for data in (meraki_data + vmanage_data):
            csv_writer.writerow([data.get(field, '') for field in ["Device Name", "Device IP", "Detected Type", "Model", "Version", "Serial Number", "Hostname", "Credentials"]])

    # # Construct Ansible dynamic inventory from the updated CSV data
    # ansible_inventory_file = '/opt/Network_Automation/Python_Projects/nmap_integration/Ansible_Serial_Model_Validation/Inventory/network_device_info.yml'
    # create_ansible_inventory_from_results(ssh_results + meraki_data + vmanage_data, ansible_inventory_file)

    # # Run Ansible playbook
    # playbook_path = '/opt/Network_Automation/Python_Projects/nmap_integration/Ansible_Serial_Model_Validation/Ansible_Serial_Model_Validation_v1.yml'
    # inventory_path = ansible_inventory_file
    # return_code = run_ansible_playbook(playbook_path, inventory_path)
    # if return_code == 0:
    #     print("Ansible playbook executed successfully")
    # else:
    #     print(f"Ansible playbook execution failed with return code: {return_code}")
    
    end_time = time.time()
    print(f"Total run time: {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    asyncio.run(main())
