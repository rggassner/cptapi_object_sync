#!/usr/bin/python3
# -*- coding: utf-8 -*-
import smtplib
from email.mime.text import MIMEText
from email.utils import formatdate
import requests
import json
import urllib3
import datetime
import sys
from cptapi import Cptapi
from my_config import *
import ipaddress
import logging
import fcntl
import atexit
import signal
import os


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOCK_FILE = "/tmp/object_sync.lock"
lock_handle = None

#Logging
logger = logging.getLogger('my_logger')
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
file_handler = logging.FileHandler('object_sync.log')
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)
logger.addHandler(console_handler)
logger.addHandler(file_handler)


def acquire_lock():
    global lock_handle
    lock_handle = open(LOCK_FILE, "w")
    try:
        fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        logger.error("Another instance is already running. Exiting.")
        sys.exit(1)
    # Register cleanup on normal exit
    atexit.register(release_lock)
    # Register cleanup on SIGINT/SIGTERM
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    return lock_handle

def release_lock():
    global lock_handle
    if lock_handle:
        try:
            fcntl.flock(lock_handle, fcntl.LOCK_UN)
            lock_handle.close()
            if os.path.exists(LOCK_FILE):
                os.remove(LOCK_FILE)
            logger.debug("Lock released and file removed.")
        except Exception as e:
            logger.error(f"Error releasing lock: {e}")
        lock_handle = None

def handle_signal(signum, frame):
    logger.warning(f"Received signal {signum}. Cleaning up lock and exiting.")
    release_lock()
    sys.exit(1)

#Custom Logging Handler to Capture Errors 
class ErrorBufferHandler(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.ERROR)
        self.errors = []

    def emit(self, record):
        msg = self.format(record)
        self.errors.append(msg)

def send_error_email(errors):
    """Send buffered errors by email if any occurred."""
    if not errors:
        return  # no errors, skip

    body = "\n".join(errors)
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = EMAIL_SUBJECT
    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(EMAIL_TO)
    msg["Date"] = formatdate(localtime=True)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=15) as server:
            #server.starttls()
            #server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        logger.info("Error report email sent successfully.")
    except Exception as e:
        logger.error(f"Failed to send error email: {e}")        

error_handler = ErrorBufferHandler()
error_handler.setFormatter(formatter)
logger.addHandler(error_handler)

DISALLOWED_NETWORKS = []
for net_str in RAW_DISALLOWED_NETWORKS:
    try:
        DISALLOWED_NETWORKS.append(ipaddress.ip_network(net_str))
    except ValueError as e:
        logger.error(f"Warning: Could not parse disallowed network '{net_str}': {e}")

def is_out_of_work_hours():
    now = datetime.datetime.now()
    current_hour = now.hour
    current_day_of_week = now.weekday()
    if current_day_of_week >= 5:
        return True
    else: 
        is_evening_slot = (current_hour >= 19 and current_hour <= 23)
        is_morning_slot = (current_hour >= 0 and current_hour <= 6)
        if is_evening_slot or is_morning_slot:
            return True
        else:
            return False

def fetch_json_from_insecure_url(url, username, password):
    try:
        response = requests.get(url, auth=(username, password), verify=False)
        response.raise_for_status()
        json_data = response.json()
        return json_data
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error occurred: {http_err} - Status Code: {response.status_code}")
        logger.error(f"Response Text: {response.text}")
    except requests.exceptions.ConnectionError as conn_err:
        logger.error(f"Connection error occurred: {conn_err}")
    except requests.exceptions.Timeout as timeout_err:
        logger.error(f"Timeout error occurred: {timeout_err}")
    except requests.exceptions.RequestException as req_err:
        logger.error(f"An unexpected error occurred: {req_err}")
    except json.JSONDecodeError as json_err:
        logger.error(f"Error decoding JSON: {json_err}")
        logger.error(f"Response content was: {response.text}")
    return None


def is_allowed(ip_or_network_obj) -> bool:
    if ip_or_network_obj is False:
        # If the input was invalid, it cannot be considered "allowed"
        return False

    for disallowed_net in DISALLOWED_NETWORKS:
        # Ensure we are comparing compatible IP versions (IPv4 with IPv4, IPv6 with IPv6)
        if ip_or_network_obj.version != disallowed_net.version:
            continue # Skip comparison if versions don't match

        if isinstance(ip_or_network_obj, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            # If it's an IP address, check if it's contained within the disallowed network
            if ip_or_network_obj in disallowed_net:
                return False  # It's disallowed
        elif isinstance(ip_or_network_obj, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            # If it's an IP network, check if it overlaps with the disallowed network
            if ip_or_network_obj.overlaps(disallowed_net):
                return False  # It's disallowed
    return True  # If no overlap/containment found, it's allowed


def parse_ip_or_network(ip_string: str):
    try:
        return ipaddress.ip_address(ip_string)
    except ValueError:
        try:
            return ipaddress.ip_network(ip_string, strict=False)
        except ValueError:
            return None

def sync_external_group_to_firewall(source_group,domain,object_internal_names):
    if 'group_content' in source_group:
        if len(source_group['group_content']) == 0:
            logger.warning('Group {} is empty'.format(source_group['group_name']))
            return True
        if not domain.group_exists(source_group['group_name']):
            logger.error('Creating group {} since it was not found in the firewall.'.format(source_group['group_name']))
            domain.add_group(name=source_group['group_name'],color=OBJECT_COLOR)
        for source_object in source_group['group_content']:
            description = source_object.get('description', '')
            object_value = parse_ip_or_network(source_object['object_value'])
            if object_value:
                #Address
                if isinstance(object_value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                    if is_allowed(object_value):
                        previous=domain.show_session()['changes'] 
                        object_name=domain.get_host_name(str(object_value))
                        domain.add_host(name=object_name,ip_address=str(object_value),comments=description,tags=['SOC'])
                        if previous<domain.show_session()['changes']:
                            logger.error('Creating host {}.'.format(object_name))
                            previous=domain.show_session()['changes']
                        domain.set_group(name=source_group['group_name'],add=object_name)
                        if previous<domain.show_session()['changes']:
                            logger.error('Adding host {} to group {}.'.format(object_name,source_group['group_name']))
                            previous=domain.show_session()['changes']
                        object_internal_names.append(object_name)
                        logger.info('Creating host {} {} {} {}'.format(object_value,type(object_value),description,object_name))
                    else:
                        logger.error('Address {} {} {} not allowed.'.format(object_value,type(object_value),description))
                #Network
                elif isinstance(object_value, ipaddress.IPv4Network):
                    if object_value.prefixlen >= MIN_V4_MASK_LENGTH:
                        if is_allowed(object_value):
                            previous=domain.show_session()['changes'] 
                            object_color = domain.get_object_color(object_value)
                            object_name=domain.get_network_name(subnet=str(object_value.network_address),mask_length=str(object_value.prefixlen))
                            domain.add_network(name=object_name,subnet=str(object_value.network_address),mask_length=str(object_value.prefixlen),color=object_color,comments=description,tags=['SOC'])
                            if previous<domain.show_session()['changes']:
                                logger.error('Creating network {}.'.format(object_name))
                                previous=domain.show_session()['changes']
                            domain.set_group(name=source_group['group_name'],add=object_name)
                            if previous<domain.show_session()['changes']:
                                logger.error('Adding network {} to group {}.'.format(object_name,source_group['group_name']))
                                previous=domain.show_session()['changes']
                            object_internal_names.append(object_name)
                            logger.info('V4 Network {} {} {} {} {}'.format(object_value,type(object_value),description, str(object_value.prefixlen),object_name))
                        else:
                            logger.error('V4 Network {} {} {} {} Not allowed'.format(object_value,type(object_value),description, object_value.prefixlen))
                    else:
                        logger.error('V4 Mask is too small {} {} {} {}'.format(object_value,type(object_value),description, object_value.prefixlen))
                elif isinstance(object_value, ipaddress.IPv6Network):
                    if object_value.prefixlen >= MIN_V6_MASK_LENGTH:
                        if is_allowed(object_value):
                            previous=domain.show_session()['changes'] 
                            object_color = domain.get_object_color(object_value)
                            object_name=domain.get_network_name(subnet=str(object_value.network_address),mask_length=str(object_value.prefixlen))
                            domain.add_network(name=object_name,subnet=str(object_value.network_address),mask_length=str(object_value.prefixlen),color=object_color,comments=description,tags=['SOC'])
                            if previous<domain.show_session()['changes']:
                                logger.error('Creating network {}.'.format(object_name))
                                previous=domain.show_session()['changes']
                            domain.set_group(name=source_group['group_name'],add=object_name)
                            if previous<domain.show_session()['changes']:
                                logger.error('Adding network {} to group {}.'.format(object_name,source_group['group_name']))
                                previous=domain.show_session()['changes']
                            object_internal_names.append(object_name)
                            logger.info('V6 Network {} {} {} {} {}'.format(object_value,type(object_value),description, object_value.prefixlen,object_name))
                        else:
                            logger.error('V6 Network {} {} {} {} not allowed'.format(object_value,type(object_value),description, object_value.prefixlen))
                    else:
                        logger.error('V6 Mask is too small {} {} {} {}'.format(object_value,type(object_value),description, object_value.prefixlen))
            else:
                logger.error('{} not an ip address or network'.format(source_object['object_value']))
    else:
        logger.error('group_content not found in source_group')

def sync_firewall_group_to_external(source_group,domain,object_internal_names):
    group=domain.show_group(source_group['group_name'])
    if 'members' in group:
        for member in group['members']:
            logger.info('Dealing with host {} '.format(json.dumps(member, indent=4)))
            if member['name'] not in object_internal_names:
                logger.error('Object {} not found in external data. Removing from group {}.'.format(member['name'],source_group['group_name']))
                result=domain.set_group(name=source_group['group_name'],remove=member['name'])
                logger.error('Result {}'.format(json.dumps(result, indent=4)))
            else:
                logger.info('Object {} found in external data.'.format(member['name']))
        return True
    else:
        logger.warning('A group in the firewall is empty!')

def sync_external_data_to_firewall(external_data,domain):
    for source_group in external_data:
        if RESTRICTED_GROUPS and source_group['group_name'] not in ALLOWED_SYNC_GROUPS:
            logger.error('Using a restricted creation policy, and group {} is not allowed'.format(source_group['group_name']))
        else:
            object_internal_names=[]
            logger.info('Working with group {}'.format(json.dumps(source_group, indent=4)))
            logger.info('Syncing group {} from site ====> firewall.'.format(source_group['group_name']))
            sync_external_group_to_firewall(source_group,domain,object_internal_names)
            logger.info('Syncing group {} from firewall ====> site.'.format(source_group['group_name']))
            sync_firewall_group_to_external(source_group,domain,object_internal_names)

if __name__ == "__main__":
    lock_handle = acquire_lock() 
    try:
        if not is_out_of_work_hours() and NON_WORKING_HOURS_ONLY:
            logger.info("Sorry, i am not allowed to run on working hours.")
            sys.exit()
        external_data = fetch_json_from_insecure_url(target_url, auth_username, auth_password)
        domain=Cptapi(user,password,url,domain_name,api_wait_time=api_wait_time,read_only=False,page_size=page_size,publish_wait_time=publish_wait_time)
        domain.verbose=False
        if external_data:
            logger.info('Syncing external source to firewall.')
            logger.info('External data retrieved {} '.format(json.dumps(external_data, indent=4)))
            sync_external_data_to_firewall(external_data,domain)
        else:
            logger.error("\nFailed to fetch JSON data.")
            logger.error("Please check the URL, credentials, and ensure the server is accessible.")
        session=domain.show_session()
        if session['changes'] != 0:
            domain.publish()
            domain.reassign_all()
            domain.reinstall_all_policies()
        domain.logout()
    finally:
        release_lock()
        if ENABLE_EMAIL_REPORTING:
            send_error_email(error_handler.errors)
