#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Firewall Group Synchronization and Automation Toolkit.

This script automates the synchronization of network objects and groups between
external data sources and a Check Point firewall management domain using the Cptapi
interface. It handles both directions of synchronization:

    1. External -> Firewall (creation and update of hosts, networks, and groups)
    2. Firewall -> External (removal of orphaned objects not present in external data)

Key Features:
    • Authentication to external APIs using HTTP REST requests.
    • Parsing and validation of IP addresses and networks (IPv4 and IPv6).
    • Enforcement of allowed and disallowed network ranges.
    • Automated creation of hosts and networks in the firewall, including tags,
      comments, and color normalization.
    • Safe synchronization of group contents and handling of restricted or missing objects.
    • Lock mechanism to prevent concurrent script executions.
    • Graceful signal handling for cleanup on termination (SIGINT/SIGTERM).
    • Time-based control to prevent modifications outside working hours.
    • Error aggregation and email reporting using SMTP.
    • Embedded logging with detailed diagnostic information.
    • Utility functions for data transformation, group normalization, padding, and
      integration with external data formats.

Technical Highlights:
    • Uses `fcntl` for file-based locking.
    • Uses `requests` for REST API communication.
    • Uses `ipaddress` module for type-safe network parsing and validation.
    • Prevents duplicate creations by tracking internal object names.
    • Supports dynamic group name prefixing, dummy entries, and missing group insertion.
    • Safely disables SSL certificate warnings during API calls (intended for testing).

Intended Use Cases:
    • SOC automation for firewall object provisioning.
    • Synchronizing CMDB/IPAM data with firewall inventories.
    • Ensuring policy consistency across multi-domain environments.
    • Scheduled synchronization jobs with email-based error reporting.
    • Auditing orphaned or unauthorized IP objects in firewall groups.

Note:
    SSL certificate verification is disabled (verify=False) in HTTP requests and should
    only be used in trusted environments. Replace with secure certificate handling
    when deploying to production.

"""
import smtplib
from email.mime.text import MIMEText
from email.utils import formatdate
import json
import os
import datetime
import sys
import ipaddress
import logging
import fcntl
import atexit
import signal
import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning
from cptapi import Cptapi
from my_config import * #pylint: disable=wildcard-import


urllib3.disable_warnings(InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOCK_FILE = "/tmp/object_sync.lock"
LOCK_HANDLE = None

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

AUTH_PAYLOAD = {
    "username": auth_username,
    "password": auth_password
}


class DataRetrievalError(Exception):
    """Custom exception for data retrieval errors."""
    pass

class AuthenticationError(Exception):
    """Custom exception for authentication errors."""
    pass

def authenticate_and_retrieve_data():
    """
    Authenticates with a remote API using a POST request and retrieves data via a subsequent GET request.

    Raises:
        AuthenticationError: If authentication fails.
        DataRetrievalError: If data retrieval fails.
    """

    # Step 1: Authentication (POST request)
    logger.info("--- STEP 1: AUTHENTICATION (POST request) ---")
    try:
        login_response = requests.post(login_url, json=AUTH_PAYLOAD, verify=False)
        login_response.raise_for_status()  # Will raise an error for non-2xx status codes

        auth_data = login_response.json()

        if 'token' not in auth_data:
            error_message = "Authentication failed: 'token' not found in response."
            logger.error(error_message)
            logger.error("Full response: %s", auth_data)
            raise AuthenticationError(error_message)  # Raise an error

        auth_token = auth_data['token']
        logger.info("Authentication successful. Received token: %s...", auth_token[:20])

    except requests.exceptions.HTTPError as exception:
        error_message = f"HTTP Error during login (Step 1): {exception}"
        logger.error(error_message)
        logger.error("Response content: %s", login_response.text)
        raise AuthenticationError(error_message)  # Raise an error

    except requests.exceptions.RequestException as exception:
        error_message = f"An error occurred during login (Step 1): {exception}"
        logger.error(error_message)
        raise AuthenticationError(error_message)  # Raise an error

    except json.JSONDecodeError:
        error_message = f"Failed to decode JSON response from login endpoint. Response: {login_response.text}"
        logger.error(error_message)
        raise AuthenticationError(error_message)  # Raise an error

    # Step 2: Data Retrieval (GET request)
    logger.info("--- STEP 2: DATA RETRIEVAL (GET request) ---")
    try:
        headers = {'Authorization': f'Bearer {auth_token}'}
        data_response = requests.get(target_url, headers=headers, verify=False)
        data_response.raise_for_status()  # Will raise an error for non-2xx status codes

        logger.info("Data retrieval successful (Status 200 OK).")
        try:
            retrieved_data = data_response.json()
            logger.info("\nRetrieved Data Preview (JSON):")
            logger.info("%s", json.dumps(retrieved_data, indent=4, ensure_ascii=False))
            return retrieved_data  # Only return data if retrieval was successful
        except json.JSONDecodeError:
            error_message = f"Failed to decode JSON response during data retrieval. Response: {data_response.text}"
            logger.error("\nRetrieved Data Preview (Raw Text):")
            logger.error("%s", data_response.text)
            raise DataRetrievalError(error_message)  # Raise an error

    except requests.exceptions.HTTPError as exception:
        error_message = f"HTTP Error during data retrieval (Step 2): {exception}"
        logger.error(error_message)
        logger.error("Response content: %s", data_response.text)
        raise DataRetrievalError(error_message)  # Raise an error

    except requests.exceptions.RequestException as exception:
        error_message = f"An error occurred during data retrieval (Step 2): {exception}"
        logger.error(error_message)
        raise DataRetrievalError(error_message)  # Raise an error


def acquire_lock():
    """
    Acquire an exclusive file-based lock to prevent multiple instances of the program from running.

    This function attempts to create and lock a lock file using `fcntl.flock()`
    with an exclusive, non-blocking lock. If the lock is already held by another
    running instance, it exits the program gracefully. On successful acquisition,
    it registers cleanup handlers to release the lock when the program exits or
    receives termination signals.

    Behavior:
        - Opens (or creates) the lock file for writing.
        - Attempts to acquire a non-blocking exclusive lock.
        - Registers `release_lock()` to be called automatically on program exit.
        - Hooks `SIGINT` and `SIGTERM` to ensure proper cleanup via `handle_signal()`.

    Returns:
        file object: The file handle representing the acquired lock.

    Exits:
        If another instance is detected (lock already held), logs the error
        and exits the program using `sys.exit(1)`.

    Side Effects:
        - Modifies the global `LOCK_HANDLE`.
        - Installs signal handlers.
        - Registers `release_lock()` with `atexit`.
        - Creates or truncates the lock file on disk.

    """
    global LOCK_HANDLE #pylint: disable=global-statement
    LOCK_HANDLE = open(LOCK_FILE, "w") #pylint: disable=consider-using-with,unspecified-encoding
    try:
        fcntl.flock(LOCK_HANDLE, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        logger.error("Another instance is already running. Exiting.")
        sys.exit(1)
    atexit.register(release_lock)
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    return LOCK_HANDLE


def release_lock():
    """
    Releases the file-based process lock and cleans up lock resources.

    This function unlocks and closes the lock file if currently held,
    removes the lock file from disk, and resets the global LOCK_HANDLE
    reference to None. It ensures that no stale lock file remains,
    preventing future false-positive lock detections.

    The function is safe to call multiple times, as it checks for the
    existence of an active lock handle before proceeding.

    Side Effects:
        - Releases the file lock using `fcntl.flock()`.
        - Closes the lock file handle.
        - Deletes the lock file from the filesystem, if present.
        - Logs success or error messages.
        - Sets `LOCK_HANDLE` to None.

    Exceptions:
        Any exceptions that occur during unlocking, closing, or file
        removal are caught and logged without being raised.

    """
    global LOCK_HANDLE #pylint: disable=global-statement
    if LOCK_HANDLE:
        try:
            fcntl.flock(LOCK_HANDLE, fcntl.LOCK_UN)
            LOCK_HANDLE.close()
            if os.path.exists(LOCK_FILE):
                os.remove(LOCK_FILE)
            logger.debug("Lock released and file removed.")
        except Exception as exception: #pylint: disable=broad-except
            logger.error("Error releasing lock: %s",exception)
        LOCK_HANDLE = None


def handle_signal(signum, _frame):
    """
    Signal handler to gracefully terminate the application.

    This function is triggered when the process receives termination signals
    (such as SIGINT or SIGTERM). It logs a warning, performs necessary cleanup
    by releasing any acquired lock, and then exits the program.

    Parameters:
        signum (int): The signal number that was received.
        _frame (frame object): The current stack frame (unused).

    Side Effects:
        - Logs a warning message.
        - Calls `release_lock()` to free lock resources.
        - Terminates the program with exit code 1.
    """
    logger.warning("Received signal %s. Cleaning up lock and exiting.",signum)
    release_lock()
    sys.exit(1)


class ErrorBufferHandler(logging.Handler):
    """
    A custom logging handler that captures error-level log messages into an in-memory list.

    This handler stores formatted log messages of level ERROR (or higher) in the `errors` list
    instead of sending them to standard logging outputs. It is useful for collecting errors
    during execution, such as for later processing, reporting, or sending via email.

    Attributes:
        errors (list[str]): A list that accumulates formatted error messages.

    Methods:
        emit(record): Formats and appends an ERROR-level log record to the `errors` list.
    """
    def __init__(self):
        super().__init__(level=logging.ERROR)
        self.errors = []

    def emit(self, record):
        msg = self.format(record)
        self.errors.append(msg)


def send_error_email(errors):
    """
    Send an error report email containing a list of error messages.

    This function takes a list of error strings, composes them into an email body,
    and sends the email using predefined SMTP settings. If no errors are provided,
    the function returns immediately without sending anything.

    The email includes:
        - Subject: Taken from EMAIL_SUBJECT
        - From: EMAIL_FROM
        - To: A comma-separated list from EMAIL_TO
        - Body: Each error message on a new line

    SMTP settings such as server address, port, sender, and recipient addresses
    are assumed to be defined globally.

    Args:
        errors (list[str]): A list of error message strings to include in the email body.

    Returns:
        None

    Logs:
        - Info log on successful email sending.
        - Error log if email sending fails or an exception occurs.
    """
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
    except Exception as exception: # pylint: disable=broad-except
        logger.error("Failed to send error email: %s",exception)


error_handler = ErrorBufferHandler()
error_handler.setFormatter(formatter)
logger.addHandler(error_handler)

DISALLOWED_NETWORKS = []
for net_str in RAW_DISALLOWED_NETWORKS:
    try:
        DISALLOWED_NETWORKS.append(ipaddress.ip_network(net_str))
    except ValueError as e:
        logger.error("Warning: Could not parse disallowed network '%s': %s",net_str,e)


def is_out_of_work_hours():
    """
    Determine whether the current time falls outside standard work hours.

    Standard work hours are defined as:
    - Weekdays (Monday to Friday), excluding weekends (Saturday and Sunday).
    - Working hours between 08:00 (8 AM) and 16:59 (4:59 PM).

    The function checks:
    - If today is Saturday (5) or Sunday (6), it's considered out of work hours.
    - If the current time is between 17:00 and 23:59 or between 00:00 and 07:59,
      it's also considered out of work hours.

    Returns:
        bool: True if the current time is outside defined work hours,
              False otherwise.
    """
    now = datetime.datetime.now()
    current_hour = now.hour
    current_day_of_week = now.weekday()
    if current_day_of_week >= 5:
        return True
    is_evening_slot = 17 <= current_hour <= 23
    is_morning_slot = 0 <= current_hour <= 7
    if is_evening_slot or is_morning_slot:
        return True
    return False


def fetch_json_from_insecure_url(request_url, user_name, request_password):
    """
    Fetch JSON data from an HTTP/HTTPS endpoint using basic authentication, without SSL
    certificate verification.

    This function sends a GET request to the specified `request_url` using the provided
    `user_name` and `request_password` for basic authentication. SSL verification is
    explicitly disabled (`verify=False`), making this suitable for testing against
    endpoints with self-signed or invalid certificates, but insecure for production use.

    If the request succeeds and valid JSON is returned, the parsed JSON object is returned.
    If any error occurs (HTTP, connection, timeout, JSON decoding, or other request-related
    exceptions), relevant details are logged and the function returns `None`.

    Parameters:
        request_url (str): The URL of the endpoint to request.
        user_name (str): The username for basic authentication.
        request_password (str): The password for basic authentication.

    Returns:
        dict or list or None: Parsed JSON data on success, or None if an error occurs.

    Notes:
        - SSL certificate verification is disabled. Avoid using this in production.
        - On failure, error details are logged and None is returned.

    Exceptions Handled:
        requests.exceptions.HTTPError
        requests.exceptions.ConnectionError
        requests.exceptions.Timeout
        requests.exceptions.RequestException
        json.JSONDecodeError
    """
    try:
        response = requests.get(request_url, auth=(user_name, request_password), verify=False)
        response.raise_for_status()
        json_data = response.json()
        return json_data
    except requests.exceptions.HTTPError as http_err:
        logger.error("HTTP error occurred: %s - Status Code: %s",http_err,response.status_code)
        logger.error("Response Text: %s",response.text)
    except requests.exceptions.ConnectionError as conn_err:
        logger.error("Connection error occurred: %s",conn_err)
    except requests.exceptions.Timeout as timeout_err:
        logger.error("Timeout error occurred: %s",timeout_err)
    except requests.exceptions.RequestException as req_err:
        logger.error("An unexpected error occurred: %s",req_err)
    except json.JSONDecodeError as json_err:
        logger.error("Error decoding JSON: %s",json_err)
        logger.error("Response content was: %s",response.text)
    return None


def is_allowed(ip_or_network_obj) -> bool:
    """
    Determine whether an IP address or network object is allowed based on disallowed ranges.

    This function checks if the given IP address or network object falls within or overlaps with
    any network specified in the `DISALLOWED_NETWORKS` list. It supports both IPv4 and IPv6
    address and network types.

    Logic:
        - Invalid or False inputs are immediately considered disallowed.
        - For IP address objects, it verifies whether the address is contained within
          any disallowed network.
        - For network objects, it checks whether the network overlaps with any disallowed network.
        - IP versions must match (e.g., IPv4 objects only compared with IPv4 networks).

    Parameters:
        ip_or_network_obj (ipaddress.IPv4Address | ipaddress.IPv6Address |
                           ipaddress.IPv4Network | ipaddress.IPv6Network | None):
            The IP address or network object to be evaluated.

    Returns:
        bool:
            - True if the IP or network is allowed (i.e., not contained within or overlapping
              any disallowed networks).
            - False if it is disallowed, invalid, or overlaps with disallowed ranges.

    Notes:
        - Uses the global `DISALLOWED_NETWORKS`, which is expected to be a list of
          `ipaddress.IPv4Network` or `ipaddress.IPv6Network` objects.
        - Ensures proper handling of IPv4 vs IPv6 version mismatches.

    """
    if ip_or_network_obj is False:
        return False
    for disallowed_net in DISALLOWED_NETWORKS:
        if ip_or_network_obj.version != disallowed_net.version:
            continue
        if isinstance(ip_or_network_obj, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            if ip_or_network_obj in disallowed_net:
                return False
        elif isinstance(ip_or_network_obj, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            if ip_or_network_obj.overlaps(disallowed_net):
                return False
    return True


def parse_ip_or_network(ip_string: str):
    """
    Parse a string into an IP address or network object.

    This function attempts to interpret the input string as either an IP address
    or an IP network (IPv4 or IPv6). It first tries to parse the string as an IP
    address. If that fails, it attempts to parse it as an IP network using
    non-strict mode (allowing host bits to be set). If both attempts fail, it
    returns None.

    Parameters:
        ip_string (str): The string representation of an IP address or network.

    Returns:
        ipaddress.IPv4Address | ipaddress.IPv6Address |
        ipaddress.IPv4Network | ipaddress.IPv6Network | None:
            - An appropriate IP address or network object if the string is valid.
            - None if the string is neither a valid address nor a valid network.

    Notes:
        - `strict=False` allows network parsing even if host bits are present.
        - Useful for handling user input where both IP formats may be allowed.
    """
    try:
        return ipaddress.ip_address(ip_string)
    except ValueError:
        try:
            return ipaddress.ip_network(ip_string, strict=False)
        except ValueError:
            return None


# pylint: disable=too-many-statements,too-many-branches,too-many-nested-blocks
def sync_external_group_to_firewall(source_group,int_domain,object_internal_names):
    """
    Synchronize an external group's contents to the firewall.

    This function ensures that all objects defined in the external group's
    `group_content` are properly created and added to the corresponding firewall
    group. It handles creation and synchronization of hosts and networks
    (IPv4 and IPv6), based on validation and allowed-policy rules.

    Parameters:
        source_group (dict): A dictionary representing the external group, containing:
                             - 'group_name': Name of the group.
                             - 'group_content': List of objects with 'object_value'
                                               and optional 'description'.
        int_domain (object): Object representing the firewall domain, providing methods:
                             * group_exists(name)
                             * add_group(name, color)
                             * get_host_name(ip)
                             * get_network_name(subnet, mask_length)
                             * add_host(...)
                             * add_network(...)
                             * set_group(name, add/remove)
                             * show_session()
        object_internal_names (list of str): List to store names of successfully
                                             synchronized firewall objects.

    Returns:
        bool: Always returns True after processing, except when early return occurs
              due to an empty group.

    Behavior:
        - Validates presence of 'group_content' in source_group.
        - If group is empty, logs a warning and returns.
        - Creates the group in the firewall if it does not exist.
        - Iterates over each object in 'group_content':
            * Parses and validates IP address or network.
            * Checks if the address or network is allowed based on policy.
            * Creates the object (host/network) in the firewall if necessary.
            * Adds the object to the firewall group.
            * Tracks created/added object names in object_internal_names.
        - Handles IPv4 and IPv6 addresses and networks with prefix validation.
        - Logs all actions, including errors, creations, and skips.

    Logging:
        - Logs detailed information on each action including object type,
          name, IP, description, prefix length, and addition to group.
        - Logs validation failures, disallowed objects, and malformed inputs.

    Notes:
        - Uses helper functions:
            * parse_ip_or_network(value) – to parse IP/network strings.
            * is_allowed(value) – to validate objects against allowed sync policies.
        - Relies on global settings:
            * MIN_V4_MASK_LENGTH, MIN_V6_MASK_LENGTH – minimum prefix rules.
            * OBJECT_COLOR – default color for newly created objects.
            * logger – for logging actions and errors.
    """
    if 'group_content' in source_group:
        if len(source_group['group_content']) == 0:
            logger.warning('Group %s is empty',source_group['group_name'])
            return True
        if not int_domain.group_exists(source_group['group_name']):
            logger.error(
                    'Creating group %s since it was not found in the firewall.',
                    source_group['group_name']
                    )
            int_domain.add_group(name=source_group['group_name'],color=OBJECT_COLOR)
        for source_object in source_group['group_content']:
            description = source_object.get('description', '')
            object_value = parse_ip_or_network(source_object['object_value'])
            if object_value:
                #Address
                if isinstance(object_value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                    if is_allowed(object_value):
                        previous=int_domain.show_session()['changes']
                        object_name=int_domain.get_host_name(str(object_value))
                        int_domain.add_host(
                                name=object_name,
                                ip_address=str(object_value),
                                comments=description,
                                tags=['SOC']
                                )
                        if previous<int_domain.show_session()['changes']:
                            logger.error('Creating host %s.',object_name)
                            previous=int_domain.show_session()['changes']
                        int_domain.set_group(name=source_group['group_name'],add=object_name)
                        if previous<int_domain.show_session()['changes']:
                            logger.error(
                                    'Adding host %s to group %s.',
                                    object_name,
                                    source_group['group_name']
                                    )
                            previous=int_domain.show_session()['changes']
                        object_internal_names.append(object_name)
                        logger.info(
                                'Creating host %s %s %s %s',
                                object_value,
                                type(object_value),
                                description,
                                object_name
                                )
                    else:
                        logger.error(
                                'Address %s %s %s not allowed.',
                                object_value,
                                type(object_value),
                                description
                                )
                #Network
                elif isinstance(object_value, ipaddress.IPv4Network):
                    if object_value.prefixlen >= MIN_V4_MASK_LENGTH:
                        if is_allowed(object_value):
                            previous=int_domain.show_session()['changes']
                            object_color = int_domain.get_object_color(object_value)
                            object_name=int_domain.get_network_name(
                                    subnet=str(object_value.network_address),
                                    mask_length=str(object_value.prefixlen)
                                    )
                            int_domain.add_network(
                                    name=object_name,
                                    subnet=str(object_value.network_address),
                                    mask_length=str(object_value.prefixlen),
                                    color=object_color,
                                    comments=description,
                                    tags=['SOC']
                                    )
                            if previous<int_domain.show_session()['changes']:
                                logger.error('Creating network %s.',object_name)
                                previous=int_domain.show_session()['changes']
                            int_domain.set_group(name=source_group['group_name'],add=object_name)
                            if previous<int_domain.show_session()['changes']:
                                logger.error(
                                        'Adding network %s to group %s.',
                                        object_name,
                                        source_group['group_name']
                                        )
                                previous=int_domain.show_session()['changes']
                            object_internal_names.append(object_name)
                            logger.info(
                                    'V4 Network %s %s %s %s %s',
                                    object_value,
                                    type(object_value),
                                    description,
                                    str(object_value.prefixlen),
                                    object_name
                                    )
                        else:
                            logger.error(
                                    'V4 Network %s %s %s %s Not allowed',
                                    object_value,
                                    type(object_value),
                                    description,
                                    object_value.prefixlen
                                    )
                    else:
                        logger.error(
                                'V4 Mask is too small %s %s %s %s',
                                object_value,
                                type(object_value),
                                description,
                                object_value.prefixlen
                                )
                elif isinstance(object_value, ipaddress.IPv6Network):
                    if object_value.prefixlen >= MIN_V6_MASK_LENGTH:
                        if is_allowed(object_value):
                            previous=int_domain.show_session()['changes']
                            object_color = int_domain.get_object_color(object_value)
                            object_name=int_domain.get_network_name(
                                    subnet=str(object_value.network_address),
                                    mask_length=str(object_value.prefixlen)
                                    )
                            int_domain.add_network(
                                    name=object_name,
                                    subnet=str(object_value.network_address),
                                    mask_length=str(object_value.prefixlen),
                                    color=object_color,
                                    comments=description,
                                    tags=['SOC']
                                    )
                            if previous<int_domain.show_session()['changes']:
                                logger.error('Creating network %s.',object_name)
                                previous=int_domain.show_session()['changes']
                            int_domain.set_group(name=source_group['group_name'],add=object_name)
                            if previous<int_domain.show_session()['changes']:
                                logger.error(
                                        'Adding network %s to group %s.',
                                        object_name,
                                        source_group['group_name']
                                        )
                                previous=int_domain.show_session()['changes']
                            object_internal_names.append(object_name)
                            logger.info(
                                    'V6 Network %s %s %s %s %s',
                                    object_value,
                                    type(object_value),
                                    description,
                                    object_value.prefixlen,
                                    object_name
                                    )
                        else:
                            logger.error(
                                    'V6 Network %s %s %s %s not allowed',
                                    object_value,
                                    type(object_value),
                                    description,
                                    object_value.prefixlen
                                    )
                    else:
                        logger.error(
                                'V6 Mask is too small %s %s %s %s',
                                object_value,
                                type(object_value),
                                description,
                                object_value.prefixlen
                                )
            else:
                logger.error('%s not an ip address or network',source_object['object_value'])
    else:
        logger.error('group_content not found in source_group')
    return True


def sync_firewall_group_to_external(source_group,int_domain,object_internal_names):
    """
    Synchronize members of a firewall group back to the external source.

    This function retrieves a group from the firewall and compares its members
    with a list of objects known to exist in the external data (`object_internal_names`).
    Any member present in the firewall group but missing from the external source
    is removed from the firewall group. The function logs detailed information
    during this process.

    Parameters:
        source_group (dict): A dictionary representing the external group,
                             containing at least the key 'group_name'.
        int_domain (object): An object providing access to firewall group
                             management methods, such as `show_group` and `set_group`.
        object_internal_names (list of str): A list of object names that are
                                             known to exist in the external data.

    Returns:
        bool:
            - True if the group exists in the firewall and synchronization actions
              were performed (even if no changes were needed).
            - False if the firewall group has no members or is empty.

    Behavior:
        - Retrieves the group's current state from the firewall.
        - For each member in the firewall group:
            - If the member's name is not in `object_internal_names`, logs an error
              and removes the member from the group in the firewall.
            - If the member exists in external data, logs a confirmation.
        - If the group has no members, logs a warning and returns False.

    Logging:
        - Logs information, errors, and warnings about each synchronization step,
          including removed members and API method results.

    Notes:
        - Assumes `int_domain` has methods:
            * `show_group(group_name)` to retrieve group details.
            * `set_group(name, remove)` to remove a member from a group.
        - Assumes `logger` is a globally configured logging instance.
    """
    group=int_domain.show_group(source_group['group_name'])
    if 'members' in group:
        for member in group['members']:
            logger.info('Dealing with host %s ',json.dumps(member, indent=4))
            if member['name'] not in object_internal_names:
                logger.error(
                        'Object %s not found in external data. Removing from group %s.',
                        member['name'],
                        source_group['group_name']
                        )
                result=int_domain.set_group(name=source_group['group_name'],remove=member['name'])
                logger.error('Result %s',json.dumps(result, indent=4))
            else:
                logger.info('Object %s found in external data.',member['name'])
        return True
    logger.warning('A group in the firewall is empty!')
    return False


def sync_external_data_to_firewall(data,int_domain):
    """
    Synchronize group data between an external source and the firewall.

    This function iterates through a list of group dictionaries and performs a
    bidirectional synchronization for each group: from the external source to the
    firewall, and from the firewall back to the external source. Synchronization
    occurs only for groups allowed by the defined sync policy.

    The function logs progress, including details of each group being processed,
    and handles restricted groups by logging an error without performing sync.

    Parameters:
        data (list of dict): A list of dictionaries, each representing a group with
                             at least the key 'group_name' and associated content.
        int_domain (str): The internal domain identifier used during synchronization
                          operations with the firewall.

    Behavior:
        - If `RESTRICTED_GROUPS` is enabled and a group's name is not in
          `ALLOWED_SYNC_GROUPS`, the group is skipped with an error logged.
        - Otherwise, synchronization is performed in two steps:
            1. External -> Firewall using `sync_external_group_to_firewall`
            2. Firewall -> External using `sync_firewall_group_to_external`

    Logging:
        - Logs detailed information for each group, including full JSON structure.
        - Logs syncing direction and policy violations.

    Notes:
        - Uses external synchronization functions:
            `sync_external_group_to_firewall(source_group, int_domain, object_internal_names)`
            `sync_firewall_group_to_external(source_group, int_domain, object_internal_names)`
        - Assumes the presence of global variables:
            `RESTRICTED_GROUPS`, `ALLOWED_SYNC_GROUPS`, and a configured `logger`.
    """
    for source_group in data:
        if RESTRICTED_GROUPS and source_group['group_name'] not in ALLOWED_SYNC_GROUPS:
            logger.error(
                    'Using a restricted creation policy, and group %s is not allowed',
                    source_group['group_name']
                    )
        else:
            object_internal_names=[]
            logger.info('Working with group %s',json.dumps(source_group, indent=4))
            logger.info('Syncing group %s from site ====> firewall.',source_group['group_name'])
            sync_external_group_to_firewall(source_group,int_domain,object_internal_names)
            logger.info('Syncing group %s from firewall ====> site.',source_group['group_name'])
            sync_firewall_group_to_external(source_group,int_domain,object_internal_names)


def prepend_group_name(data):
    """
    Prepend a predefined prefix to the 'group_name' of each group in the input list.

    This function iterates through a list of group dictionaries and updates each
    dictionary's 'group_name' by adding the global `GROUP_PREFIX` at the beginning.
    It returns a new list containing the modified group dictionaries.

    Parameters:
        data (list of dict): A list of dictionaries, each expected to have a
                             'group_name' key with a string value.

    Returns:
        list of dict: A list of dictionaries with updated 'group_name' values,
                      now prefixed with `GROUP_PREFIX`.

    Notes:
        - The function modifies the dictionaries inside the input list (in-place),
          but returns a new list containing those dictionaries.
        - It assumes `GROUP_PREFIX` is a predefined global string.
    """
    result=[]
    for item in data:
        item['group_name'] = GROUP_PREFIX+item['group_name']
        result.append(item)
    return result


def add_dummy_host(data):
    """
    Append a dummy host entry to the 'group_content' of each group in the input list.

    This function iterates through a list of group dictionaries and adds the global
    `DUMMY_HOST` value to each dictionary's 'group_content' list. It returns a new
    list containing the modified group dictionaries.

    Parameters:
        data (list of dict): A list of dictionaries, each expected to have a
                             'group_content' key containing a list.

    Returns:
        list of dict: A list of dictionaries where each 'group_content' list now
                      includes the `DUMMY_HOST` entry.

    Notes:
        - The function modifies the dictionaries inside the input list (in-place),
          but returns a new list containing those dictionaries.
        - It assumes `DUMMY_HOST` is a predefined global object that represents
          a placeholder or dummy host.
    """
    result=[]
    for item in data:
        item['group_content'].append(DUMMY_HOST)
        result.append(item)
    return result


def add_missing_groups(data):
    """
    Ensure that all groups listed in ALLOWED_SYNC_GROUPS are present in the input list.

    This function checks the list of existing group dictionaries (`data`) to see which
    group names are already included. For any group name defined in the global
    ALLOWED_SYNC_GROUPS list that is not found in `data`, it appends a new dictionary
    with that group name and an empty `group_content` list.

    Parameters:
        data (list of dict): A list of dictionaries, each expected to have the keys
                           'group_name' and 'group_content'.

    Returns:
        list of dict: The updated list including any missing groups initialized with
                      empty content.

    Notes:
        - The function modifies the input list in place by appending missing groups.
        - Each added group has the structure:
          {'group_name': <name>, 'group_content': []}
    """
    result=data
    ed_group_names=[item['group_name'] for item in data]
    for group_name in ALLOWED_SYNC_GROUPS:
        if group_name not in ed_group_names:
            result.append({'group_name':group_name,'group_content':[]})
    return result


if __name__ == "__main__":
    LOCK_HANDLE = acquire_lock()
    try:
        if not is_out_of_work_hours() and NON_WORKING_HOURS_ONLY:
            logger.info("Sorry, I am not allowed to run during working hours.")
            sys.exit()

        try:
            external_data = authenticate_and_retrieve_data()
            external_data = prepend_group_name(external_data)
            external_data = add_missing_groups(external_data)
            external_data = add_dummy_host(external_data)

            domain = Cptapi(
                user,
                password,
                url,
                domain_name,
                api_wait_time=api_wait_time,
                read_only=False,
                page_size=page_size,
                publish_wait_time=publish_wait_time
            )
            domain.verbose = False

            if external_data:
                logger.info('Syncing external source to firewall.')
                logger.info('External data retrieved %s', json.dumps(external_data, indent=4))
                sync_external_data_to_firewall(external_data, domain)
            else:
                logger.error("\nFailed to fetch JSON data.")
                logger.error("Please check the URL, credentials, and ensure the server is accessible.")

            session = domain.show_session()
            if session['changes'] != 0:
                domain.publish()
                domain.reassign_all()
                domain.reinstall_all_policies()

            domain.logout()

        except AuthenticationError as auth_error:
            logger.error(f"Authentication failed: {auth_error}")
        except DataRetrievalError as data_error:
            logger.error(f"Data retrieval failed: {data_error}")
        except Exception as general_error:
            logger.error(f"An unexpected error occurred: {general_error}")

    finally:
        release_lock()
        if ENABLE_EMAIL_REPORTING:
            send_error_email(error_handler.errors)



