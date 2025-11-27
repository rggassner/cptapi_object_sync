# object_sync
Sync objects from a json source to checkpoint objects

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
