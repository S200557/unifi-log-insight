"""Deployment profile. No router credentials or management client is required."""
import os


def is_mikrotik():
    return os.environ.get('ROUTER_PLATFORM', 'unifi').lower() == 'mikrotik'


def default_wan_interfaces():
    # RouterOS names are arbitrary; require an explicit selection during setup.
    return [] if is_mikrotik() else ['ppp0']
