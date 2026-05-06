from .input_handler import InputHandler
from .netlas_client import NetlasClient
from .shodan_client import ShodanClient
from .whois_lookup import WhoisLookup
from .dns_recon import DNSRecon
from .export_manager import ExportManager

__all__ = [
    'InputHandler',
    'NetlasClient',
    'ShodanClient',
    'WhoisLookup',
    'DNSRecon',
    'ExportManager'
]

# Version info
__version__ = '2.0.0'

def get_core_version():
    """Get core module version"""
    return __version__