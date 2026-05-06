from .scanner_manager import (
    scan_service,
    get_supported_ports,
    get_scanner_info,
    get_pre_scan_intelligence,
    generate_scan_plan,
    get_integration_status,
    initialize_integrations,
    scanner_manager,
    passive_discovery,
    enhanced_vulnerability_scan,
    # Add the missing functions
    enhanced_scan_service,
    bulk_scan_with_intelligence,
    quick_intelligence_lookup,
    get_enhanced_capabilities,
    validate_scan_target,
    check_service_health,
    scan_service_aggressive,
    get_smb_scanner_status,

)

# Try to import FTP-specific functions with fallback
try:
    # Import FTP-specific functions if available
    def ftp_specific_scan(ip: str, port: int = 21, **kwargs):
        """FTP-specific scanning with enhanced defaults"""
        # Ensure FTP-specific defaults
        ftp_options = {
            'service_type': 'ftp',
            'use_individual_nmap': True,
            'enable_vuln_check': True,
            'test_anonymous': True,
            'test_directory_traversal': True,
            'test_bounce_attack': True
        }

        ftp_options.update(kwargs)
        return enhanced_scan_service(ip, port, **ftp_options)

    def validate_ftp_target(target: str, port: int = 21):
        """FTP-specific target validation"""
        validation = validate_scan_target(target, 'ip')

        # Add FTP-specific validation
        validation.update({
            'port': port,
            'service_type': 'ftp',
            'ftp_specific': True,
            'ftp_enhanced_available': True
        })

        # Check if port is FTP-related
        if port not in [21, 990, 2121, 8021]:
            validation['recommendations'].append(f'Port {port} is not a standard FTP port (21, 990, 2121, 8021)')

        # Check nmap availability for enhanced scanning
        try:
            status = get_integration_status()
            nmap_available = status.get('integrations', {}).get('individual_scanner_nmap', {}).get('enabled', False)
            validation['nmap_available'] = nmap_available

            if nmap_available:
                validation['recommendations'].append('Enhanced nmap FTP scanning available')
            else:
                validation['recommendations'].append('Basic FTP scanning only (install nmap for enhanced features)')
        except:
            validation['nmap_available'] = False
            validation['recommendations'].append('Could not check nmap availability')

        return validation

    FTP_SPECIFIC_AVAILABLE = True
    print("✅ FTP-specific scan functions loaded successfully")

except Exception as e:
    print(f"⚠️ FTP-specific functions could not be loaded: {e}")

    # Create fallback functions
    def ftp_specific_scan(ip: str, port: int = 21, **kwargs):
        """Fallback FTP scanning using standard enhanced scan"""
        print(f"⚠️ Using fallback FTP scanning for {ip}:{port}")
        return enhanced_scan_service(ip, port, **kwargs)

    def validate_ftp_target(target: str, port: int = 21):
        """Fallback FTP validation"""
        validation = validate_scan_target(target, 'ip')
        validation.update({
            'port': port,
            'service_type': 'ftp',
            'ftp_specific': False,
            'ftp_enhanced_available': False
        })
        return validation

    FTP_SPECIFIC_AVAILABLE = False

# Try to import SMB-specific functions
try:
    def smb_specific_scan(ip: str, port: int = 445, **kwargs):
        """SMB-specific scanning with enhanced defaults"""
        smb_options = {
            'service_type': 'smb',
            'use_individual_nmap': True,
            'enable_vuln_check': True,
            'test_null_session': True,
            'test_shares': True,
            'test_vulnerabilities': True
        }

        smb_options.update(kwargs)
        return enhanced_scan_service(ip, port, **smb_options)

    def validate_smb_target(target: str, port: int = 445):
        """SMB-specific target validation"""
        validation = validate_scan_target(target, 'ip')

        validation.update({
            'port': port,
            'service_type': 'smb',
            'smb_specific': True,
            'smb_enhanced_available': True
        })

        # Check if port is SMB-related
        if port not in [139, 445]:
            validation['recommendations'].append(f'Port {port} is not a standard SMB port (139, 445)')

        # Check WSL availability for enhanced scanning
        try:
            import subprocess
            wsl_test = subprocess.run(['wsl', 'echo', 'test'],
                                      capture_output=True, text=True, timeout=5)
            validation['wsl_available'] = wsl_test.returncode == 0

            if validation['wsl_available']:
                validation['recommendations'].append('Enhanced WSL-based SMB scanning available')
            else:
                validation['recommendations'].append('Basic SMB scanning only (WSL recommended for advanced features)')
        except:
            validation['wsl_available'] = False
            validation['recommendations'].append('Could not check WSL availability')

        return validation

    SMB_SPECIFIC_AVAILABLE = True
    print("✅ SMB-specific scan functions loaded successfully")

except Exception as e:
    print(f"⚠️ SMB-specific functions could not be loaded: {e}")

    def smb_specific_scan(ip: str, port: int = 445, **kwargs):
        """Fallback SMB scanning"""
        print(f"⚠️ Using fallback SMB scanning for {ip}:{port}")
        return enhanced_scan_service(ip, port, **kwargs)

    def validate_smb_target(target: str, port: int = 445):
        """Fallback SMB validation"""
        validation = validate_scan_target(target, 'ip')
        validation.update({
            'port': port,
            'service_type': 'smb',
            'smb_specific': False,
            'smb_enhanced_available': False
        })
        return validation

    SMB_SPECIFIC_AVAILABLE = False

# NEW: Try to import SNMP-specific functions
try:
    def snmp_specific_scan(ip: str, port: int = 161, **kwargs):
        """SNMP-specific scanning with enhanced defaults"""
        snmp_options = {
            'service_type': 'snmp',
            'use_individual_nmap': True,
            'enable_vuln_check': True,
            'test_community_strings': True,
            'enumerate_system_info': True,
            'snmp_nmap_integration': True
        }

        snmp_options.update(kwargs)
        return enhanced_scan_service(ip, port, **snmp_options)

    def validate_snmp_target(target: str, port: int = 161):
        """SNMP-specific target validation"""
        validation = validate_scan_target(target, 'ip')

        validation.update({
            'port': port,
            'service_type': 'snmp',
            'protocol': 'UDP',
            'snmp_specific': True,
            'snmp_enhanced_available': True
        })

        # Check if port is SNMP-related
        if port != 161:
            validation['recommendations'].append(f'Port {port} is not the standard SNMP port (161)')

        # Check nmap availability for enhanced scanning
        try:
            status = get_integration_status()
            nmap_available = status.get('integrations', {}).get('individual_scanner_nmap', {}).get('enabled', False)
            validation['nmap_available'] = nmap_available

            if nmap_available:
                validation['recommendations'].append('Enhanced nmap SNMP scanning with NSE scripts available')
                validation['recommendations'].append('Aggressive mode includes community string brute force')
            else:
                validation['recommendations'].append('Basic SNMP scanning only (install nmap for enhanced features)')
        except:
            validation['nmap_available'] = False
            validation['recommendations'].append('Could not check nmap availability')

        # Add SNMP-specific recommendations
        validation['recommendations'].extend([
            'SNMP uses UDP protocol - ensure firewall allows UDP 161',
            'Community strings will be tested - ensure proper authorization',
            'Consider SNMPv3 for enhanced security testing',
            'Aggressive mode includes system enumeration and brute force'
        ])

        return validation

    SNMP_SPECIFIC_AVAILABLE = True
    print("✅ SNMP-specific scan functions loaded successfully")

except Exception as e:
    print(f"⚠️ SNMP-specific functions could not be loaded: {e}")

    def snmp_specific_scan(ip: str, port: int = 161, **kwargs):
        """Fallback SNMP scanning"""
        print(f"⚠️ Using fallback SNMP scanning for {ip}:{port}")
        return enhanced_scan_service(ip, port, **kwargs)

    def validate_snmp_target(target: str, port: int = 161):
        """Fallback SNMP validation"""
        validation = validate_scan_target(target, 'ip')
        validation.update({
            'port': port,
            'service_type': 'snmp',
            'protocol': 'UDP',
            'snmp_specific': False,
            'snmp_enhanced_available': False
        })
        validation['recommendations'].append('Basic SNMP validation only - enhanced features unavailable')
        return validation

    SNMP_SPECIFIC_AVAILABLE = False

# Enhanced service configuration
SERVICE_CONFIG = {
    'default_timeout': 10,
    'max_concurrent_scans': 5,
    'enable_verbose_logging': True,

    # Shodan integration settings
    'shodan_integration': {
        'enabled': True,
        'default_use_pre_scan': True,
        'cache_results': True,
        'cache_duration_minutes': 30
    },

    # CVE integration settings
    'cve_integration': {
        'enabled': True,
        'default_nvd_api_key': 'dcb2817e-0074-422c-8d1a-fcd54711ca3b',
        'rate_limit_delay': 0.6
    },

    # Individual scanner nmap integration
    'individual_scanner_nmap': {
        'enabled': True,
        'auto_detect': True,
        'fallback_on_failure': True,
        'supported_scanners': ['FTP', 'SSH', 'HTTP', 'SMB', 'SNMP'],  # Added SNMP
        'timeout': 30
    },

    # Scan optimization settings
    'scan_optimization': {
        'prioritize_common_ports': True,
        'skip_known_closed_ports': True,
        'use_intelligence_for_targeting': True,
        'prefer_nmap_when_available': True
    },

    # FTP-specific settings
    'ftp_scanner': {
        'enable_nmap_integration': True,
        'nse_scripts_enabled': True,
        'anonymous_login_test': True,
        'directory_traversal_test': True,
        'bounce_attack_test': True,
        'max_enumeration_time': 60
    },

    # SMB-specific settings
    'smb_scanner': {
        'enable_wsl_integration': True,
        'enable_nmap_integration': True,
        'nse_scripts_enabled': True,
        'null_session_test': True,
        'share_enumeration': True,
        'user_enumeration': True,
        'vulnerability_testing': True,
        'aggressive_mode_available': True,
        'max_enumeration_time': 120,
        'wsl_tools': [
            'nmap', 'enum4linux-ng', 'smbmap', 'crackmapexec',
            'smbclient', 'rpcclient', 'nmblookup'
        ]
    },

    # NEW: SNMP-specific settings
    'snmp_scanner': {
        'enable_nmap_integration': True,
        'nse_scripts_enabled': True,
        'community_string_testing': True,
        'system_enumeration': True,
        'windows_enumeration': True,
        'aggressive_mode_available': True,
        'max_enumeration_time': 180,
        'default_communities': [
            'public', 'private', 'community', 'snmp', 'read', 'write',
            'admin', 'manager', 'cisco', 'password', '123456', 'default'
        ],
        'nse_scripts': [
            'snmp-sysdescr', 'snmp-info', 'snmp-interfaces',
            'snmp-brute', 'snmp-win32-services', 'snmp-win32-shares',
            'snmp-win32-users', 'snmp-win32-software', 'snmp-processes'
        ]
    }
}

def get_service_config():
    """Get service configuration"""
    return SERVICE_CONFIG

def update_service_config(**kwargs):
    """Update service configuration"""
    SERVICE_CONFIG.update(kwargs)

def print_service_info():
    """Print enhanced service information on startup"""
    print("🔧 ReconLite Service Layer Initialized")
    print(f"📊 Configuration: {len(SERVICE_CONFIG)} sections loaded")

    try:
        capabilities = get_enhanced_capabilities()
        enhanced_count = sum(1 for feature in capabilities.get('enhanced_features', {}).values()
                             if feature.get('enabled', False))
        scanner_count = sum(1 for feature in capabilities.get('scanner_features', {}).values()
                            if feature.get('enabled', False))

        print(f"✨ Enhanced Features: {enhanced_count} integrations active")
        print(f"🎯 Scanner Features: {scanner_count} enhanced scanners active")

        # Check specific integrations
        if capabilities['enhanced_features'].get('shodan_intelligence', {}).get('enabled'):
            print("🌐 Shodan Intelligence: Ready")
        if capabilities['enhanced_features'].get('cve_detection', {}).get('enabled'):
            print("🔍 CVE Detection: Ready")
        if capabilities['enhanced_features'].get('advanced_scanning', {}).get('enabled'):
            print("🎯 Advanced Scanning: Ready")

        # Check scanner-specific features
        if capabilities['scanner_features'].get('individual_nmap_integration', {}).get('enabled'):
            print("📁 Enhanced FTP Scanner: Ready (with nmap)")
        else:
            print("📁 Basic FTP Scanner: Ready (fallback mode)")

        # FTP-specific status
        if FTP_SPECIFIC_AVAILABLE:
            print("   - FTP-specific functions: ✅ Available")
        else:
            print("   - FTP-specific functions: ⚠️ Using fallback")

        # SMB-specific status
        if SMB_SPECIFIC_AVAILABLE:
            print("   - SMB-specific functions: ✅ Available")
        else:
            print("   - SMB-specific functions: ⚠️ Using fallback")

        # NEW: SNMP-specific status
        if SNMP_SPECIFIC_AVAILABLE:
            print("   - SNMP-specific functions: ✅ Available")
        else:
            print("   - SNMP-specific functions: ⚠️ Using fallback")

        ftp_config = SERVICE_CONFIG.get('ftp_scanner', {})
        if ftp_config.get('enable_nmap_integration'):
            print("   - FTP nmap integration: ✅ Enabled")
        if ftp_config.get('nse_scripts_enabled'):
            print("   - FTP NSE scripts: ✅ Enabled")

        smb_config = SERVICE_CONFIG.get('smb_scanner', {})
        if smb_config.get('enable_wsl_integration'):
            print("   - SMB WSL integration: ✅ Enabled")
        if smb_config.get('aggressive_mode_available'):
            print("   - SMB aggressive mode: ✅ Available")

        # NEW: SNMP configuration status
        snmp_config = SERVICE_CONFIG.get('snmp_scanner', {})
        if snmp_config.get('enable_nmap_integration'):
            print("   - SNMP nmap integration: ✅ Enabled")
        if snmp_config.get('aggressive_mode_available'):
            print("   - SNMP aggressive mode: ✅ Available")
        if snmp_config.get('community_string_testing'):
            print("   - SNMP community testing: ✅ Enabled")

    except Exception as e:
        print(f"⚠️ Could not load enhancement info: {e}")

# Enhanced exports including all functions
__all__ = [
    # Core scanner functions
    'scan_service',
    'get_supported_ports',
    'get_scanner_info',

    # Enhanced Shodan integration functions
    'get_pre_scan_intelligence',
    'generate_scan_plan',
    'get_integration_status',
    'initialize_integrations',

    # Enhanced scanning functions
    'enhanced_scan_service',
    'ftp_specific_scan',
    'smb_specific_scan',
    'snmp_specific_scan',  # NEW
    'bulk_scan_with_intelligence',
    'quick_intelligence_lookup',

    # Configuration functions
    'get_service_config',
    'update_service_config',
    'get_enhanced_capabilities',

    # Utility functions
    'validate_scan_target',
    'validate_ftp_target',
    'validate_smb_target',
    'validate_snmp_target',  # NEW
    'check_service_health',

    # Scanner manager instance
    'scanner_manager',

    # Discovery functions
    'passive_discovery',
    'enhanced_vulnerability_scan',

    # Aggressive scanning
    'scan_service_aggressive',

    # Status functions
    'get_smb_scanner_status',


    # Status variables
    'FTP_SPECIFIC_AVAILABLE',
    'SMB_SPECIFIC_AVAILABLE',
    'SNMP_SPECIFIC_AVAILABLE'  # NEW
]

# Initialize and print status
print_service_info()