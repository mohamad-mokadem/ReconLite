import time
import json
import io
import traceback
from datetime import datetime

import self
from flask import Flask, request, jsonify, render_template, send_file
from typing import Dict, Any, List
from database import db
import subprocess
import shutil
import os

# Import API keys from config
from config.vulnerability_config import (
    VULNERS_API_KEY,
    SHODAN_API_KEY,
    NETLAS_API_KEY,
    SECURITYTRAILS_API_KEY
)

from services import (
    scan_service,
    get_supported_ports,
    get_scanner_info,
    get_pre_scan_intelligence,
    generate_scan_plan,
    get_integration_status,
    enhanced_scan_service,
    bulk_scan_with_intelligence,
    quick_intelligence_lookup,
    get_enhanced_capabilities,
    validate_scan_target,
    check_service_health,
    initialize_integrations,
    # Enhanced nmap functions
    passive_discovery,
    enhanced_vulnerability_scan
)
from services.scanner_manager import scan_service_aggressive
from services import smb_specific_scan, validate_smb_target
from services.snmp_scanner import SNMPScanner

# Try to import FTP-specific functions
try:
    from services import ftp_specific_scan, validate_ftp_target

    FTP_SPECIFIC_AVAILABLE = True
    print("✅ FTP-specific scan functions available")
except ImportError:
    FTP_SPECIFIC_AVAILABLE = False
    print("⚠️ FTP-specific scan functions not available - using fallback")


try:
    from services.http_scanner import HTTPScanner
    HTTP_SCANNER_AVAILABLE = True
    print("✅ HTTP scanner available")
except ImportError as e:
    HTTP_SCANNER_AVAILABLE = False
    print(f"⚠️ HTTP scanner not available: {e}")

try:
    from services.snmp_scanner import SNMPScanner
    SNMP_SCANNER_AVAILABLE = True
    print("✅ SNMP scanner available")
except ImportError:
    SNMP_SCANNER_AVAILABLE = False
    print("⚠️ SNMP scanner not available")

from core.input_handler import InputHandler
from core.netlas_client import NetlasClient
from core.shodan_client import ShodanClient
from core.whois_lookup import WhoisLookup
from core.dns_recon import DNSRecon
from core.export_manager import ExportManager

app = Flask(__name__)

# Initialize core components
input_handler = InputHandler()
netlas_client = NetlasClient(NETLAS_API_KEY)
shodan_client = ShodanClient(SHODAN_API_KEY)
whois_lookup = WhoisLookup()
dns_recon = DNSRecon(SECURITYTRAILS_API_KEY)
export_manager = ExportManager()

print("🔧 Initializing enhanced scanner integrations with Nmap NSE...")
initialize_integrations(
    shodan_api_key=SHODAN_API_KEY,
    vulners_api_key=VULNERS_API_KEY
)


def check_nmap_installation():
    """Check if nmap is installed and accessible"""
    try:
        result = subprocess.run(['nmap', '--version'],
                                capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            version_line = result.stdout.split('\n')[0]
            return {
                'installed': True,
                'version': version_line,
                'path': shutil.which('nmap')
            }
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass

    return {
        'installed': False,
        'version': None,
        'path': None
    }


def check_nmap_permissions():
    """Check if nmap can be run (Windows-compatible)"""
    try:
        # On Windows, just check if nmap runs without admin requirements
        result = subprocess.run(['nmap', '--version'],
                                capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except:
        return False


def handle_nmap_permission_error(error_message):
    """Handle nmap permission errors gracefully (Windows-compatible)"""
    if 'permission' in error_message.lower() or 'access' in error_message.lower():
        return {
            'error': 'Nmap execution issue on Windows',
            'suggestions': [
                'Run PyCharm as Administrator',
                'Ensure nmap is installed and in PATH',
                'Try running: nmap --version in Command Prompt',
                'Install nmap from: https://nmap.org/download.html'
            ],
            'fallback': 'Using basic FTP enumeration without nmap enhancement'
        }
    return {'error': error_message}


def check_vulners_nse_scripts():
    """Check if Vulners NSE scripts are available"""
    try:
        # Common paths for NSE scripts
        nse_paths = [
            '/usr/share/nmap/scripts/',
            '/usr/local/share/nmap/scripts/',
            'C:\\Program Files (x86)\\Nmap\\scripts\\',
            'C:\\Program Files\\Nmap\\scripts\\'
        ]

        vulners_scripts = ['vulners.nse', 'http-vulners-regex.nse']
        found_scripts = []

        for path in nse_paths:
            if os.path.exists(path):
                for script in vulners_scripts:
                    script_path = os.path.join(path, script)
                    if os.path.exists(script_path):
                        found_scripts.append(script)

        return {
            'available': len(found_scripts) > 0,
            'scripts_found': found_scripts,
            'total_scripts': len(vulners_scripts)
        }
    except Exception:
        return {
            'available': False,
            'scripts_found': [],
            'total_scripts': 0
        }


# Complete Active and Aggressive SNMP Routes for app.py

# Add this import at the top of your app.py
try:
    from services.snmp_scanner import SNMPScanner

    SNMP_SCANNER_AVAILABLE = True
    print("✅ SNMP scanner available")
except ImportError:
    SNMP_SCANNER_AVAILABLE = False
    print("⚠️ SNMP scanner not available")


@app.route('/api/active-scan', methods=['POST'])
def active_scan():
    """Enhanced active scanning endpoint with complete HTTP integration"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        target_ip = data.get('targetIP')
        target_port = data.get('targetPort')
        scan_type = data.get('scanType', 'auto')
        custom_wordlist = data.get('customWordlist')

        # Enhanced options
        enhanced_mode = data.get('enhancedMode', True)
        enable_shodan = False
        enable_vuln_check = False
        use_enhanced_nmap = data.get('useEnhancedNmap', False)

        scan_start_time = time.time()

        print(f"🎯 Enhanced active scan request for {target_ip}:{target_port}")
        print(f"🔍 Scan type: {scan_type}, Enhanced mode: {enhanced_mode}")
        print(f"🛡️ Shodan: {enable_shodan}, Vulners: {enable_vuln_check}")
        print(f"🎯 Enhanced nmap NSE: {use_enhanced_nmap}")

        # Validation
        if not target_ip or not target_port:
            return jsonify({'error': 'Target IP and port are required'}), 400

        try:
            import ipaddress
            ipaddress.ip_address(target_ip)
            port = int(target_port)
            if port < 1 or port > 65535:
                raise ValueError("Invalid port range")
        except ValueError as e:
            return jsonify({'error': str(e)}), 400

        # Enhanced port support check - NOW INCLUDES HTTP AND HTTPS
        supported_ports = get_supported_ports()
        https_ports = [443, 8443, 9443]  # HTTPS ports
        http_ports = [80, 8000, 8080]  # HTTP ports (8080 can be both HTTP and HTTPS)
        web_ports = http_ports + https_ports

        if port not in supported_ports and port not in web_ports:
            return jsonify({
                'error': f'Port {port} is not supported for active scanning',
                'supported_ports': supported_ports + web_ports,
                'scanner_info': get_scanner_info(),
                'http_ports_supported': http_ports,
                'https_ports_supported': https_ports,
                'note': 'HTTP and HTTPS ports now supported with dedicated web application scanners'
            }), 400

        # Create session with enhanced detection
        target_name = f"{target_ip}:{port}"
        session_type = "Enhanced Active Scan"

        # Detect service type for better session naming
        if port in https_ports:
            session_type += " (HTTPS/SSL)"
        elif port in http_ports:
            session_type += " (HTTP)"
        elif port in [161]:
            session_type += " (SNMP)"
        elif port in [139, 445]:
            session_type += " (SMB)"
        elif port in [21, 990, 2121, 8021]:
            session_type += " (FTP)"
        elif port in [22, 2222]:
            session_type += " (SSH)"
        elif port in [25, 465, 587, 2525]:
            session_type += " (SMTP)"

        if use_enhanced_nmap:
            session_type += " + Nmap NSE + Vulners"
        elif enhanced_mode:
            session_type += " + Individual Scanner Enhancement"

        session_data = {
            'name': f"{session_type} - {target_name}",
            'type': 'active',
            'target': target_name,
            'status': 'in_progress'
        }
        session_id = db.create_session(session_data)
        print(f"📝 Session created with ID: {session_id}")

        # Enhanced scanning logic with HTTP support
        results = None
        scan_method = None

        # Method 1: Enhanced nmap comprehensive scanning
        if use_enhanced_nmap:
            print(f"🚀 Attempting enhanced nmap NSE vulnerability scanner")
            try:
                results = enhanced_vulnerability_scan(target_ip, port, scan_type)
                scan_method = 'enhanced_nmap_nse'
                results['enhanced_nmap_used'] = True
                print(f"✅ Enhanced nmap scan successful")
            except Exception as nmap_error:
                print(f"❌ Enhanced nmap scan failed: {nmap_error}")
                print(f"🔄 Falling back to individual scanner method...")
                use_enhanced_nmap = False

        # Method 2: Individual scanner with enhanced features
        if not use_enhanced_nmap:
            print(f"🚀 Using individual scanner method for port {port}")

            # Try HTTP scanning first
            http_results, http_scan_method = handle_http_scanning(
                data, target_ip, port, session_id, enhanced_mode,
                enable_vuln_check, enable_shodan, scan_type, custom_wordlist
            )

            if http_results and http_scan_method:
                results = http_results
                scan_method = http_scan_method

            # HTTPS-specific scanning logic
            elif port in https_ports:
                print(f"🔒 HTTPS port detected - using dedicated HTTPS scanner")
                try:
                    from services.https_scanner import HTTPSScanner
                    https_scanner = HTTPSScanner()

                    # Determine HTTPS scan intensity
                    https_intensity = data.get('httpsScanIntensity', 'normal')

                    # Process custom wordlist for directory enumeration
                    custom_paths = None
                    if custom_wordlist and custom_wordlist.strip():
                        custom_paths = [path.strip() for path in custom_wordlist.split('\n') if path.strip()]
                        print(f"🔍 Custom directory paths detected: {len(custom_paths)} paths")

                    if https_intensity == 'aggressive':
                        print(f"🎯 Running aggressive HTTPS scan with all scripts")
                        scan_results = https_scanner.scan_aggressive(target_ip, port)
                    else:
                        print(f"🔒 Running normal HTTPS scan (safe mode)")
                        # ✅ Now passing custom_paths to the scanner
                        scan_results = https_scanner.scan(target_ip, port, custom_paths=custom_paths)

                    # Process HTTPS results
                    results = process_https_scan_results(scan_results, session_id, target_ip, port, https_intensity)
                    scan_method = f'https_scanner_{https_intensity}'
                    print(f"✅ HTTPS scan completed successfully")

                except ImportError:
                    print(f"⚠️ HTTPS scanner not available, using standard method")
                    scan_kwargs = prepare_standard_scan_kwargs(enable_vuln_check, enable_shodan,
                                                               enhanced_mode, scan_type, custom_wordlist, port)
                    results = enhanced_scan_service(target_ip, port, **scan_kwargs)
                    scan_method = 'standard_enhanced_fallback'
                except Exception as https_error:
                    print(f"❌ HTTPS scanner failed: {https_error}")
                    scan_kwargs = prepare_standard_scan_kwargs(enable_vuln_check, enable_shodan,
                                                               enhanced_mode, scan_type, custom_wordlist, port)
                    results = enhanced_scan_service(target_ip, port, **scan_kwargs)
                    scan_method = 'standard_enhanced_fallback'

            # SNMP-specific scanning logic
            elif port in [161]:
                print(f"📡 SNMP port detected - using enhanced SNMP scanner")
                try:
                    if SNMP_SCANNER_AVAILABLE:
                        snmp_scanner = SNMPScanner()
                        results = snmp_scanner.scan(target_ip, port)

                        # Add metadata for compatibility with frontend
                        results.update({
                            'session_id': session_id,
                            'enhanced_mode': enhanced_mode,
                            'scan_method': 'snmp_enhanced_scanner',
                            'service_name': 'SNMP',
                            'service_type': 'snmp',
                            'target': target_name,
                            'ip': target_ip,
                            'port': port,
                            'nmap_enhanced': results.get('nmap_enhanced', False),
                            'snmp_protocol_info': results.get('advanced_findings', {}),
                            'protocol': 'UDP',
                            'scanner_type': 'SNMP Enhanced'
                        })

                        scan_method = 'snmp_enhanced_scanner'
                        print(f"✅ Enhanced SNMP scan completed")
                    else:
                        raise ImportError("SNMP scanner not available")
                except ImportError:
                    print(f"⚠️ SNMP-specific scan not available, using standard method")
                    scan_kwargs = prepare_standard_scan_kwargs(enable_vuln_check, enable_shodan,
                                                               enhanced_mode, scan_type, custom_wordlist, port)
                    results = enhanced_scan_service(target_ip, port, **scan_kwargs)
                    scan_method = 'standard_enhanced_fallback'
                except Exception as snmp_error:
                    print(f"❌ Enhanced SNMP scan failed: {snmp_error}")
                    scan_kwargs = prepare_standard_scan_kwargs(enable_vuln_check, enable_shodan,
                                                               enhanced_mode, scan_type, custom_wordlist, port)
                    results = enhanced_scan_service(target_ip, port, **scan_kwargs)
                    scan_method = 'standard_enhanced_fallback'

            # SMB-specific scanning logic
            elif port in [139, 445]:
                print(f"🏢 SMB port detected - using enhanced SMB scanner")
                try:
                    from services import smb_specific_scan
                    results = smb_specific_scan(target_ip, port,
                                                enable_vuln_check=enable_vuln_check,
                                                enable_shodan=enable_shodan,
                                                use_pre_scan=enhanced_mode,
                                                scan_type=scan_type)
                    scan_method = 'smb_enhanced_scanner'
                    print(f"✅ Enhanced SMB scan completed")
                except ImportError:
                    print(f"⚠️ SMB-specific scan not available, using standard method")
                    scan_kwargs = prepare_standard_scan_kwargs(enable_vuln_check, enable_shodan,
                                                               enhanced_mode, scan_type, custom_wordlist, port)
                    results = enhanced_scan_service(target_ip, port, **scan_kwargs)
                    scan_method = 'standard_enhanced_fallback'
                except Exception as smb_error:
                    print(f"❌ Enhanced SMB scan failed: {smb_error}")
                    scan_kwargs = prepare_standard_scan_kwargs(enable_vuln_check, enable_shodan,
                                                               enhanced_mode, scan_type, custom_wordlist, port)
                    results = enhanced_scan_service(target_ip, port, **scan_kwargs)
                    scan_method = 'standard_enhanced_fallback'

            # FTP-specific scanning logic
            elif port in [21, 990, 2121, 8021]:
                print(f"📁 FTP port detected - using enhanced FTP scanner")
                try:
                    if FTP_SPECIFIC_AVAILABLE:
                        results = ftp_specific_scan(target_ip, port,
                                                    enable_vuln_check=enable_vuln_check,
                                                    enable_shodan=enable_shodan,
                                                    use_pre_scan=enhanced_mode)
                        scan_method = 'ftp_enhanced_scanner'
                        print(f"✅ Enhanced FTP scan completed")
                    else:
                        raise ImportError("FTP-specific scan not available")
                except ImportError:
                    print(f"⚠️ FTP-specific scan not available, using standard method")
                    scan_kwargs = prepare_standard_scan_kwargs(enable_vuln_check, enable_shodan,
                                                               enhanced_mode, scan_type, custom_wordlist, port)
                    results = enhanced_scan_service(target_ip, port, **scan_kwargs)
                    scan_method = 'standard_enhanced_fallback'
                except Exception as ftp_error:
                    print(f"❌ Enhanced FTP scan failed: {ftp_error}")
                    scan_kwargs = prepare_standard_scan_kwargs(enable_vuln_check, enable_shodan,
                                                               enhanced_mode, scan_type, custom_wordlist, port)
                    results = enhanced_scan_service(target_ip, port, **scan_kwargs)
                    scan_method = 'standard_enhanced_fallback'
            else:
                print(f"🔍 Other service port - using standard enhanced scanner")
                scan_kwargs = prepare_standard_scan_kwargs(enable_vuln_check, enable_shodan,
                                                           enhanced_mode, scan_type, custom_wordlist, port)
                results = enhanced_scan_service(target_ip, port, **scan_kwargs)
                scan_method = 'standard_enhanced'

        # Add scan metadata
        if results:
            results['session_id'] = session_id
            results['enhanced_mode'] = enhanced_mode
            results['scan_method'] = scan_method
            results['enhanced_nmap_used'] = use_enhanced_nmap

            # Log scan completion
            print(f"✅ Scan completed using method: {scan_method}")
            print(f"📊 Status: {results.get('status')}")
            print(f"🛡️ Vulnerabilities found: {len(results.get('vulnerabilities', []))}")

        # Enhanced results processing and database saving
        if results and (results.get('status') == 'completed' or 'vulnerabilities' in results):
            try:
                save_active_scan_results(session_id, target_ip, port, results, scan_start_time)
                print(f"💾 Results saved to database successfully")
            except Exception as db_error:
                print(f"⚠️ Database save error: {db_error}")
        else:
            print(f"⚠️ Scan failed or incomplete - updating session status")
            db.execute_query("UPDATE sessions SET status = 'failed' WHERE id = %s", (session_id,))

        return jsonify(results)

    except Exception as e:
        print(f"❌ Enhanced active scan error: {str(e)}")
        print(f"📍 Error traceback: {traceback.format_exc()}")
        if 'session_id' in locals():
            try:
                db.execute_query("UPDATE sessions SET status = 'failed' WHERE id = %s", (session_id,))
            except:
                pass
        return jsonify({'error': f'Enhanced active scan failed: {str(e)}'}), 500


@app.route('/api/active-scan-aggressive', methods=['POST'])
def active_scan_aggressive():
    """Aggressive active scanning endpoint with complete HTTP support"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        target_ip = data.get('targetIP')
        target_port = data.get('targetPort')
        scan_type = data.get('scanType', 'auto')
        skip_dns = data.get('skipDnsAnalysis', False)
        normal_scan_results = data.get('normal_scan_results')  # For passing previous results

        scan_start_time = time.time()

        print(f"⚡ Aggressive scan request for {target_ip}:{target_port}")
        print(f"🎯 Scan type: {scan_type}, Skip DNS: {skip_dns}")

        # Validation
        if not target_ip or not target_port:
            return jsonify({'error': 'Target IP and port are required'}), 400

        try:
            import ipaddress
            ipaddress.ip_address(target_ip)
            port = int(target_port)
            if port < 1 or port > 65535:
                raise ValueError("Invalid port range")
        except ValueError as e:
            return jsonify({'error': str(e)}), 400

        # Enhanced port support check for aggressive scanning - NOW INCLUDES HTTP AND HTTPS
        aggressive_supported_ports = [21, 22, 25, 80, 139, 161, 443, 445, 465, 587, 2525, 990, 2121, 8000, 8021, 8080,
                                      8443, 9443]
        if port not in aggressive_supported_ports:
            return jsonify({
                'error': f'Aggressive scanning not supported for port {port}',
                'supported_ports': aggressive_supported_ports,
                'note': 'HTTP and HTTPS aggressive scanning now available with comprehensive web vulnerability testing'
            }), 400

        # Check for HTTP-specific aggressive scanning
        if port in [80, 8000] or (port == 8080 and not _check_if_https(target_ip, port)):
            print(f"🌐 HTTP aggressive scan requested - comprehensive web application vulnerability testing")
            try:
                if HTTP_SCANNER_AVAILABLE:
                    http_scanner = HTTPScanner()

                    # Run aggressive HTTP scan
                    results = http_scanner.scan_aggressive(target_ip, port, normal_scan_results=normal_scan_results)

                    # Add comprehensive metadata for aggressive HTTP scan
                    results.update({
                        'scan_mode': 'aggressive',
                        'service_type': 'http',
                        'protocol': 'TCP',
                        'target': f"{target_ip}:{port}",
                        'aggressive_features_used': [
                            'Comprehensive web application vulnerability scanning',
                            'Directory and file enumeration',
                            'SQL injection testing',
                            'XSS vulnerability detection',
                            'Security headers analysis',
                            'Server information disclosure testing',
                            'HTTP methods analysis',
                            'Backup file detection',
                            'All nmap http-* scripts'
                        ],
                        'scanner_type': 'HTTP Aggressive',
                        'nmap_aggressive_mode': True
                    })

                    # Log aggressive scan results
                    advanced_findings = results.get('advanced_findings', {})
                    if advanced_findings.get('web_analysis'):
                        web_analysis = advanced_findings['web_analysis']
                        if web_analysis.get('directories_found'):
                            print(f"🌐 HTTP web enumeration found directories/files")
                        if web_analysis.get('security_headers'):
                            print(f"🛡️ HTTP security headers analysis completed")

                    vulnerabilities = results.get('vulnerabilities', [])
                    if vulnerabilities:
                        critical_count = len([v for v in vulnerabilities if v.get('severity') == 'Critical'])
                        high_count = len([v for v in vulnerabilities if v.get('severity') == 'High'])
                        print(
                            f"🚨 HTTP aggressive scan found {len(vulnerabilities)} issues: {critical_count} critical, {high_count} high")

                    print(f"✅ HTTP aggressive scan completed")
                    return jsonify(results)
                else:
                    raise ImportError("HTTP scanner not available")

            except ImportError:
                print(f"⚠️ HTTP scanner not available, falling back to standard method")
                return jsonify({'error': 'HTTP aggressive scanning not available - HTTP scanner not found'}), 500
            except Exception as http_error:
                print(f"❌ HTTP aggressive scan failed: {http_error}")
                return jsonify({'error': f'HTTP aggressive scan failed: {str(http_error)}'}), 500

        # Check for HTTPS-specific aggressive scanning
        elif port in [443, 8443, 9443] or (port == 8080 and _check_if_https(target_ip, port)):
            print(f"🔒 HTTPS aggressive scan requested - comprehensive SSL/TLS + web vulnerability testing")
            try:
                from services.https_scanner import HTTPSScanner
                https_scanner = HTTPSScanner()

                # Run aggressive HTTPS scan
                results = https_scanner.scan_aggressive(target_ip, port, normal_scan_results=normal_scan_results)

                # Add comprehensive metadata for aggressive HTTPS scan
                results.update({
                    'scan_mode': 'aggressive',
                    'service_type': 'https',
                    'protocol': 'TCP',
                    'target': f"{target_ip}:{port}",
                    'aggressive_features_used': [
                        'Comprehensive SSL/TLS security analysis',
                        'Web vulnerability scanning (sql-injection, xss, etc.)',
                        'Directory and file enumeration',
                        'SSL cipher suite analysis',
                        'Certificate security assessment',
                        'Security headers analysis',
                        'Backup file detection',
                        'All nmap ssl-* and http-* scripts'
                    ],
                    'scanner_type': 'HTTPS Aggressive',
                    'nmap_aggressive_mode': True
                })

                # Log aggressive scan results
                advanced_findings = results.get('advanced_findings', {})
                if advanced_findings.get('ssl_analysis'):
                    print(f"🔒 HTTPS aggressive scan found SSL/TLS security issues")

                if advanced_findings.get('web_analysis'):
                    web_analysis = advanced_findings['web_analysis']
                    if web_analysis.get('directories_found'):
                        print(f"🌐 HTTPS web enumeration found directories/files")
                    if web_analysis.get('security_headers'):
                        print(f"🛡️ HTTPS security headers analysis completed")

                vulnerabilities = results.get('vulnerabilities', [])
                if vulnerabilities:
                    critical_count = len([v for v in vulnerabilities if v.get('severity') == 'Critical'])
                    high_count = len([v for v in vulnerabilities if v.get('severity') == 'High'])
                    print(
                        f"🚨 HTTPS aggressive scan found {len(vulnerabilities)} issues: {critical_count} critical, {high_count} high")

                print(f"✅ HTTPS aggressive scan completed")
                return jsonify(results)

            except Exception as https_error:
                print(f"❌ HTTPS aggressive scan failed: {https_error}")
                return jsonify({'error': f'HTTPS aggressive scan failed: {str(https_error)}'}), 500

        # Check for SNMP-specific aggressive scanning
        elif port == 161 and SNMP_SCANNER_AVAILABLE:
            print(f"📡 SNMP aggressive scan requested - community string brute force + enumeration")
            try:
                snmp_scanner = SNMPScanner()
                results = snmp_scanner.scan_aggressive(target_ip, port)

                # Add comprehensive metadata for aggressive SNMP scan
                results.update({
                    'scan_mode': 'aggressive',
                    'service_type': 'snmp',
                    'protocol': 'UDP',
                    'target': f"{target_ip}:{port}",
                    'aggressive_features_used': [
                        'SNMP community string brute force',
                        'System information enumeration',
                        'Windows service and user enumeration',
                        'Network interface discovery',
                        'Process enumeration',
                        'Comprehensive NSE script execution'
                    ],
                    'scanner_type': 'SNMP Aggressive',
                    'nmap_aggressive_mode': True
                })

                # Log aggressive scan results
                advanced_findings = results.get('advanced_findings', {})
                if advanced_findings.get('brute_force_results', {}).get('success'):
                    communities_found = advanced_findings['brute_force_results'].get('communities_found', [])
                    print(f"🚨 SNMP aggressive scan found {len(communities_found)} community strings!")

                if advanced_findings.get('windows_enumeration'):
                    windows_enum = advanced_findings['windows_enumeration']
                    users_count = len(windows_enum.get('users', []))
                    services_count = len(windows_enum.get('services', []))
                    print(f"🪟 SNMP Windows enumeration: {users_count} users, {services_count} services")

                print(f"✅ SNMP aggressive scan completed")
                return jsonify(results)

            except Exception as snmp_error:
                print(f"❌ SNMP aggressive scan failed: {snmp_error}")
                return jsonify({'error': f'SNMP aggressive scan failed: {str(snmp_error)}'}), 500

        # Perform standard aggressive scan for other ports using scanner manager
        else:
            print(f"🚀 Calling scan_service_aggressive for non-HTTP/non-HTTPS/non-SNMP port...")
            results = scan_service_aggressive(
                target_ip,
                port,
                scan_type=scan_type,
                skip_dns_analysis=skip_dns
            )

            print(f"📥 Aggressive scan results received")

            # Enhanced results processing for different services
            if port in [139, 445] and results.get('advanced_findings'):
                print(f"🏢 SMB aggressive scan results processing...")
                smb_findings = results['advanced_findings']

                # Check for SMB-specific attack results
                if 'null_session_results' in smb_findings:
                    print(f"🔍 SMB null session attack results found")
                if 'eternalblue_results' in smb_findings:
                    print(f"💥 SMB EternalBlue test results found")
                if 'password_attack_results' in smb_findings:
                    print(f"🔐 SMB password attack results found")

            elif port in [25, 465, 587, 2525] and results.get('advanced_findings'):
                print(f"📧 SMTP aggressive scan results processing...")
                smtp_findings = results['advanced_findings']

                # Check for SMTP-specific attack results
                if 'password_attacks' in smtp_findings:
                    print(f"🔐 SMTP password attack results found")
                if 'user_enumeration' in smtp_findings:
                    print(f"👥 SMTP user enumeration results found")

            elif port in [21, 990, 2121, 8021] and results.get('advanced_findings'):
                print(f"📁 FTP aggressive scan results processing...")
                # FTP aggressive processing would go here

        if results.get('status') == 'error':
            return jsonify(results), 500

        return jsonify(results)

    except Exception as e:
        print(f"❌ Aggressive scan error: {str(e)}")
        import traceback
        print(f"📍 Error traceback: {traceback.format_exc()}")
        return jsonify({'error': f'Aggressive scan failed: {str(e)}'}), 500


def prepare_standard_scan_kwargs(enable_vuln_check, enable_shodan, enhanced_mode, scan_type, custom_wordlist, port):
    """Prepare scan parameters for standard enhanced scanner with HTTP support"""
    scan_kwargs = {
        'enable_vuln_check': False,
        'vulners_api_key': VULNERS_API_KEY,
        'enable_shodan': False,
        'use_pre_scan': enhanced_mode,
        'shodan_api_key': None,
        'service_type': scan_type,
        'use_individual_nmap': True,
        'nmap_fallback': True
    }

    # Add custom wordlist for HTTP/HTTPS services
    if custom_wordlist and port in [80, 443, 8000, 8080, 8443, 9443]:
        wordlist_lines = custom_wordlist.strip().split('\n')
        wordlist_paths = [line.strip() for line in wordlist_lines if line.strip()]
        scan_kwargs['custom_wordlist'] = wordlist_paths
        print(f"📝 Custom wordlist: {len(wordlist_paths)} paths")

    # Add HTTP-specific parameters for HTTP ports
    if port in [80, 8000] or (port == 8080 and not _check_if_https_simple(port)):
        scan_kwargs.update({
            'test_web_security': True,
            'analyze_headers': True,
            'test_http_methods': True,
            'http_nmap_integration': True,
            'security_headers_check': True,
            'directory_enumeration': enhanced_mode,
            'protocol': 'TCP'
        })
        print(f"🌐 HTTP-specific parameters added (TCP protocol)")

    # Add HTTPS-specific parameters for HTTPS ports
    elif port in [443, 8443, 9443] or (port == 8080 and _check_if_https_simple(port)):
        scan_kwargs.update({
            'test_ssl_security': True,
            'analyze_certificate': True,
            'test_web_security': enhanced_mode,
            'https_nmap_integration': True,
            'ssl_cipher_analysis': enhanced_mode,
            'security_headers_check': True,
            'protocol': 'TCP'
        })
        print(f"🔒 HTTPS-specific parameters added (TCP protocol)")

    # Add FTP-specific parameters for FTP ports
    if port in [21, 990, 2121, 8021]:
        scan_kwargs.update({
            'test_anonymous': True,
            'test_directory_traversal': True,
            'test_bounce_attack': True,
            'ftp_nmap_integration': True
        })
        print(f"📁 FTP-specific parameters added")

    # Add SMB-specific parameters for SMB ports
    if port in [139, 445]:
        scan_kwargs.update({
            'test_null_session': True,
            'test_shares': True,
            'test_vulnerabilities': True,
            'smb_wsl_integration': True,
            'enable_aggressive_mode': True
        })
        print(f"🏢 SMB-specific parameters added")

    # Add SNMP-specific parameters for SNMP ports
    if port in [161]:
        scan_kwargs.update({
            'test_community_strings': True,
            'enumerate_system_info': True,
            'snmp_nmap_integration': True,
            'enable_snmp_brute_force': enhanced_mode,
            'protocol': 'UDP',
            'snmp_community_wordlist': [
                'public', 'private', 'community', 'snmp', 'read', 'write',
                'admin', 'manager', 'cisco', 'password', '123456', 'default'
            ]
        })
        print(f"📡 SNMP-specific parameters added (UDP protocol)")

    return scan_kwargs


def _check_if_https_simple(port: int) -> bool:
    """Simple check for HTTPS based on common port patterns"""
    # Port 8080 can be either HTTP or HTTPS, default to HTTP unless proven otherwise
    if port == 8080:
        return False
    return port in [443, 8443, 9443]


def process_http_scan_results(scan_results: Dict[str, Any], session_id: str, target_ip: str, port: int,
                              intensity: str) -> Dict[str, Any]:
    """Process HTTP scanner results for API response"""

    # Create standardized response structure
    results = {
        'target': f"{target_ip}:{port}",
        'ip': target_ip,
        'port': port,
        'service_type': 'http',
        'service_name': 'HTTP',
        'status': scan_results.get('status', 'completed'),
        'scan_time': scan_results.get('scan_time', time.strftime('%Y-%m-%d %H:%M:%S UTC')),
        'scan_duration': scan_results.get('scan_duration', 0),
        'session_id': session_id,
        'scanner_type': 'HTTP Enhanced',
        'http_scan_intensity': intensity,
        'protocol': 'TCP'
    }

    # Copy service information
    if scan_results.get('service_info'):
        results['service_info'] = scan_results['service_info'].copy()

        # Ensure basic fields are present
        results['service_info']['service_name'] = 'HTTP'
        results['service_info']['accessible'] = scan_results.get('connectivity_info', {}).get('accessible', True)

        # Add response time from connectivity check
        if scan_results.get('connectivity_info', {}).get('response_time'):
            results['service_info']['response_time_ms'] = scan_results['connectivity_info']['response_time']

    # Copy banner information
    results['banner'] = scan_results.get('banner', '')

    # Copy vulnerabilities
    results['vulnerabilities'] = scan_results.get('vulnerabilities', [])

    # Copy recommendations
    results['recommendations'] = scan_results.get('recommendations', [])

    # Copy advanced findings
    results['advanced_findings'] = scan_results.get('advanced_findings', {})

    # Copy nmap data if available
    if scan_results.get('nmap_data'):
        results['nmap_data'] = scan_results['nmap_data']
        results['nmap_enhanced'] = not scan_results['nmap_data'].get('error')
    else:
        results['nmap_enhanced'] = False

    # Add HTTP-specific metadata
    results['http_features_used'] = [
        f'Web Application Security Analysis ({intensity} mode)',
        'HTTP Headers Analysis',
        'Server Information Detection',
        'HTTP Methods Testing'
    ]

    if intensity == 'aggressive':
        results['http_features_used'].extend([
            'Comprehensive Web Vulnerability Scanning',
            'Directory and File Enumeration',
            'SQL Injection Testing',
            'XSS Vulnerability Detection',
            'Security Headers Analysis',
            'Backup File Detection',
            'All nmap http-* scripts'
        ])
    else:
        results['http_features_used'].extend([
            'Safe Web Application Security Check',
            'Basic Server Analysis',
            'Security Headers Check',
            'Safe nmap scripts only'
        ])

    # Copy steps completed
    results['steps_completed'] = scan_results.get('steps_completed', [])

    # Calculate scan summary
    vulnerabilities = results.get('vulnerabilities', [])
    critical_count = len([v for v in vulnerabilities if v.get('severity') == 'Critical'])
    high_count = len([v for v in vulnerabilities if v.get('severity') == 'High'])

    results['scan_summary'] = {
        'total_vulnerabilities': len(vulnerabilities),
        'critical_vulnerabilities': critical_count,
        'high_vulnerabilities': high_count,
        'scan_intensity': intensity,
        'web_analysis_completed': bool(scan_results.get('advanced_findings', {}).get('web_analysis')),
        'server_analysis_completed': bool(scan_results.get('advanced_findings', {}).get('server_analysis'))
    }

    return results


def _check_if_https(ip: str, port: int) -> bool:
    """Quick check to determine if a port is running HTTPS"""
    try:
        import ssl
        import socket

        # Try SSL connection
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=5) as sock:
            with context.wrap_socket(sock) as ssock:
                return True  # SSL handshake successful
    except:
        return False  # Not HTTPS or connection failed


def process_https_scan_results(scan_results: Dict[str, Any], session_id: str, target_ip: str, port: int,
                               intensity: str) -> Dict[str, Any]:
    """Process HTTPS scanner results for API response"""

    # Create standardized response structure
    results = {
        'target': f"{target_ip}:{port}",
        'ip': target_ip,
        'port': port,
        'service_type': 'https',
        'service_name': 'HTTPS',
        'status': scan_results.get('status', 'completed'),
        'scan_time': scan_results.get('scan_time', time.strftime('%Y-%m-%d %H:%M:%S UTC')),
        'scan_duration': scan_results.get('scan_duration', 0),
        'session_id': session_id,
        'scanner_type': 'HTTPS Enhanced',
        'https_scan_intensity': intensity,
        'protocol': 'TCP'
    }

    # Copy service information
    if scan_results.get('service_info'):
        results['service_info'] = scan_results['service_info'].copy()

        # Ensure basic fields are present
        results['service_info']['service_name'] = 'HTTPS'
        results['service_info']['accessible'] = scan_results.get('connectivity_info', {}).get('accessible', True)

        # Add response time from connectivity check
        if scan_results.get('connectivity_info', {}).get('response_time'):
            results['service_info']['response_time_ms'] = scan_results['connectivity_info']['response_time']

    # Copy banner information
    results['banner'] = scan_results.get('banner', '')

    # Copy vulnerabilities
    results['vulnerabilities'] = scan_results.get('vulnerabilities', [])

    # Copy recommendations
    results['recommendations'] = scan_results.get('recommendations', [])

    # Copy advanced findings
    results['advanced_findings'] = scan_results.get('advanced_findings', {})

    # Copy nmap data if available
    if scan_results.get('nmap_data'):
        results['nmap_data'] = scan_results['nmap_data']
        results['nmap_enhanced'] = not scan_results['nmap_data'].get('error')
    else:
        results['nmap_enhanced'] = False

    # Add HTTPS-specific metadata
    results['https_features_used'] = [
        f'SSL/TLS Security Analysis ({intensity} mode)',
        'Certificate Validity Check',
        'SSL Handshake Analysis'
    ]

    if intensity == 'aggressive':
        results['https_features_used'].extend([
            'Comprehensive Web Vulnerability Scanning',
            'Directory and File Enumeration',
            'SSL Cipher Suite Analysis',
            'Security Headers Analysis',
            'All nmap ssl-* and http-* scripts'
        ])
    else:
        results['https_features_used'].extend([
            'Safe SSL/TLS Security Check',
            'Basic Certificate Analysis',
            'Safe nmap scripts only'
        ])

    # Copy steps completed
    results['steps_completed'] = scan_results.get('steps_completed', [])

    # Calculate scan summary
    vulnerabilities = results.get('vulnerabilities', [])
    critical_count = len([v for v in vulnerabilities if v.get('severity') == 'Critical'])
    high_count = len([v for v in vulnerabilities if v.get('severity') == 'High'])

    results['scan_summary'] = {
        'total_vulnerabilities': len(vulnerabilities),
        'critical_vulnerabilities': critical_count,
        'high_vulnerabilities': high_count,
        'scan_intensity': intensity,
        'ssl_analysis_completed': bool(scan_results.get('advanced_findings', {}).get('ssl_analysis')),
        'web_analysis_completed': bool(scan_results.get('advanced_findings', {}).get('web_analysis'))
    }

    return results


def handle_http_scanning(data, target_ip, port, session_id, enhanced_mode, enable_vuln_check, enable_shodan, scan_type,
                         custom_wordlist):
    """Handle HTTP scanning logic"""
    try:
        # HTTP-specific scanning logic (port 80, 8000, 8080 for HTTP)
        if port in [80, 8000] or (port == 8080 and not _check_if_https(target_ip, port)):
            print(f"🌐 HTTP port detected - using dedicated HTTP scanner")

            if HTTP_SCANNER_AVAILABLE:
                http_scanner = HTTPScanner()

                # Determine HTTP scan intensity
                http_intensity = data.get('httpScanIntensity', 'normal')

                if http_intensity == 'aggressive':
                    print(f"🎯 Running aggressive HTTP scan with all scripts")
                    scan_results = http_scanner.scan_aggressive(target_ip, port)
                else:
                    print(f"🌐 Running normal HTTP scan (safe mode)")
                    scan_results = http_scanner.scan(target_ip, port)

                # Process HTTP results
                results = process_http_scan_results(scan_results, session_id, target_ip, port, http_intensity)
                scan_method = f'http_scanner_{http_intensity}'
                print(f"✅ HTTP scan completed successfully")
                return results, scan_method
            else:
                raise ImportError("HTTP scanner not available")

        # Port 8080 detection - could be HTTP or HTTPS
        elif port == 8080:
            print(f"🔄 Port 8080 detected - determining HTTP vs HTTPS")

            is_https = _check_if_https(target_ip, port)

            if not is_https:  # It's HTTP
                print(f"🌐 Port 8080 is HTTP - using HTTP scanner")

                if HTTP_SCANNER_AVAILABLE:
                    http_scanner = HTTPScanner()
                    http_intensity = data.get('httpScanIntensity', 'normal')

                    if http_intensity == 'aggressive':
                        scan_results = http_scanner.scan_aggressive(target_ip, port)
                    else:
                        scan_results = http_scanner.scan(target_ip, port)

                    results = process_http_scan_results(scan_results, session_id, target_ip, port, http_intensity)
                    scan_method = f'http_scanner_{http_intensity}'
                    return results, scan_method
                else:
                    raise ImportError("HTTP scanner not available")
            else:
                # Handle as HTTPS (you'd need HTTPS scanner logic here)
                print(f"🔒 Port 8080 is HTTPS - would use HTTPS scanner")
                raise Exception("HTTPS handling needed")

        # If we get here, it's not an HTTP port we handle
        return None, None

    except ImportError:
        print(f"⚠️ HTTP scanner not available, using standard method")
        scan_kwargs = prepare_standard_scan_kwargs(enable_vuln_check, enable_shodan,
                                                   enhanced_mode, scan_type, custom_wordlist, port)
        results = enhanced_scan_service(target_ip, port, **scan_kwargs)
        scan_method = 'standard_enhanced_fallback'
        return results, scan_method
    except Exception as http_error:
        print(f"❌ HTTP scanner failed: {http_error}")
        scan_kwargs = prepare_standard_scan_kwargs(enable_vuln_check, enable_shodan,
                                                   enhanced_mode, scan_type, custom_wordlist, port)
        results = enhanced_scan_service(target_ip, port, **scan_kwargs)
        scan_method = 'standard_enhanced_fallback'
        return results, scan_method


@app.route('/api/validate-http-target', methods=['POST'])
def validate_http_target_endpoint():
    """Validate HTTP target and provide recommendations"""
    try:
        data = request.get_json()
        target = data.get('target')
        port = data.get('port', 80)

        if not target:
            return jsonify({'error': 'Target is required'}), 400

        # Try to use HTTP-specific validation if available
        try:
            if HTTP_SCANNER_AVAILABLE:
                http_scanner = HTTPScanner()

                # Basic HTTP connectivity test
                connectivity = http_scanner._check_http_connectivity(target, port)

                validation = {
                    'valid': True,
                    'target': target,
                    'port': port,
                    'service_type': 'http',
                    'protocol': 'TCP',
                    'http_specific': True,
                    'http_enhanced_available': True,
                    'connectivity_test': connectivity,
                    'scan_modes': ['normal', 'aggressive'],
                    'aggressive_features': [
                        'Comprehensive web application vulnerability scanning',
                        'Directory and file enumeration',
                        'SQL injection testing',
                        'XSS vulnerability detection',
                        'Security headers analysis',
                        'Server information disclosure testing',
                        'HTTP methods analysis',
                        'Backup file detection'
                    ],
                    'normal_features': [
                        'Safe web application security check',
                        'Basic server analysis',
                        'HTTP headers analysis',
                        'Safe security checks only'
                    ],
                    'recommendations': [
                        'HTTP scans test web application security and server configuration',
                        'Normal mode performs safe security checks without intrusive testing',
                        'Aggressive mode includes comprehensive vulnerability testing and enumeration',
                        'Ensure you have authorization before running aggressive scans',
                        'HTTP scans may trigger web application firewalls (WAF)',
                        'Consider using HTTPS instead of HTTP for sensitive applications'
                    ]
                }

                if connectivity.get('accessible'):
                    validation['status'] = 'HTTP service appears to be running and accessible'
                    validation['http_response_successful'] = connectivity.get('http_response_successful', False)
                    validation['status_code'] = connectivity.get('status_code')
                    validation['server_header'] = connectivity.get('server_header')

                    if connectivity.get('http_response_successful'):
                        validation['recommendations'].append('HTTP service responding - ready for web security testing')
                        if connectivity.get('status_code') == 200:
                            validation['recommendations'].append(
                                'HTTP 200 OK response - web application appears to be running')
                    else:
                        validation['recommendations'].append(
                            'HTTP service not responding properly - verify web server configuration')
                else:
                    validation['status'] = 'HTTP service may not be accessible'
                    validation['recommendations'].append('Verify HTTP service is running and accessible')
                    validation['recommendations'].append('Check firewall rules and network connectivity')

                return jsonify(validation)
            else:
                raise ImportError("HTTP scanner not available")

        except Exception as http_error:
            print(f"HTTP validation error: {http_error}")

        # Fallback to basic validation
        validation = validate_scan_target(target, 'ip')
        validation.update({
            'http_specific': False,
            'http_enhanced_available': False,
            'port': port,
            'service_type': 'http',
            'protocol': 'TCP'
        })
        validation['recommendations'].append('Basic HTTP validation only - enhanced features may be limited')
        return jsonify(validation)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/validate-https-target', methods=['POST'])
def validate_https_target_endpoint():
    """Validate HTTPS target and provide recommendations"""
    try:
        data = request.get_json()
        target = data.get('target')
        port = data.get('port', 443)

        if not target:
            return jsonify({'error': 'Target is required'}), 400

        # Try to use HTTPS-specific validation if available
        try:
            from services.https_scanner import HTTPSScanner
            https_scanner = HTTPSScanner()

            # Basic HTTPS connectivity test
            connectivity = https_scanner._check_https_connectivity(target, port)

            validation = {
                'valid': True,
                'target': target,
                'port': port,
                'service_type': 'https',
                'protocol': 'TCP',
                'https_specific': True,
                'https_enhanced_available': True,
                'connectivity_test': connectivity,
                'scan_modes': ['normal', 'aggressive'],
                'aggressive_features': [
                    'Comprehensive SSL/TLS vulnerability testing',
                    'Web application security scanning',
                    'Directory and file enumeration',
                    'SSL cipher suite analysis',
                    'Certificate security assessment',
                    'Security headers analysis',
                    'Backup file detection',
                    'SQL injection testing',
                    'XSS vulnerability detection'
                ],
                'normal_features': [
                    'Safe SSL/TLS security check',
                    'Basic certificate analysis',
                    'SSL handshake verification',
                    'Security headers check',
                    'Safe nmap scripts only'
                ],
                'recommendations': [
                    'HTTPS scans test SSL/TLS security and web application vulnerabilities',
                    'Normal mode performs safe security checks without intrusive testing',
                    'Aggressive mode includes comprehensive vulnerability testing and enumeration',
                    'Ensure you have authorization before running aggressive scans',
                    'HTTPS scans may trigger web application firewalls (WAF)',
                    'Consider testing during maintenance windows for aggressive scans'
                ]
            }

            if connectivity.get('accessible'):
                validation['status'] = 'HTTPS service appears to be running and accessible'
                validation['ssl_handshake_successful'] = connectivity.get('ssl_handshake_successful', False)
                validation['ssl_version'] = connectivity.get('ssl_version')
                validation['cipher_suite'] = connectivity.get('cipher_suite')

                if connectivity.get('ssl_handshake_successful'):
                    validation['recommendations'].append('SSL/TLS handshake successful - ready for security testing')
                else:
                    validation['recommendations'].append('SSL/TLS handshake failed - verify SSL configuration')
            else:
                validation['status'] = 'HTTPS service may not be accessible'
                validation['recommendations'].append('Verify HTTPS service is running and accessible')
                validation['recommendations'].append('Check firewall rules and network connectivity')

            return jsonify(validation)

        except Exception as https_error:
            print(f"HTTPS validation error: {https_error}")

        # Fallback to basic validation
        validation = validate_scan_target(target, 'ip')
        validation.update({
            'https_specific': False,
            'https_enhanced_available': False,
            'port': port,
            'service_type': 'https',
            'protocol': 'TCP'
        })
        validation['recommendations'].append('Basic HTTPS validation only - enhanced features may be limited')
        return jsonify(validation)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# SNMP validation endpoint
@app.route('/api/validate-snmp-target', methods=['POST'])
def validate_snmp_target_endpoint():
    """Validate SNMP target and provide recommendations"""
    try:
        data = request.get_json()
        target = data.get('target')
        port = data.get('port', 161)

        if not target:
            return jsonify({'error': 'Target is required'}), 400

        # Try to use SNMP-specific validation if available
        if SNMP_SCANNER_AVAILABLE:
            try:
                snmp_scanner = SNMPScanner()
                # Basic UDP connectivity test
                connectivity = snmp_scanner._check_udp_connectivity(target, port)

                validation = {
                    'valid': True,
                    'target': target,
                    'port': port,
                    'service_type': 'snmp',
                    'protocol': 'UDP',
                    'snmp_specific': True,
                    'snmp_enhanced_available': True,
                    'connectivity_test': connectivity,
                    'aggressive_features': [
                        'Community string brute force',
                        'System information enumeration',
                        'Windows service and user enumeration',
                        'Network interface discovery',
                        'Process enumeration'
                    ],
                    'recommendations': [
                        'SNMP scans use UDP protocol - ensure firewall allows UDP traffic on port 161',
                        'Community strings will be tested - ensure authorization for security testing',
                        'Aggressive mode includes brute force attacks on community strings',
                        'Normal mode performs safe information gathering only',
                        'SNMP enumeration may reveal sensitive system information',
                        'Consider testing SNMPv1, SNMPv2c, and SNMPv3 if available'
                    ]
                }

                if connectivity.get('accessible'):
                    validation['status'] = 'SNMP service appears to be running and accessible'
                    validation['snmp_response_detected'] = True
                else:
                    validation['status'] = 'SNMP service may not be accessible or filtered'
                    validation['recommendations'].append('Verify SNMP service is running and UDP 161 is accessible')
                    validation['recommendations'].append('Check for firewall rules blocking UDP traffic')

                return jsonify(validation)

            except Exception as snmp_error:
                print(f"SNMP validation error: {snmp_error}")

        # Fallback to basic validation
        validation = validate_scan_target(target, 'ip')
        validation.update({
            'snmp_specific': False,
            'snmp_enhanced_available': SNMP_SCANNER_AVAILABLE,
            'port': port,
            'service_type': 'snmp',
            'protocol': 'UDP'
        })
        validation['recommendations'].append('Basic SNMP validation only - enhanced features may be limited')
        return jsonify(validation)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/validate-smb-target', methods=['POST'])
def validate_smb_target_endpoint():
    """Validate SMB target and provide recommendations"""
    try:
        data = request.get_json()
        target = data.get('target')
        port = data.get('port', 445)

        if not target:
            return jsonify({'error': 'Target is required'}), 400

        # Try to import SMB validation function
        try:
            from services import validate_smb_target
            validation = validate_smb_target(target, port)
            validation['smb_specific'] = True
            validation['smb_enhanced_available'] = True
            return jsonify(validation)
        except ImportError:
            # Fallback to basic validation
            validation = validate_scan_target(target, 'ip')
            validation['smb_specific'] = False
            validation['smb_enhanced_available'] = False
            validation['port'] = port
            validation['service_type'] = 'smb'
            validation['recommendations'].append('Basic SMB validation only - enhanced features unavailable')
            return jsonify(validation)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


def save_active_scan_results(session_id, target_ip, port, results, scan_start_time):
    """Enhanced function to save active scan results with proper vulnerability handling"""
    try:
        # Save basic service data
        service_info = results.get('service_info', {})
        service_data = {
            'ip': target_ip,
            'port': port,
            'protocol': 'tcp',
            'service': results.get('service_name', results.get('service', 'unknown')),
            'version': service_info.get('version', '') or results.get('version', ''),
            'banner': results.get('banner', ''),
            'state': 'open' if service_info.get('accessible', True) else 'closed'
        }
        db.save_discovered_service(session_id, service_data)

        # Enhanced vulnerability processing
        vulnerabilities = results.get('vulnerabilities', [])
        cve_vulns = results.get('cve_vulnerabilities', [])  # From CVE analysis

        cve_count = 0
        exploit_count = 0
        nse_findings = 0
        regular_vulns = 0

        # Process vulnerabilities from main list
        for vuln in vulnerabilities:
            vuln_source = vuln.get('source', '').lower()
            detection_method = vuln.get('detection_method', '').lower()

            if vuln.get('type') == 'cve_vulnerability' or 'vulners' in vuln_source or 'cve' in vuln_source:
                # CVE vulnerability
                enhanced_vuln = enhance_vulnerability_with_urls(vuln)
                db.save_cve_vulnerability(session_id, enhanced_vuln)
                cve_count += 1
            elif 'searchsploit' in vuln_source or 'exploit-db' in vuln_source:
                # Exploit database finding
                enhanced_vuln = enhance_vulnerability_with_urls(vuln)
                db.save_cve_vulnerability(session_id, enhanced_vuln)  # Save as CVE for unified display
                exploit_count += 1
            elif 'nmap' in vuln_source or 'nse' in detection_method:
                # NSE script findings
                save_vulnerability(session_id, vuln)
                nse_findings += 1
            else:
                # Regular scanner finding
                save_vulnerability(session_id, vuln)
                regular_vulns += 1

        # Process CVE vulnerabilities from analysis
        for cve_vuln in cve_vulns:
            enhanced_cve = enhance_vulnerability_with_urls(cve_vuln)
            db.save_cve_vulnerability(session_id, enhanced_cve)
            cve_count += 1

        # Save detected software if available
        software_count = 0
        cve_analysis = results.get('cve_analysis', {})
        if cve_analysis and cve_analysis.get('detected_software'):
            for software in cve_analysis['detected_software']:
                db.save_detected_software(session_id, software)
                software_count += 1

        # Complete session with enhanced statistics
        scan_duration = int(time.time() - scan_start_time)
        all_vulns = vulnerabilities + cve_vulns
        highest_cvss = max([v.get('cvss_score', 0) for v in all_vulns if v.get('cvss_score')], default=0)

        summary_data = {
            'duration': scan_duration,
            'total_ports': 1,
            'open_ports': 1 if service_data['state'] == 'open' else 0,
            'vulnerabilities': len(all_vulns),
            'cve_vulnerabilities_found': cve_count,
            'regular_vulnerabilities_found': regular_vulns,
            'nse_findings': nse_findings,
            'exploit_findings': exploit_count,
            'software_detected': software_count,
            'highest_cvss_score': highest_cvss,
            'enhanced_nmap_used': results.get('enhanced_nmap_used', False),
            'individual_nmap_used': results.get('nmap_enhanced', False),
            'scan_method': results.get('scan_method', 'unknown'),
            'scanner_type': results.get('service_name', 'unknown')
        }

        db.complete_session(session_id, summary_data)

        print(f"📊 Enhanced session statistics:")
        print(f"   🎯 Method: {results.get('scan_method', 'unknown')}")
        print(f"   🛡️ Total vulnerabilities: {len(all_vulns)}")
        print(f"   📋 CVE findings: {cve_count}")
        print(f"   💥 Exploit findings: {exploit_count}")
        print(f"   🎯 NSE findings: {nse_findings}")
        print(f"   🔧 Regular findings: {regular_vulns}")
        print(f"   📦 Software detected: {software_count}")

    except Exception as e:
        print(f"❌ Error saving active scan results: {e}")
        raise


@app.route('/active-scan')
def active_scan_page():
    """Enhanced active scanning page with HTTPS integration status"""
    try:
        # Get integration status for frontend
        integration_status = get_integration_status()
        enhanced_capabilities = get_enhanced_capabilities()
        supported_ports = get_supported_ports()

        # Add HTTPS ports to supported ports
        https_ports = [443, 8443, 8080, 9443]
        all_supported_ports = list(set(supported_ports + https_ports))

        # Check HTTPS scanner availability
        https_available = False
        try:
            from services.https_scanner import HTTPSScanner
            https_available = True
        except ImportError:
            pass

        # Pass enhanced data to template
        template_data = {
            'integration_status': integration_status,
            'enhanced_capabilities': enhanced_capabilities,
            'supported_ports': all_supported_ports,
            'https_ports': https_ports,
            'ftp_ports': [21, 990, 2121, 8021],  # FTP-specific ports
            'smb_ports': [139, 445],  # SMB-specific ports
            'snmp_ports': [161],  # SNMP-specific ports
            'scanner_features': {
                'nmap_available': integration_status.get('integrations', {}).get('individual_scanner_nmap', {}).get(
                    'enabled', False),
                'shodan_available': integration_status.get('integrations', {}).get('shodan_intelligence', {}).get(
                    'enabled', False),
                'vuln_check_available': integration_status.get('integrations', {}).get(
                    'enhanced_vulnerability_checking', {}).get('enabled', False),
                'enhanced_nmap_available': integration_status.get('integrations', {}).get('enhanced_nmap', {}).get(
                    'enabled', False),
                'https_enhanced_available': https_available,
                'ftp_enhanced_available': FTP_SPECIFIC_AVAILABLE,
                'smb_enhanced_available': True,  # Assuming SMB is available
                'snmp_enhanced_available': SNMP_SCANNER_AVAILABLE
            },
            'scan_modes': {
                'https': {
                    'normal': {
                        'name': 'Normal HTTPS Scan',
                        'description': 'Safe SSL/TLS security assessment',
                        'features': [
                            'SSL/TLS handshake verification',
                            'Basic certificate analysis',
                            'Safe security checks',
                            'Security headers analysis'
                        ]
                    },
                    'aggressive': {
                        'name': 'Aggressive HTTPS Scan',
                        'description': 'Comprehensive SSL/TLS + web vulnerability testing',
                        'features': [
                            'Complete SSL/TLS vulnerability testing',
                            'Web application security scanning',
                            'Directory enumeration',
                            'Backup file detection',
                            'SQL injection testing'
                        ]
                    }
                }
            }
        }

        return render_template('active-scan.html', **template_data)

    except Exception as e:
        print(f"❌ Error loading active scan page: {e}")
        return render_template('active-scan.html', error=str(e))


# FTP Validation Endpoint
@app.route('/api/validate-ftp-target', methods=['POST'])
def validate_ftp_target_endpoint():
    """Validate FTP target and provide recommendations"""
    try:
        data = request.get_json()
        target = data.get('target')
        port = data.get('port', 21)

        if not target:
            return jsonify({'error': 'Target is required'}), 400

        if FTP_SPECIFIC_AVAILABLE:
            validation = validate_ftp_target(target, port)
            return jsonify(validation)
        else:
            # Fallback to basic validation
            validation = validate_scan_target(target, 'ip')
            validation['ftp_specific'] = False
            validation['ftp_enhanced_available'] = False
            return jsonify(validation)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Existing routes (keeping all your existing functionality)
@app.route('/api/nmap-scan', methods=['POST'])
def nmap_scan():
    """Dedicated nmap scanning endpoint"""
    try:
        print("🎯 Dedicated nmap scan endpoint called")

        data = request.get_json()
        if not data or 'target' not in data:
            return jsonify({'error': 'No target provided'}), 400

        target = data['target']
        port_range = data.get('port_range', '1-1000')
        enable_vulners = data.get('enable_vulners', True)
        scan_type = data.get('scan_type', 'discovery')
        scan_timing = data.get('scan_timing', 'T3')
        enable_os_detection = data.get('enable_os_detection', False)

        scan_start_time = time.time()

        print(f"🎯 Nmap scan configuration:")
        print(f"   Target: {target}")
        print(f"   Type: {scan_type}")
        print(f"   Port Range: {port_range}")
        print(f"   Vulners: {enable_vulners}")
        print(f"   Timing: {scan_timing}")

        # Create session for nmap scan
        session_data = {
            'name': f"Nmap {scan_type.title()} - {target}",
            'type': 'nmap',
            'target': target,
            'status': 'in_progress'
        }
        session_id = db.create_session(session_data)

        # Check nmap availability
        try:
            from services.nmap_scanner import enhanced_nmap_scanner
            if not enhanced_nmap_scanner or not enhanced_nmap_scanner.available:
                return jsonify({
                    'error': 'Nmap scanner not available',
                    'suggestions': [
                        'Install nmap: sudo apt-get install nmap (Linux) or brew install nmap (macOS)',
                        'Install python-nmap: pip install python-nmap',
                        'Check nmap is in system PATH',
                        'Verify nmap has necessary permissions'
                    ]
                }), 500
        except ImportError:
            return jsonify({
                'error': 'Nmap scanner module not available',
                'suggestions': ['Check nmap_scanner.py installation and dependencies']
            }), 500

        # Perform nmap scan based on type
        if scan_type == 'discovery':
            print(f"🔍 Starting nmap port discovery...")
            nmap_results = enhanced_nmap_scanner.passive_port_discovery(
                target=target,
                port_range=port_range,
                enable_vulners=enable_vulners
            )
        elif scan_type == 'vulnerability':
            port = data.get('port')
            if not port:
                return jsonify({'error': 'Port required for vulnerability scan'}), 400

            print(f"🛡️ Starting nmap vulnerability scan on port {port}...")
            nmap_results = enhanced_nmap_scanner.comprehensive_vulnerability_scan(
                target=target,
                port=int(port),
                service_type=data.get('service_type')
            )
        else:
            return jsonify({'error': 'Invalid scan type. Use "discovery" or "vulnerability"'}), 400

        if 'error' in nmap_results:
            print(f"❌ Nmap scan failed: {nmap_results['error']}")
            db.execute_query("UPDATE sessions SET status = 'failed' WHERE id = %s", (session_id,))
            return jsonify(nmap_results), 500

        # Format results
        scan_duration = time.time() - scan_start_time

        results = {
            'target': target,
            'scan_type': scan_type,
            'port_range': port_range if scan_type == 'discovery' else f"Port {data.get('port', 'N/A')}",
            'vulners_enabled': enable_vulners,
            'timing_used': scan_timing,
            'os_detection_enabled': enable_os_detection,
            'status': 'completed',
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
            'scan_duration': round(scan_duration, 2),
            'session_id': session_id,
            'nmap_results': nmap_results
        }

        # Save results to database
        if scan_type == 'discovery':
            discovered_ports = nmap_results.get('discovered_ports', [])
            vulnerabilities = nmap_results.get('vulnerabilities', [])
            cve_vulnerabilities = nmap_results.get('cve_vulnerabilities', [])

            # Save discovered services
            for port_data in discovered_ports:
                try:
                    db.save_discovered_service(session_id, {
                        'ip': target,
                        'port': port_data['port'],
                        'protocol': port_data['protocol'],
                        'service': port_data['service'],
                        'version': port_data['version'],
                        'banner': port_data['banner'],
                        'state': port_data['state']
                    })
                except Exception as db_error:
                    print(f"⚠️ Failed to save service: {db_error}")

            # Save vulnerabilities
            for vuln in vulnerabilities + cve_vulnerabilities:
                try:
                    if vuln.get('source') == 'vulners_nse':
                        db.save_cve_vulnerability(session_id, vuln)
                    else:
                        save_vulnerability(session_id, vuln)
                except Exception as db_error:
                    print(f"⚠️ Failed to save vulnerability: {db_error}")

        # Complete session
        summary_data = {
            'duration': int(scan_duration),
            'scan_type': scan_type,
            'nmap_used': True,
            'vulners_enabled': enable_vulners,
            'timing_profile': scan_timing,
            'ports_found': len(nmap_results.get('discovered_ports', [])),
            'vulnerabilities_found': len(nmap_results.get('vulnerabilities', [])) + len(
                nmap_results.get('cve_vulnerabilities', []))
        }

        db.complete_session(session_id, summary_data)

        print(f"✅ Nmap {scan_type} scan completed successfully")
        print(f"   Duration: {scan_duration:.1f}s")
        print(f"   Ports found: {summary_data['ports_found']}")
        print(f"   Vulnerabilities: {summary_data['vulnerabilities_found']}")

        return jsonify(results)

    except Exception as e:
        print(f"❌ Nmap scan error: {str(e)}")
        if 'session_id' in locals():
            try:
                db.execute_query("UPDATE sessions SET status = 'failed' WHERE id = %s", (session_id,))
            except:
                pass
        return jsonify({'error': f'Nmap scan failed: {str(e)}'}), 500


@app.route('/api/scan', methods=['POST'])
def passive_scan():
    """Clean passive scanning endpoint focused on discovery only"""
    try:
        print("🚀 Clean passive scan endpoint called")

        data = request.get_json()
        if not data or 'target' not in data:
            print("❌ No target provided in request")
            return jsonify({'error': 'No target provided'}), 400

        raw_target = data['target']
        scan_start_time = time.time()

        print(f"🎯 Target: {raw_target}")

        processed = input_handler.process_input(raw_target)
        if not processed:
            print("❌ Invalid target format")
            return jsonify({'error': 'Invalid target. Please enter a valid domain or IP range.'}), 400

        target = processed['target']
        target_type = processed['type']

        print(f"🔍 Processed target: {target} (type: {target_type})")

        session_data = {
            'name': f"Passive Reconnaissance - {target}",
            'type': 'passive',
            'target': target,
            'status': 'in_progress'
        }
        session_id = db.create_session(session_data)
        print(f"📝 Session created: {session_id}")

        results = {
            'target': target,
            'type': target_type,
            'status': 'completed',
            'ports_services': [],
            'dns_records': {},
            'securitytrails_dns_records': [],
            'subdomains': [],
            'whois_info': {},
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
            'session_id': session_id,
            'discovery_methods': ['netlas', 'shodan'],
            'timeout_issues': [],
            'enhanced_features_used': []
        }

        print(f"🔍 Starting clean passive reconnaissance...")

        # DNS and domain enumeration for domains
        if target_type == 'domain':
            try:
                print(f"🌐 Getting SecurityTrails DNS records for {target}...")
                sec_trails_dns = dns_recon.get_securitytrails_dns_records(target)
                results['securitytrails_dns_records'] = sec_trails_dns
                for record in sec_trails_dns:
                    save_dns_record(session_id, record)
                print(f"✅ Found {len(sec_trails_dns)} DNS records")
                results['enhanced_features_used'].append('SecurityTrails DNS')
            except Exception as dns_error:
                print(f"⚠️ SecurityTrails DNS lookup failed: {dns_error}")
                results['timeout_issues'].append(f"SecurityTrails failed: {dns_error}")

            try:
                print(f"🔗 Finding subdomains for {target}...")
                subdomains = dns_recon.find_subdomains_passive(target)
                results['subdomains'] = subdomains
                for subdomain in subdomains:
                    save_subdomain(session_id, subdomain)
                print(f"✅ Found {len(subdomains)} subdomains")
                results['enhanced_features_used'].append('Certificate Transparency')
            except Exception as subdomain_error:
                print(f"⚠️ Subdomain enumeration failed: {subdomain_error}")
                results['timeout_issues'].append(f"Subdomain enumeration failed: {subdomain_error}")

            try:
                print(f"📋 Getting whois information for {target}...")
                whois_info = whois_lookup.get_whois_info(target)
                results['whois_info'] = whois_info
                if whois_info:
                    save_whois_data(session_id, target, whois_info)
                    print(f"✅ Retrieved whois information")
                results['enhanced_features_used'].append('WHOIS Lookup')
            except Exception as whois_error:
                print(f"⚠️ WHOIS lookup failed: {whois_error}")
                results['timeout_issues'].append(f"WHOIS failed: {whois_error}")

        # Service discovery using intelligence APIs
        try:
            print(f"🌐 Discovering services using intelligence APIs...")

            netlas_results = []
            shodan_results = []

            try:
                netlas_results = netlas_client.search_target(target, target_type)
                print(f"✅ Netlas found {len(netlas_results)} services")
                results['enhanced_features_used'].append('Netlas Intelligence')
            except Exception as netlas_error:
                print(f"⚠️ Netlas search failed: {netlas_error}")
                results['timeout_issues'].append(f"Netlas failed: {netlas_error}")

            try:
                shodan_results = shodan_client.search_target(target, target_type)
                print(f"✅ Shodan found {len(shodan_results)} services")
                results['enhanced_features_used'].append('Shodan Intelligence')
            except Exception as shodan_error:
                print(f"⚠️ Shodan search failed: {shodan_error}")
                results['timeout_issues'].append(f"Shodan failed: {shodan_error}")

            # Combine and clean service data
            all_services = netlas_results + shodan_results

            # Remove duplicates and enhance service data
            unique_services = []
            seen_services = set()

            for service in all_services:
                # Create unique identifier for service
                service_key = f"{service.get('ip', target)}:{service.get('port', 0)}"

                if service_key not in seen_services:
                    seen_services.add(service_key)

                    # Clean and enhance service data
                    clean_service = {
                        'ip': service.get('ip', target),
                        'port': service.get('port'),
                        'protocol': service.get('protocol', 'tcp'),
                        'service': service.get('service', 'unknown'),
                        'version': service.get('version', ''),
                        'banner': service.get('banner', ''),
                        'source': service.get('source', 'Intelligence API'),
                        'state': 'open'
                    }

                    # Only include if we have a valid port
                    if clean_service['port'] and str(clean_service['port']).isdigit():
                        unique_services.append(clean_service)

            results['ports_services'] = unique_services

            # Save services to database
            for service in unique_services:
                try:
                    db.save_discovered_service(session_id, {
                        'ip': service.get('ip'),
                        'port': service.get('port'),
                        'protocol': service.get('protocol', 'tcp'),
                        'service': service.get('service'),
                        'version': service.get('version'),
                        'banner': service.get('banner'),
                        'state': 'open'
                    })
                except Exception as db_error:
                    print(f"⚠️ Failed to save service to DB: {db_error}")

            print(f"✅ Service discovery found {len(unique_services)} unique services")

        except Exception as service_error:
            print(f"❌ Service discovery failed: {service_error}")
            results['timeout_issues'].append(f"Service discovery failed: {service_error}")

        # Calculate final statistics
        scan_duration = int(time.time() - scan_start_time)
        open_ports = len([s for s in results['ports_services'] if s.get('port')])
        supported_ports = len([s for s in results['ports_services']
                               if s.get('port') and int(s.get('port')) in [21, 22, 25, 161, 443, 445, 990]])

        print(f"📊 Clean passive scan statistics:")
        print(f"   ⏱️ Duration: {scan_duration} seconds")
        print(f"   📊 Services found: {open_ports}")
        print(f"   🎯 Active scan ready: {supported_ports}")
        print(f"   🌐 DNS records: {len(results['securitytrails_dns_records'])}")
        print(f"   🔗 Subdomains: {len(results['subdomains'])}")
        print(f"   ✨ Methods used: {', '.join(results['enhanced_features_used'])}")

        summary_data = {
            'duration': scan_duration,
            'total_ports': len(results['ports_services']),
            'open_ports': open_ports,
            'supported_ports': supported_ports,
            'dns_records_found': len(results['securitytrails_dns_records']),
            'subdomains_found': len(results['subdomains']),
            'discovery_methods': results['discovery_methods'],
            'enhanced_features': results['enhanced_features_used'],
            'timeout_issues_count': len(results['timeout_issues']),
            'scan_type': 'passive_discovery'
        }

        # Complete the session
        try:
            db.complete_session(session_id, summary_data)
            print(f"💾 Session {session_id} completed and saved")
        except Exception as db_error:
            print(f"⚠️ Failed to complete session in DB: {db_error}")

        print(f"🎯 Clean passive reconnaissance completed successfully:")
        print(f"   🎯 Target: {target}")
        print(f"   📊 Services: {open_ports}")
        print(f"   🔧 Methods: {', '.join(results['discovery_methods'])}")
        print(f"   ⚡ Active scan ready: {supported_ports} services")

        return jsonify(results)

    except Exception as e:
        print(f"❌ Clean passive scan error: {str(e)}")
        return jsonify({'error': f'Passive reconnaissance failed: {str(e)}'}), 500


@app.route('/api/nmap-discovery', methods=['POST'])
def nmap_discovery_endpoint():
    """Direct nmap discovery endpoint for testing and advanced usage"""
    try:
        data = request.get_json()
        target = data.get('target')
        port_range = data.get('port_range', '1-1000')

        if not target:
            return jsonify({'error': 'Target is required'}), 400

        print(f"🎯 Direct nmap discovery for {target}")

        # Validate target
        validation = validate_scan_target(target, 'ip')
        if not validation['valid']:
            return jsonify({
                'error': 'Invalid target',
                'validation_issues': validation['issues']
            }), 400

        # Perform nmap discovery
        results = passive_discovery(target, port_range)

        return jsonify({
            'success': True,
            'target': target,
            'port_range': port_range,
            'results': results,
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        print(f"❌ Nmap discovery error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/nmap-vulnerability-scan', methods=['POST'])
def nmap_vulnerability_scan_endpoint():
    """Direct nmap vulnerability scanning endpoint for testing and advanced usage"""
    try:
        data = request.get_json()
        target = data.get('target')
        port = data.get('port')
        service_type = data.get('service_type')

        if not target or not port:
            return jsonify({'error': 'Target and port are required'}), 400

        print(f"🛡️ Direct nmap vulnerability scan for {target}:{port}")

        # Validate inputs
        validation = validate_scan_target(target, 'ip')
        if not validation['valid']:
            return jsonify({
                'error': 'Invalid target',
                'validation_issues': validation['issues']
            }), 400

        try:
            port = int(port)
            if port < 1 or port > 65535:
                raise ValueError("Invalid port range")
        except ValueError:
            return jsonify({'error': 'Invalid port number'}), 400

        # Perform enhanced vulnerability scan
        results = enhanced_vulnerability_scan(target, port, service_type)

        return jsonify({
            'success': True,
            'target': target,
            'port': port,
            'service_type': service_type,
            'results': results,
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        print(f"❌ Nmap vulnerability scan error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/pre-scan-intelligence', methods=['POST'])
def pre_scan_intelligence():
    """Get pre-scan intelligence from Shodan and other sources"""
    try:
        data = request.get_json()
        target = data.get('target')
        target_type = data.get('target_type', 'ip')

        if not target:
            return jsonify({'error': 'Target is required'}), 400

        # Validate target
        validation = validate_scan_target(target, target_type)
        if not validation['valid']:
            return jsonify({
                'error': 'Invalid target',
                'validation_issues': validation['issues']
            }), 400

        print(f"🔍 Getting pre-scan intelligence for {target}")

        # Get intelligence
        intelligence = get_pre_scan_intelligence(target, target_type)

        return jsonify({
            'success': True,
            'target': target,
            'target_type': target_type,
            'intelligence': intelligence,
            'validation': validation,
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        print(f"❌ Pre-scan intelligence error: {e}")
        return jsonify({'error': str(e)}), 500


def get_mock_integration_status():
    """Return mock integration status when services are unavailable"""
    nmap_check = check_nmap_installation()
    vulners_nse = check_vulners_nse_scripts()

    return {
        'status': 'partial',
        'timestamp': datetime.now().isoformat(),
        'integrations': {
            'nmap': {
                'enabled': nmap_check['installed'],
                'status': 'Available' if nmap_check['installed'] else 'Not installed',
                'version': nmap_check['version'],
                'path': nmap_check['path'],
                'reason': 'Nmap binary found' if nmap_check['installed'] else 'Nmap not installed'
            },
            'individual_scanner_nmap': {
                'enabled': nmap_check['installed'],
                'status': 'Available' if nmap_check['installed'] else 'Not available',
                'reason': 'Individual scanner nmap integration' if nmap_check['installed'] else 'Nmap not available'
            },
            'enhanced_nmap': {
                'enabled': nmap_check['installed'] and vulners_nse['available'],
                'status': 'Available' if nmap_check['installed'] and vulners_nse['available'] else 'Limited',
                'nse_scripts': vulners_nse['scripts_found'],
                'reason': 'NSE scripts available' if vulners_nse['available'] else 'NSE scripts missing'
            },
            'enhanced_vulnerability_checking': {
                'enabled': bool(VULNERS_API_KEY) and nmap_check['installed'],
                'status': 'Configured' if bool(VULNERS_API_KEY) and nmap_check['installed'] else 'Not configured',
                'reason': 'API key configured' if bool(VULNERS_API_KEY) else 'API key missing'
            },
            'vulners_cve_detection': {
                'enabled': bool(VULNERS_API_KEY),
                'status': 'Configured' if bool(VULNERS_API_KEY) else 'Not configured',
                'api_key_configured': bool(VULNERS_API_KEY),
                'reason': 'API key found' if bool(VULNERS_API_KEY) else 'API key not configured'
            },
            'shodan_intelligence': {
                'enabled': bool(SHODAN_API_KEY),
                'status': 'Configured' if bool(SHODAN_API_KEY) else 'Not configured',
                'reason': 'API key found' if bool(SHODAN_API_KEY) else 'API key not configured'
            }
        },
        'capabilities': {
            'passive_scanning': True,
            'active_scanning': nmap_check['installed'],
            'ftp_enhanced_scanning': nmap_check['installed'] and FTP_SPECIFIC_AVAILABLE,
            'vulnerability_detection': bool(VULNERS_API_KEY),
            'intelligence_gathering': bool(SHODAN_API_KEY) or bool(NETLAS_API_KEY),
            'enhanced_nmap_discovery': nmap_check['installed'] and vulners_nse['available'],
            'cve_detection': bool(VULNERS_API_KEY)
        },
        'recommendations': generate_setup_recommendations(nmap_check, vulners_nse)
    }


def generate_setup_recommendations(nmap_check, vulners_nse):
    """Generate setup recommendations based on current configuration"""
    recommendations = []

    if not nmap_check['installed']:
        recommendations.append({
            'priority': 'high',
            'category': 'installation',
            'title': 'Install Nmap',
            'description': 'Install Nmap to enable enhanced discovery and FTP scanning features',
            'commands': {
                'ubuntu': 'sudo apt-get install nmap',
                'centos': 'sudo yum install nmap',
                'macos': 'brew install nmap',
                'windows': 'Download from https://nmap.org/download.html'
            }
        })

    if nmap_check['installed'] and not vulners_nse['available']:
        recommendations.append({
            'priority': 'medium',
            'category': 'configuration',
            'title': 'Install Vulners NSE Scripts',
            'description': 'Install Vulners NSE scripts for CVE detection',
            'commands': {
                'linux': 'git clone https://github.com/vulnersCom/nmap-vulners.git && sudo cp nmap-vulners/*.nse /usr/share/nmap/scripts/',
                'update_db': 'sudo nmap --script-updatedb'
            }
        })

    if not FTP_SPECIFIC_AVAILABLE:
        recommendations.append({
            'priority': 'medium',
            'category': 'enhancement',
            'title': 'Enable Enhanced FTP Scanning',
            'description': 'Configure enhanced FTP scanner for advanced FTP security testing',
            'steps': [
                'Ensure FTP scanner is properly initialized',
                'Check services/__init__.py for FTP imports',
                'Verify base scanner integration'
            ]
        })

    if not VULNERS_API_KEY:
        recommendations.append({
            'priority': 'medium',
            'category': 'api_keys',
            'title': 'Configure Vulners API Key',
            'description': 'Add Vulners API key for CVE vulnerability detection',
            'steps': [
                'Register at https://vulners.com',
                'Get your API key',
                'Add VULNERS_API_KEY to config/vulnerability_config.py'
            ]
        })

    if not SHODAN_API_KEY:
        recommendations.append({
            'priority': 'low',
            'category': 'api_keys',
            'title': 'Configure Shodan API Key',
            'description': 'Add Shodan API key for enhanced intelligence gathering',
            'steps': [
                'Register at https://shodan.io',
                'Get your API key',
                'Add SHODAN_API_KEY to config/vulnerability_config.py'
            ]
        })

    return recommendations


@app.route('/api/integration-status', methods=['GET'])
def get_integration_status_endpoint():
    """Enhanced integration status endpoint with fallback support"""
    try:
        # Try to get detailed status from services
        try:
            status = get_integration_status()
            # Add FTP-specific status
            status['integrations']['ftp_enhanced_scanning'] = {
                'enabled': FTP_SPECIFIC_AVAILABLE,
                'status': 'Available' if FTP_SPECIFIC_AVAILABLE else 'Not available',
                'reason': 'FTP-specific functions loaded' if FTP_SPECIFIC_AVAILABLE else 'FTP-specific functions missing'
            }
            return jsonify(status)
        except Exception as service_error:
            print(f"⚠️ Service integration check failed: {service_error}")

            # Fallback to mock status with basic checks
            mock_status = get_mock_integration_status()
            mock_status['fallback_mode'] = True
            mock_status['service_error'] = str(service_error)

            return jsonify(mock_status)

    except Exception as e:
        print(f"❌ Integration status endpoint error: {e}")

        # Ultimate fallback - basic status
        fallback_status = {
            'status': 'error',
            'timestamp': datetime.now().isoformat(),
            'error': str(e),
            'integrations': {
                'enhanced_nmap': {
                    'enabled': False,
                    'status': 'Error checking status',
                    'reason': 'Service unavailable'
                },
                'ftp_enhanced_scanning': {
                    'enabled': FTP_SPECIFIC_AVAILABLE,
                    'status': 'Available' if FTP_SPECIFIC_AVAILABLE else 'Not available',
                    'reason': 'Basic check only'
                },
                'vulners_cve_detection': {
                    'enabled': bool(VULNERS_API_KEY),
                    'status': 'Configured' if bool(VULNERS_API_KEY) else 'Not configured',
                    'reason': 'Basic check only'
                },
                'shodan_intelligence': {
                    'enabled': bool(SHODAN_API_KEY),
                    'status': 'Configured' if bool(SHODAN_API_KEY) else 'Not configured',
                    'reason': 'Basic check only'
                }
            },
            'capabilities': {
                'passive_scanning': True,
                'active_scanning': False,
                'ftp_enhanced_scanning': FTP_SPECIFIC_AVAILABLE,
                'vulnerability_detection': bool(VULNERS_API_KEY),
                'intelligence_gathering': bool(SHODAN_API_KEY) or bool(NETLAS_API_KEY)
            },
            'fallback_mode': True
        }

        return jsonify(fallback_status), 200


@app.route('/api/supported-ports', methods=['GET'])
def get_supported_ports_route():
    http_ports = [80, 8000, 8080]
    http_available = "true" if HTTP_SCANNER_AVAILABLE else "false"
    """Enhanced supported ports endpoint with HTTPS integration info"""
    try:
        integration_status = get_integration_status()
        nmap_available = integration_status.get('integrations', {}).get('enhanced_nmap', {}).get('enabled', False)
        individual_nmap_available = integration_status.get('integrations', {}).get('individual_scanner_nmap', {}).get('enabled', False)

        # Check HTTPS scanner status
        https_status = "❌"
        try:
            from services.https_scanner import HTTPSScanner
            https_status = "✅"
        except ImportError:
            pass

        # Check SNMP scanner status
        snmp_status = "❌"
        try:
            from services import get_snmp_scanner_status
            snmp_scanner_status = get_snmp_scanner_status()
            snmp_status = "✅" if snmp_scanner_status.get('snmp_scanner_available') else "❌"
        except:
            pass

        # Check SMB scanner status
        smb_status = "❌"
        wsl_status = "❌"
        try:
            from services import get_smb_scanner_status
            smb_scanner_status = get_smb_scanner_status()
            smb_status = "✅" if smb_scanner_status.get('smb_scanner_available') else "❌"
            wsl_status = "✅" if smb_scanner_status.get('wsl_tools_available') else "❌"
        except:
            pass

        # Get base supported ports and add HTTPS ports
        base_supported_ports = get_supported_ports()
        https_ports = [443, 8443, 8080, 9443]
        all_supported_ports = list(set(base_supported_ports + https_ports))

        return jsonify({
            'supported_ports': all_supported_ports,
            'http_ports': http_ports,
            'https_ports': https_ports,
            'scanner_info': get_scanner_info(),
            'integration_status': integration_status,
            'enhanced_capabilities': get_enhanced_capabilities(),
            'total_scanners': len(get_scanner_info()),
            'http_enhanced_available': http_available,
            'https_enhanced_available': https_status == "✅",
            'ftp_enhanced_available': FTP_SPECIFIC_AVAILABLE,
            'snmp_enhanced_available': True,  # SNMP is now available
            'enhanced_features': [
                'Shodan Intelligence Integration',
                'Vulners CVE Vulnerability Detection',
                f'Enhanced Nmap NSE Script Integration {"✅" if nmap_available else "❌"}',
                f'Individual Scanner Nmap Integration {"✅" if individual_nmap_available else "❌"}',
                f'Enhanced HTTP Scanner {"✅" if http_available else "❌"}',
                f'Enhanced HTTPS Scanner {https_status}',
                f'Enhanced FTP Scanner {"✅" if FTP_SPECIFIC_AVAILABLE else "❌"}',
                f'Enhanced SMB Scanner {smb_status}',
                f'Enhanced SNMP Scanner {snmp_status}',
                f'WSL Tools Integration {wsl_status}',
                'Passive Port Discovery with NSE Scripts',
                'Comprehensive Vulnerability Scanning with Vulners API',
                'Pre-scan Intelligence Optimization',
                'Multi-source Intelligence Correlation',
                'Bulk Scan Optimization',
                'HTTP Web Application Vulnerability Scanning',
                'HTTP Security Headers Analysis',
                'HTTP Directory Enumeration',
                'HTTPS SSL/TLS Security Testing',
                'HTTPS Web Application Vulnerability Scanning',
                'HTTPS Certificate Security Analysis',
                'HTTPS Security Headers Analysis',
                'SMB Aggressive Mode with WSL Tools',
                'SNMP Community String Brute Force',
                'SNMP System and Windows Enumeration',
                'UDP Protocol Support for SNMP'
            ],
            'scan_modes': {
                'http': {
                    'normal': 'Safe web application security assessment',
                    'aggressive': 'Comprehensive web vulnerability testing'
                },
                'https': {
                    'normal': 'Safe SSL/TLS security assessment',
                    'aggressive': 'Comprehensive SSL/TLS + web vulnerability testing'
                },
                'snmp': {
                    'normal': 'Basic SNMP enumeration',
                    'aggressive': 'Community string brute force + system enumeration'
                },
                'smb': {
                    'normal': 'Basic SMB enumeration',
                    'aggressive': 'Null session + share enumeration + vulnerability testing'
                },
                'ftp': {
                    'normal': 'Basic FTP enumeration',
                    'aggressive': 'Anonymous access + directory traversal + bounce attack testing'
                }
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/api/health', methods=['GET'])
def health_check():
    """Enhanced health check endpoint with FTP scanner status"""
    try:
        integration_status = get_integration_status()
        service_health = check_service_health()

        return jsonify({
            'status': 'healthy',
            'service': 'ReconLite Enhanced',
            'version': '2.3',  # Updated version
            'timestamp': datetime.now().isoformat(),
            'scanners': list(get_scanner_info().keys()),
            'supported_ports': get_supported_ports(),
            'integrations': {
                'nmap': integration_status['integrations'].get('nmap', {}).get('enabled', False),
                'individual_nmap': integration_status['integrations'].get('individual_scanner_nmap', {}).get('enabled',
                                                                                                             False),
                'enhanced_nmap': integration_status['integrations'].get('enhanced_nmap', {}).get('enabled', False),
                'ftp_enhanced': FTP_SPECIFIC_AVAILABLE,
                'vulners_cve_checking': integration_status['integrations'].get('enhanced_vulnerability_checking',
                                                                               {}).get('enabled', False),
                'shodan': integration_status['integrations'].get('shodan_intelligence', {}).get('enabled', False)
            },
            'capabilities': integration_status['capabilities'],
            'service_health': service_health,
            'database_connected': db.connected,
            'api_keys_configured': {
                'netlas': bool(NETLAS_API_KEY),
                'shodan': bool(SHODAN_API_KEY),
                'securitytrails': bool(SECURITYTRAILS_API_KEY),
                'vulners': bool(VULNERS_API_KEY)
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'service': 'ReconLite Enhanced',
            'version': '2.3',
            'timestamp': datetime.now().isoformat()
        }), 500


# Enhanced utility functions for vulnerability processing
def enhance_vulnerability_with_urls(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """Enhance vulnerability with professional exploit URLs"""
    enhanced_vuln = vuln.copy()

    # Add exploit URLs if not already present
    if not enhanced_vuln.get('href') and enhanced_vuln.get('cve_id'):
        cve_id = enhanced_vuln['cve_id']
        enhanced_vuln['href'] = f"https://vulners.com/cve/{cve_id}"

    # Add CVE database URL
    if enhanced_vuln.get('cve_id') and not enhanced_vuln.get('source_href'):
        enhanced_vuln['source_href'] = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={enhanced_vuln['cve_id']}"

    # Enhance title for better display
    if not enhanced_vuln.get('title') and enhanced_vuln.get('cve_id'):
        enhanced_vuln['title'] = f"CVE Vulnerability: {enhanced_vuln['cve_id']}"

    # Add exploit references for frontend display
    if not enhanced_vuln.get('exploit_references'):
        enhanced_vuln['exploit_references'] = []

        if enhanced_vuln.get('href'):
            enhanced_vuln['exploit_references'].append({
                'url': enhanced_vuln['href'],
                'type': 'vulners',
                'title': 'View on Vulners',
                'verified': True
            })

        if enhanced_vuln.get('source_href'):
            enhanced_vuln['exploit_references'].append({
                'url': enhanced_vuln['source_href'],
                'type': 'cve',
                'title': 'CVE Details',
                'verified': True
            })

    return enhanced_vuln


def extract_edb_id_from_vulnerability(vuln: Dict[str, Any]) -> str:
    """Extract EDB ID from vulnerability data"""
    if vuln.get('exploit_db_id'):
        return str(vuln['exploit_db_id'])

    if vuln.get('path'):
        import re
        match = re.search(r'(\d+)\.', vuln['path'])
        if match:
            return match.group(1)

    if vuln.get('title'):
        import re
        match = re.search(r'EDB-ID:\s*(\d+)', vuln['title'], re.IGNORECASE)
        if match:
            return match.group(1)

    return None


def extract_cve_from_title(title: str) -> str:
    """Extract CVE ID from title"""
    if not title:
        return ''

    import re
    match = re.search(r'CVE-\d{4}-\d+', title, re.IGNORECASE)
    if match:
        return match.group(0).upper()

    return ''


def assess_exploit_severity(exploit: Dict[str, Any]) -> str:
    """Assess severity from exploit data"""
    title = (exploit.get('title', '') or '').lower()
    exploit_type = (exploit.get('type', '') or '').lower()

    if any(keyword in title or keyword in exploit_type for keyword in
           ['remote code execution', 'buffer overflow', 'privilege escalation']):
        return 'Critical'

    if any(keyword in title or keyword in exploit_type for keyword in
           ['sql injection', 'authentication bypass', 'command injection']):
        return 'High'

    if any(keyword in title or keyword in exploit_type for keyword in
           ['denial of service', 'information disclosure']):
        return 'Medium'

    return 'High'  # Default for exploits


def get_cvss_from_severity(severity: str) -> float:
    """Convert severity to approximate CVSS score"""
    severity_mapping = {
        'Critical': 9.5,
        'High': 7.5,
        'Medium': 5.0,
        'Low': 2.5,
        'Info': 0.0
    }
    return severity_mapping.get(severity, 7.0)


# Database helper functions
def save_dns_record(session_id: str, record: Dict[str, Any]):
    """Save DNS record to database"""
    try:
        query = """
        INSERT INTO dns_records (session_id, domain, record_type, record_value, source)
        VALUES (%s, %s, %s, %s, %s)
        """
        params = (
            session_id,
            record.get('name', ''),
            record.get('type', ''),
            record.get('value', ''),
            'SecurityTrails'
        )
        db.execute_query(query, params)
    except Exception as e:
        print(f"Error saving DNS record: {e}")


def save_subdomain(session_id: str, subdomain: str):
    """Save subdomain to database"""
    try:
        query = """
        INSERT INTO subdomains (session_id, subdomain, discovered_method)
        VALUES (%s, %s, %s)
        """
        params = (session_id, subdomain, 'Certificate Transparency')
        db.execute_query(query, params)
    except Exception as e:
        print(f"Error saving subdomain: {e}")


def save_whois_data(session_id: str, domain: str, whois_info: Dict[str, Any]):
    """Save whois data to database"""
    try:
        query = """
        INSERT INTO whois_data (session_id, domain, registrar, creation_date, expiration_date, raw_data)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        # Convert dates safely
        creation_date = None
        expiration_date = None

        if whois_info.get('creation_date'):
            try:
                creation_date = whois_info['creation_date'].split()[0]
            except:
                pass

        if whois_info.get('expiration_date'):
            try:
                expiration_date = whois_info['expiration_date'].split()[0]
            except:
                pass

        params = (
            session_id,
            domain,
            whois_info.get('registrar', ''),
            creation_date,
            expiration_date,
            str(whois_info)
        )
        db.execute_query(query, params)
    except Exception as e:
        print(f"Error saving whois data: {e}")


def save_vulnerability(session_id: str, vuln: Dict[str, Any]):
    """Save vulnerability to database"""
    try:
        query = """
        INSERT INTO vulnerabilities (session_id, vuln_id, severity, title, description, recommendation)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        params = (
            session_id,
            vuln.get('id', ''),
            vuln.get('severity', 'info'),
            vuln.get('title', ''),
            vuln.get('description', ''),
            vuln.get('recommendation', '')
        )
        db.execute_query(query, params)
    except Exception as e:
        print(f"Error saving vulnerability: {e}")


# Web routes
@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')


@app.route('/passive-scan')
def passive_scan_page():
    """Passive scanning page"""
    return render_template('main.html')


@app.route('/nmap-scan')
def nmap_scan_page():
    """Dedicated nmap scanning page"""
    return render_template('nmap-scan.html')


@app.route('/sessions')
def sessions():
    """Session management page"""
    return render_template('sessions.html')


# Export and session management endpoints
@app.route('/api/sessions', methods=['GET'])
def get_sessions():
    """Get all sessions"""
    sessions = db.get_sessions()
    return jsonify(sessions)


@app.route('/api/sessions/<session_id>', methods=['GET'])
def get_session_details(session_id):
    """Enhanced session details with exploit URLs"""
    try:
        print(f"[DEBUG] Getting enhanced session details for ID: {session_id}")

        # Get enhanced session data with exploit URLs
        session_data = db.get_session_details(session_id)

        if not session_data:
            print(f"[DEBUG] Session not found: {session_id}")
            return jsonify({'error': 'Session not found'}), 404

        # Process vulnerabilities to ensure exploit URLs are properly formatted
        if session_data.get('cve_vulnerabilities'):
            for cve in session_data['cve_vulnerabilities']:
                # Ensure exploit_references is properly formatted for frontend
                if cve.get('exploit_references'):
                    # Already processed by database method
                    pass
                else:
                    # Add basic URLs if missing
                    cve['exploit_references'] = []
                    if cve.get('cve_id') and cve['cve_id'].startswith('CVE-'):
                        cve['exploit_references'].append({
                            'url': f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve['cve_id']}",
                            'type': 'advisory',
                            'title': 'CVE Details',
                            'verified': True
                        })

        print(f"[DEBUG] Returning enhanced session with exploit URLs")
        return jsonify(session_data)

    except Exception as e:
        print(f"[DEBUG] Error: {str(e)}")
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/api/sessions/<session_id>', methods=['DELETE'])
def delete_session(session_id):
    """Delete a session"""
    try:
        success = db.delete_session(session_id)
        if success:
            return jsonify({'message': 'Session deleted successfully'})
        else:
            return jsonify({'error': 'Session not found'}), 404
    except Exception as e:
        print(f"Error deleting session: {e}")
        return jsonify({'error': 'Failed to delete session'}), 500


@app.route('/api/sessions/<session_id>/complete', methods=['GET'])
def get_complete_session_details(session_id):
    """Get COMPLETE session information with all data formatted for UI"""
    try:
        print(f"[DEBUG] Getting COMPLETE session details for ID: {session_id}")

        # Get complete session data using enhanced method
        session_data = db.get_session_details_complete(session_id)

        if not session_data:
            print(f"[DEBUG] Session not found: {session_id}")
            return jsonify({'error': 'Session not found'}), 404

        # Enhanced data formatting based on session type
        if session_data.get('type') == 'passive':
            # Format for passive scan UI loading
            formatted_data = format_passive_session_for_ui(session_data)
        else:
            # Format for active scan UI loading
            formatted_data = format_active_session_for_ui(session_data)

        print(f"[DEBUG] Returning complete session with all data formatted")
        return jsonify(formatted_data)

    except Exception as e:
        print(f"[DEBUG] Error: {str(e)}")
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/api/sessions/<session_id>/export', methods=['GET'])
def export_session_pdf(session_id):
    """Export session as PDF with all data included"""
    try:
        print(f"🔽 Exporting session as PDF: {session_id}")

        # Get session data
        session_data = db.get_session_details(session_id)

        if not session_data:
            return jsonify({'error': 'Session not found'}), 404

        # Parse target information
        target = session_data.get('target', 'Unknown Target')
        target_ip = 'Unknown'
        target_port = 'Unknown'

        if ':' in str(target):
            target_parts = str(target).split(':', 1)
            target_ip = target_parts[0] if len(target_parts) > 0 else 'Unknown'
            target_port = target_parts[1] if len(target_parts) > 1 else 'Unknown'
        else:
            target_ip = str(target)
            target_port = '443'  # Default port

        # Prepare comprehensive data for PDF export
        export_data = {
            'target': target,
            'type': 'domain' if session_data.get('type') == 'passive' else 'ip',
            'status': 'completed',
            'scan_time': session_data.get('created_at', ''),
        }

        # Add enhanced metadata for nmap scans
        if session_data.get('enhanced_nmap_used'):
            export_data['scan_method'] = 'Enhanced Nmap NSE + Vulners'
            export_data['enhanced_features'] = [
                'Nmap NSE Script Integration',
                'Vulners API Vulnerability Detection',
                'Multi-source Intelligence Correlation'
            ]

        # Format data based on session type
        if session_data.get('type') == 'passive':
            export_data.update(format_passive_export_data(session_data))
        else:
            export_data.update(format_active_export_data(session_data, target_ip, target_port))

        # Use export manager for PDF generation
        exported_file = export_manager.export(
            export_data,
            'pdf',
            datetime.now().isoformat()
        )

        return send_file(
            io.BytesIO(exported_file['content']),
            download_name=exported_file['filename'],
            mimetype=exported_file['mimetype'],
            as_attachment=True
        )

    except Exception as e:
        print(f"❌ PDF export error: {e}")
        return jsonify({'error': f'PDF export failed: {str(e)}'}), 500


def format_passive_export_data(session_data):
    """Format passive session data for PDF export"""
    # Format services data
    services = session_data.get('services', [])
    formatted_services = []
    for service in services:
        formatted_services.append({
            'ip': service.get('ip_address', service.get('ip', 'Unknown')),
            'port': service.get('port', 'Unknown'),
            'service': service.get('service_name', service.get('service', 'Unknown')),
            'version': service.get('service_version', service.get('version', '')),
            'banner': service.get('banner', ''),
            'state': service.get('state', 'open'),
            'protocol': service.get('protocol', 'tcp')
        })

    # Format DNS records
    dns_records = {}
    for record in session_data.get('dns_records', []):
        record_type = record.get('record_type', 'Unknown')
        if record_type not in dns_records:
            dns_records[record_type] = []
        dns_records[record_type].append(record.get('record_value', ''))

    # Format subdomains
    subdomains = []
    for subdomain in session_data.get('subdomains', []):
        if isinstance(subdomain, dict):
            subdomains.append(subdomain.get('subdomain', str(subdomain)))
        else:
            subdomains.append(str(subdomain))

    # Format whois data
    whois_data = {}
    if session_data.get('whois_data'):
        whois_record = session_data['whois_data'][0] if session_data['whois_data'] else {}
        whois_data = {
            'domain': whois_record.get('domain', ''),
            'registrar': whois_record.get('registrar', ''),
            'creation_date': whois_record.get('creation_date', ''),
            'expiration_date': whois_record.get('expiration_date', '')
        }

    return {
        'ports_services': formatted_services,
        'dns_records': dns_records,
        'subdomains': subdomains,
        'whois_info': whois_data
    }


def format_active_export_data(session_data, target_ip, target_port):
    """Format active session data for PDF export"""
    # Get all vulnerabilities including CVE data
    regular_vulns = session_data.get('vulnerabilities', [])
    cve_vulns = session_data.get('cve_vulnerabilities', [])
    all_vulnerabilities = regular_vulns + cve_vulns

    # Format service info
    services = session_data.get('services', [])
    if services:
        service = services[0]
        service_info = {
            'service_name': service.get('service_name', service.get('service', 'Unknown')),
            'version': service.get('service_version', service.get('version', '')),
            'banner': service.get('banner', ''),
            'port': service.get('port', target_port),
            'state': service.get('state', 'open'),
            'accessible': True
        }
        service_type = service.get('service_name', service.get('service', 'unknown'))
    else:
        service_info = {
            'service_name': 'Unknown',
            'port': target_port,
            'accessible': True,
            'state': 'open'
        }
        service_type = 'unknown'

    # Format vulnerabilities for PDF
    formatted_vulns = []
    for vuln in all_vulnerabilities:
        vuln_data = {
            'id': vuln.get('vuln_id', vuln.get('id', vuln.get('cve_id', 'Unknown'))),
            'severity': vuln.get('severity', 'Unknown'),
            'title': vuln.get('title', 'Security Finding'),
            'description': vuln.get('description', 'No description available'),
            'recommendation': vuln.get('recommendation', 'Review and remediate this finding')
        }

        # Add CVSS score if available
        if vuln.get('cvss_score'):
            vuln_data['cvss_score'] = vuln.get('cvss_score')

        # Add source information for enhanced tracking
        if vuln.get('source'):
            vuln_data['source'] = vuln.get('source')

        formatted_vulns.append(vuln_data)

    # Generate recommendations
    recommendations = generate_enhanced_recommendations(formatted_vulns, service_type)

    return {
        'service_type': service_type,
        'service_info': service_info,
        'vulnerabilities': formatted_vulns,
        'recommendations': recommendations,
        'ports_services': [{
            'ip': target_ip,
            'port': target_port,
            'service': service_info.get('service_name', 'Unknown'),
            'version': service_info.get('version', ''),
            'banner': service_info.get('banner', ''),
            'state': 'open',
            'protocol': 'tcp'
        }]
    }


def generate_enhanced_recommendations(vulnerabilities, service_type):
    """Generate enhanced recommendations including nmap findings"""
    recommendations = [
        f"Security Assessment Summary: {len(vulnerabilities)} vulnerabilities found"
    ]

    # Count by severity and source
    critical_count = len([v for v in vulnerabilities if v.get('severity', '').lower() == 'critical'])
    high_count = len([v for v in vulnerabilities if v.get('severity', '').lower() == 'high'])
    nse_findings = len([v for v in vulnerabilities if 'nmap' in v.get('source', '').lower()])
    cve_findings = len([v for v in vulnerabilities if v.get('source') in ['Vulners', 'Vulners API']])

    if critical_count > 0:
        recommendations.append(f"🚨 URGENT: {critical_count} Critical vulnerabilities require immediate attention")
    if high_count > 0:
        recommendations.append(f"⚠️ HIGH PRIORITY: {high_count} High severity vulnerabilities found")
    if nse_findings > 0:
        recommendations.append(f"🎯 NMAP NSE: {nse_findings} findings from advanced script analysis")
    if cve_findings > 0:
        recommendations.append(f"🛡️ CVE DATABASE: {cve_findings} known vulnerabilities identified")

    # Add FTP-specific recommendations if applicable
    if service_type.lower() == 'ftp':
        recommendations.extend([
            '📁 FTP SECURITY: Disable anonymous access if not required',
            '🔐 FTP ENCRYPTION: Implement FTPS or migrate to SFTP',
            '🛡️ FTP ACCESS: Restrict FTP access to specific IP ranges',
            '📋 FTP MONITORING: Enable comprehensive FTP logging'
        ])

    recommendations.extend([
        'Keep all services updated to latest stable versions',
        'Implement proper firewall rules and access controls',
        'Monitor service logs for suspicious activity',
        'Consider network segmentation for critical services',
        'Perform regular security assessments with updated tools'
    ])

    return recommendations


def format_passive_session_for_ui(session_data):
    """Format passive session data for UI loading"""
    formatted_data = {
        'target': session_data.get('target', 'Unknown'),
        'type': 'domain' if session_data.get('target', '').count('.') > 0 else 'ip',
        'status': 'completed',
        'scan_time': session_data.get('created_at', ''),
        'session_id': session_data.get('id'),
        'session_name': session_data.get('name', 'Loaded Session'),
        'ports_services': session_data.get('services', []),
        'dns_records': session_data.get('dns_records', []),
        'subdomains': session_data.get('subdomains', []),
        'whois_info': session_data.get('whois_data', [])
    }

    # Add nmap metadata if available
    if session_data.get('enhanced_nmap_used'):
        formatted_data['enhanced_discovery'] = True
        formatted_data['discovery_methods'] = ['enhanced_nmap_nse']
        formatted_data['nmap_metadata'] = {
            'nse_scripts_used': True,
            'vulnerability_detection': True
        }

    return formatted_data


def format_active_session_for_ui(session_data):
    """Format active session data for UI loading with enhanced FTP support"""
    try:
        from services import formatActiveSessionForUI
        return formatActiveSessionForUI(session_data)
    except ImportError:
        # Fallback formatting
        target = session_data.get('target', 'Unknown')
        target_parts = target.split(':') if ':' in target else [target, '443']

        return {
            'targetIP': target_parts[0],
            'targetPort': int(target_parts[1]) if target_parts[1].isdigit() else 443,
            'scanType': 'auto',
            'enableCveCheck': True,
            'customWordlist': '',
            'scan_results': session_data,
            'enhanced_nmap_used': session_data.get('enhanced_nmap_used', False),
            'ftp_enhanced_used': session_data.get('scanner_type', '').lower() == 'ftp',
            'scan_method': session_data.get('scan_method', 'standard')
        }


@app.route('/api/export', methods=['POST'])
def export_report():
    try:
        data = request.get_json()
        scan_data = data.get('data')
        export_format = data.get('format', 'pdf')
        timestamp = data.get('timestamp', datetime.utcnow().isoformat())

        if not scan_data:
            return jsonify({'error': 'No data provided'}), 400

        # Call ExportManager to generate the export
        exported_file = export_manager.export(scan_data, export_format, timestamp)

        # Send file
        return send_file(
            io.BytesIO(exported_file['content']),
            download_name=exported_file['filename'],
            mimetype=exported_file['mimetype']
        )

    except Exception as e:
        print(f"❌ Export failed: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    """Get dashboard statistics"""
    stats = db.get_dashboard_stats()
    return jsonify(stats)


def print_enhanced_startup_banner():
    """Enhanced startup banner with HTTPS scanner status"""
    print("\n" + "=" * 80)
    print("🚀 RECONLITE ENHANCED - STARTUP DIAGNOSTICS")
    print("=" * 80)
    print("🔧 Service: ReconLite Enhanced v2.4")
    print("📅 Startup Time:", datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'))

    # Check system tools
    print("\n🔧 System Tools:")
    nmap_check = check_nmap_installation()
    print(f"  🎯 Nmap: {'✅ ' + nmap_check['version'] if nmap_check['installed'] else '❌ Not installed'}")

    try:
        wsl_test = subprocess.run(['wsl', 'echo', 'WSL check'],
                                  capture_output=True, text=True, timeout=5)
        if wsl_test.returncode == 0:
            print("  ✅ WSL Status: Available and ready")
        else:
            print("  ❌ WSL Status: Not responding")
    except:
        print("  ❌ WSL Status: Not installed")
        print("  💡 Install WSL: wsl --install")

    # Add scanner status checks
    try:
        from services import get_scanner_info
        scanner_info = get_scanner_info()

        # HTTPS scanner status
        try:
            from services.https_scanner import HTTPSScanner
            https_status = "✅ Full SSL/TLS + web vulnerability testing"
        except ImportError:
            https_status = "❌ Not available"
        print(f"  🔒 HTTPS Scanner: {https_status}")

        # SMB scanner status
        smb_available = 'SMB' in scanner_info
        if smb_available:
            try:
                from services import get_smb_scanner_status
                smb_status = get_smb_scanner_status()
                wsl_available = smb_status.get('wsl_tools_available', False)
                aggressive_supported = smb_status.get('aggressive_mode_supported', False)

                if nmap_check['installed'] and wsl_available and aggressive_supported:
                    smb_status_str = "✅ Full features (nmap + WSL + aggressive mode)"
                elif wsl_available:
                    smb_status_str = "✅ Enhanced mode with WSL tools"
                elif smb_available:
                    smb_status_str = "✅ Basic mode only"
                else:
                    smb_status_str = "❌ Not available"
            except:
                smb_status_str = "✅ Basic mode available"
        else:
            smb_status_str = "❌ Not available"

        print(f"  🏢 SMB Scanner: {smb_status_str}")

        # FTP scanner status
        ftp_available = 'FTP' in scanner_info
        ftp_status = ""
        if nmap_check['installed'] and ftp_available and FTP_SPECIFIC_AVAILABLE:
            ftp_status = "✅ Enhanced with nmap + FTP-specific functions"
        elif ftp_available and FTP_SPECIFIC_AVAILABLE:
            ftp_status = "✅ Enhanced mode available"
        elif ftp_available:
            ftp_status = "✅ Basic mode only"
        else:
            ftp_status = "❌ Not available"
        print(f"  📁 FTP Scanner: {ftp_status}")

        # SNMP scanner status
        snmp_status = "✅ Enhanced UDP enumeration + brute force" if SNMP_SCANNER_AVAILABLE else "❌ Not available"
        print(f"  📡 SNMP Scanner: {snmp_status}")

    except:
        print(f"  ❓ Scanner status check failed")

    # Check NSE scripts
    vulners_nse = check_vulners_nse_scripts()
    print(
        f"  🛡️ Vulners NSE: {'✅ ' + str(len(vulners_nse['scripts_found'])) + ' scripts' if vulners_nse['available'] else '❌ Not available'}")

    # Check API keys
    print("\n🔑 API Keys:")
    api_keys = {
        'Vulners': VULNERS_API_KEY,
        'Shodan': SHODAN_API_KEY,
        'Netlas': NETLAS_API_KEY,
        'SecurityTrails': SECURITYTRAILS_API_KEY
    }

    for name, key in api_keys.items():
        status = f"✅ Configured ({len(key)} chars)" if key else "❌ Not configured"
        print(f"  🔐 {name}: {status}")

    # Database status
    try:
        db_status = "✅ Connected" if getattr(db, 'connected', False) else "❌ Disconnected"
    except:
        db_status = "❓ Unknown"
    print(f"\n💾 Database: {db_status}")

    # Enhanced Capabilities summary with HTTPS
    print("\n✨ Enhanced Capabilities:")

    # Check HTTPS availability
    https_available = False
    try:
        from services.https_scanner import HTTPSScanner
        https_available = True
    except ImportError:
        pass

    capabilities = [
        ("Passive Port Discovery", True),
        ("Enhanced Nmap Discovery", nmap_check['installed']),
        ("Individual Scanner Nmap", nmap_check['installed']),
        ("Enhanced HTTPS Scanner", https_available),
        ("HTTPS SSL/TLS Security Testing", https_available),
        ("HTTPS Web Vulnerability Scanning", https_available),
        ("Enhanced FTP Scanner", FTP_SPECIFIC_AVAILABLE and nmap_check['installed']),
        ("Enhanced SMB Scanner", smb_available if 'smb_available' in locals() else False),
        ("Enhanced SNMP Scanner", SNMP_SCANNER_AVAILABLE),
        ("CVE Vulnerability Detection", bool(VULNERS_API_KEY)),
        ("Intelligence Gathering", bool(SHODAN_API_KEY) or bool(NETLAS_API_KEY)),
        ("Subdomain Enumeration", bool(SECURITYTRAILS_API_KEY))
    ]

    for name, enabled in capabilities:
        print(f"  {'✅' if enabled else '❌'} {name}")

    print("\n" + "=" * 80)
    print("🎯 ReconLite Enhanced - Ready for Advanced Reconnaissance!")
    print("🌐 Frontend: Enhanced UI with HTTPS + SMB + FTP + SNMP Scanner + Nmap NSE + Vulners Integration")
    print("⚡ Backend: Multi-source Intelligence + CVE Detection + Enhanced Security Testing")
    print("🛡️ Security: Passive Discovery + Active Vulnerability Scanning + Comprehensive Testing")
    print("🔒 HTTPS Features: SSL/TLS security + Web vuln testing + Certificate analysis + Security headers")
    print("📁 FTP Features: Anonymous access testing + Directory traversal + Bounce attacks + Nmap NSE")
    print("🏢 SMB Features: Null sessions + Share enumeration + EternalBlue testing + WSL integration")
    print("📡 SNMP Features: Community brute force + System enumeration + Windows enumeration + UDP scanning")
    print("=" * 80 + "\n")


if __name__ == '__main__':
    print_enhanced_startup_banner()
    app.run(debug=True)