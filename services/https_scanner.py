import socket
import ssl
import time
import subprocess
import re
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import os
import tempfile
from .base_scanner import BaseScanner


class HTTPSScanner(BaseScanner):
    """HTTPS Scanner with Normal and Aggressive modes using nmap"""

    def __init__(self, timeout: int = 10):
        super().__init__(timeout)

    def get_supported_ports(self) -> List[int]:
        return [443, 8443, 8080, 9443]  # Common HTTPS ports

    def get_service_name(self) -> str:
        return "HTTPS"

    def scan(self, ip: str, port: int, custom_paths: List[str] = None, **kwargs) -> Dict[str, Any]:
        """Normal HTTPS scan - Safe, basic security assessment with optional directory enumeration"""
        self.scan_start_time = time.time()
        results = self.create_base_result(ip, port)

        try:
            print(f"🔒 Starting HTTPS normal scan for {ip}:{port}")
            if custom_paths:
                print(f"🔍 Custom directory enumeration enabled with {len(custom_paths)} paths")

            # Step 1: Basic connectivity and SSL handshake
            self.mark_step_completed(results, 'connectivity')
            connectivity_info = self._check_https_connectivity(ip, port)
            results['connectivity_info'] = connectivity_info

            if not connectivity_info.get('accessible'):
                return self.create_failed_result(ip, port,
                                                 f"HTTPS service not accessible: {connectivity_info.get('failure_reason', 'Connection failed')}")

            # Step 2: Basic SSL certificate analysis
            self.mark_step_completed(results, 'certificate')
            cert_info = self._analyze_ssl_certificate(ip, port)
            results['service_info'].update(cert_info)

            # Step 3: Run normal nmap scan (safe scripts)
            self.mark_step_completed(results, 'nmap_scan')
            if custom_paths:
                # Use enhanced scan with directory enumeration
                nmap_results = self._run_normal_https_scan_with_directory_enum(ip, port, custom_paths)
            else:
                # Use regular normal scan
                nmap_results = self._run_normal_https_scan(ip, port)

            results['nmap_data'] = nmap_results

            if nmap_results.get('error'):
                print(f"⚠️ Nmap scan failed, continuing with manual analysis")
                results['nmap_enhanced'] = False
            else:
                results['nmap_enhanced'] = True
                # Extract additional service info from nmap
                nmap_service_info = nmap_results.get('service_info', {})
                results['service_info'].update(nmap_service_info)
                results['banner'] = nmap_results.get('banner', '')

            # Step 4: Parse nmap results for security findings
            self.mark_step_completed(results, 'security_analysis')
            security_findings = self._parse_https_security_findings(nmap_results, aggressive=False)
            results['vulnerabilities'] = security_findings.get('vulnerabilities', [])
            results['recommendations'] = security_findings.get('recommendations', [])
            results['advanced_findings'] = security_findings.get('advanced_findings', {})

            # Step 5: Add manual certificate analysis to findings
            cert_vulnerabilities = self._assess_certificate_security(cert_info)
            results['vulnerabilities'].extend(cert_vulnerabilities)

            # Step 6: Process directory enumeration results if custom paths were used
            if custom_paths and 'directory_enumeration' in nmap_results:
                results['directory_enumeration'] = nmap_results['directory_enumeration']

                # Add findings to vulnerabilities if directories found
                directories_found = nmap_results['directory_enumeration'].get('directories_found', [])
                if directories_found:
                    results['vulnerabilities'].append({
                        'id': 'HTTPS-DIR-001',
                        'severity': 'Low',
                        'title': 'Sensitive Directories Found',
                        'description': f"Found directories: {', '.join(directories_found[:5])}",
                        'recommendation': 'Review exposed directories and restrict access if needed',
                        'source': 'directory_enumeration',
                        'detection_method': 'http-enum-custom'
                    })

            return self.finalize_results(results, success=True)

        except Exception as e:
            print(f"❌ HTTPS normal scan error: {e}")
            results['error'] = str(e)
            return self.finalize_results(results, success=False)

    def scan_aggressive(self, ip: str, port: int, **kwargs) -> Dict[str, Any]:
        """Aggressive HTTPS scan - Comprehensive vulnerability assessment (NO custom directory enumeration)"""
        self.scan_start_time = time.time()
        results = self.create_base_result(ip, port)

        try:
            print(f"🎯 Starting HTTPS aggressive scan for {ip}:{port}")

            # Get normal scan results if provided
            normal_results = kwargs.get('normal_scan_results')

            # Step 1: Connectivity (reuse if available)
            self.mark_step_completed(results, 'connectivity')
            if normal_results and normal_results.get('connectivity_info'):
                connectivity_info = normal_results['connectivity_info']
            else:
                connectivity_info = self._check_https_connectivity(ip, port)
            results['connectivity_info'] = connectivity_info

            # Step 2: Enhanced SSL analysis
            self.mark_step_completed(results, 'enhanced_certificate')
            if normal_results and normal_results.get('service_info'):
                cert_info = normal_results['service_info']
            else:
                cert_info = self._analyze_ssl_certificate(ip, port)
            results['service_info'].update(cert_info)

            # Step 3: Run aggressive nmap scan (all scripts)
            self.mark_step_completed(results, 'aggressive_nmap_scan')
            nmap_results = self._run_aggressive_https_scan(ip, port)
            results['nmap_data'] = nmap_results
            results['scan_mode'] = 'aggressive'

            if nmap_results.get('error'):
                print(f"⚠️ Aggressive nmap scan failed")
                results['nmap_enhanced'] = False
            else:
                results['nmap_enhanced'] = True
                nmap_service_info = nmap_results.get('service_info', {})
                results['service_info'].update(nmap_service_info)
                results['banner'] = nmap_results.get('banner', '')

            # Step 4: Parse aggressive findings
            self.mark_step_completed(results, 'aggressive_analysis')
            security_findings = self._parse_https_security_findings(nmap_results, aggressive=True)
            results['vulnerabilities'] = security_findings.get('vulnerabilities', [])
            results['recommendations'] = security_findings.get('recommendations', [])
            results['advanced_findings'] = security_findings.get('advanced_findings', {})

            # Step 5: Enhanced certificate security assessment
            cert_vulnerabilities = self._assess_certificate_security(cert_info, aggressive=True)
            results['vulnerabilities'].extend(cert_vulnerabilities)

            return self.finalize_results(results, success=True)

        except Exception as e:
            print(f"❌ HTTPS aggressive scan error: {e}")
            results['error'] = str(e)
            return self.finalize_results(results, success=False)

    def _check_https_connectivity(self, ip: str, port: int) -> Dict[str, Any]:
        """Check HTTPS connectivity and basic SSL handshake"""
        connectivity_info = {
            'accessible': False,
            'ssl_handshake_successful': False,
            'response_time': None,
            'ssl_version': None,
            'cipher_suite': None
        }

        try:
            start_time = time.time()

            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Connect and perform SSL handshake
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    response_time = round((time.time() - start_time) * 1000, 2)

                    connectivity_info.update({
                        'accessible': True,
                        'ssl_handshake_successful': True,
                        'response_time': response_time,
                        'ssl_version': ssock.version(),
                        'cipher_suite': ssock.cipher()[0] if ssock.cipher() else None,
                        'server_hostname': ip
                    })

        except socket.timeout:
            connectivity_info['failure_reason'] = 'Connection timed out'
        except ssl.SSLError as e:
            connectivity_info['failure_reason'] = f'SSL handshake failed: {str(e)}'
            connectivity_info['ssl_error'] = True
        except Exception as e:
            connectivity_info['failure_reason'] = f'Connection failed: {str(e)}'

        return connectivity_info

    def _analyze_ssl_certificate(self, ip: str, port: int) -> Dict[str, Any]:
        """Analyze SSL certificate details"""
        cert_info = {}

        try:
            # Get certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    cert_der = ssock.getpeercert(binary_form=True)

                    if cert:
                        cert_info.update({
                            'certificate_subject': dict(x[0] for x in cert.get('subject', [])),
                            'certificate_issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'certificate_version': cert.get('version'),
                            'certificate_serial_number': cert.get('serialNumber'),
                            'certificate_not_before': cert.get('notBefore'),
                            'certificate_not_after': cert.get('notAfter'),
                            'certificate_signature_algorithm': cert.get('signatureAlgorithm'),
                            'certificate_sans': cert.get('subjectAltName', [])
                        })

                        # Check certificate validity
                        cert_info['certificate_valid'] = self._is_certificate_valid(cert)
                        cert_info['certificate_expired'] = self._is_certificate_expired(cert)
                        cert_info['certificate_self_signed'] = self._is_self_signed_certificate(cert)

        except Exception as e:
            cert_info['certificate_error'] = str(e)

        return cert_info

    def _run_normal_https_scan(self, ip: str, port: int) -> Dict[str, Any]:
        """Run normal (safe) nmap HTTPS scan"""
        try:
            # Normal HTTPS scan - safe scripts only
            cmd = [
                'wsl', 'nmap', '-sV', f'-p{port}',
                '--script',
                'ssl-cert,ssl-enum-ciphers,http-headers,http-title,http-server-header,http-methods,http-security-headers',
                '--script-timeout', '60s',
                '--host-timeout', '300s',
                ip
            ]

            print(f"🔒 Running normal HTTPS scan: {' '.join(cmd)}")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=420)

            if result.returncode != 0:
                error_msg = f"Normal HTTPS nmap failed with return code {result.returncode}"
                if result.stderr:
                    error_msg += f": {result.stderr}"
                return {'error': error_msg}

            parsed = self._parse_nmap_https_output(result.stdout, aggressive=False)
            parsed['command_used'] = ' '.join(cmd)
            parsed['scan_type'] = 'normal'

            return parsed

        except subprocess.TimeoutExpired:
            return {'error': 'Normal HTTPS nmap scan timed out'}
        except Exception as e:
            return {'error': f'Normal HTTPS nmap execution failed: {str(e)}'}

    def _run_normal_https_scan_with_directory_enum(self, ip: str, port: int, custom_paths: List[str]) -> Dict[str, Any]:
        """Run normal HTTPS scan with directory enumeration using custom wordlist"""
        wordlist_path = None
        try:
            print(f"🔍 Starting HTTPS scan with custom directory enumeration")
            print(f"📝 Creating custom wordlist with {len(custom_paths)} paths")

            # Create wordlist file in a location accessible to WSL
            wordlist_path = self._create_wsl_compatible_wordlist(custom_paths)
            print(f"📄 Wordlist created at: {wordlist_path}")

            cmd = [
                'wsl', 'nmap', '-sV', f'-p{port}', '-T4',
                '--script',
                'ssl-cert,ssl-enum-ciphers,http-headers,http-title,http-server-header,http-methods,http-security-headers,http-enum',
                '--script-args', f'http-enum.basepath=/,-http-enum.urlfile={wordlist_path}',
                '--script-timeout', '120s',
                '--host-timeout', '500s',
                '-v',
                ip
            ]

            print(f"🚀 Running HTTPS scan with directory enumeration:")
            print(f"   Command: {' '.join(cmd)}")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            # Clean up wordlist file
            self._cleanup_wordlist(wordlist_path)

            if result.returncode != 0:
                error_msg = f"HTTPS nmap with directory enum failed with return code {result.returncode}"
                if result.stderr:
                    error_msg += f": {result.stderr}"
                print(f"❌ {error_msg}")
                return {'error': error_msg}

            print(f"✅ Nmap scan completed successfully")
            print(f"📊 Output length: {len(result.stdout)} characters")

            # Parse the output
            parsed = self._parse_nmap_https_output(result.stdout, aggressive=False)
            parsed['command_used'] = ' '.join(cmd)
            parsed['scan_type'] = 'normal_with_directory_enum'

            # Parse directory enumeration results specifically
            directories_found = self._parse_http_enum_results(result.stdout)
            print(f"🔍 Found {len(directories_found)} directories/files")

            parsed['directory_enumeration'] = {
                'directories_found': directories_found,
                'custom_wordlist_used': True,
                'wordlist_size': len(custom_paths),
                'wordlist_path_used': wordlist_path,
                'scan_output_snippet': result.stdout[:1000] if result.stdout else 'No output'
            }

            # Debug output
            if directories_found:
                print(f"📁 Directories found: {directories_found}")
            else:
                print("🔍 No directories found - checking if http-enum ran...")
                if 'http-enum' in result.stdout:
                    print("✅ http-enum script executed")
                else:
                    print("❌ http-enum script may not have executed")

            return parsed

        except subprocess.TimeoutExpired:
            self._cleanup_wordlist(wordlist_path)
            return {'error': 'HTTPS nmap scan with directory enumeration timed out'}
        except Exception as e:
            self._cleanup_wordlist(wordlist_path)
            print(f"❌ Directory enumeration error: {e}")
            return {'error': f'HTTPS nmap execution failed: {str(e)}'}

    def _create_wsl_compatible_wordlist(self, custom_paths: List[str]) -> str:
        """Create a simple wordlist file for http-enum using urlfile parameter"""
        try:
            import time
            import os

            # Create unique filename - simple text file
            timestamp = int(time.time())
            wordlist_filename = f"wordlist_{timestamp}.txt"

            print(f"📝 Creating simple wordlist file: {wordlist_filename}")

            # Default paths if custom ones are empty
            if not custom_paths or len(custom_paths) == 0:
                custom_paths = [
                    'admin', 'login', 'wp-admin', 'robots.txt', 'api',
                    'uploads', '.git', 'config', 'backup', 'phpmyadmin',
                    'dashboard', 'panel', 'cpanel', 'administrator',
                    'test', 'dev', 'staging', 'temp', 'tmp', 'docs',
                    'documentation', 'help', 'support', 'downloads'
                ]

            # Write simple wordlist - one path per line with trailing slash for directories
            with open(wordlist_filename, 'w') as f:
                for path in custom_paths:
                    clean_path = path.strip().lstrip('/')
                    if clean_path and clean_path != '':
                        # Add trailing slash for directories (unless it's a file like robots.txt)
                        if not clean_path.endswith('.txt') and not clean_path.endswith(
                                '.html') and not clean_path.endswith('.xml'):
                            clean_path += '/'
                        f.write(f"{clean_path}\n")

            print(f"✅ Simple wordlist created with {len(custom_paths)} paths")

            # Verify file exists and show contents
            if os.path.exists(wordlist_filename):
                file_size = os.path.getsize(wordlist_filename)
                print(f"📄 Wordlist file size: {file_size} bytes")

                # Show file contents for debugging
                with open(wordlist_filename, 'r') as f:
                    content = f.read().strip()
                    lines = content.split('\n')
                    print(f"📋 Wordlist contents ({len(lines)} entries):")
                    for line in lines[:10]:  # Show first 10 entries
                        print(f"   {line}")
                    if len(lines) > 10:
                        print(f"   ... and {len(lines) - 10} more")

                return wordlist_filename
            else:
                raise Exception("Wordlist file was not created successfully")

        except Exception as e:
            print(f"❌ Error creating wordlist: {e}")
            raise Exception(f"Failed to create wordlist: {e}")

    def _cleanup_wordlist(self, wordlist_path: str):
        """Safely cleanup the wordlist file"""
        if not wordlist_path:
            return

        try:
            if os.path.exists(wordlist_path):
                os.unlink(wordlist_path)
                print(f"🗑️ Cleaned up wordlist: {wordlist_path}")
            else:
                print(f"⚠️ Wordlist file not found for cleanup: {wordlist_path}")
        except Exception as cleanup_error:
            print(f"⚠️ Cleanup warning for {wordlist_path}: {cleanup_error}")

    def _parse_http_enum_results(self, nmap_output: str) -> List[str]:
        """Parse directory enumeration results from http-enum script output"""
        directories = []

        print(f"🔍 Parsing http-enum results from output...")

        lines = nmap_output.split('\n')
        in_http_enum_section = False

        for line in lines:
            line_stripped = line.strip()

            # Check if we're in the http-enum section
            if 'http-enum:' in line_stripped or '|_http-enum:' in line_stripped:
                in_http_enum_section = True
                print(f"✅ Found http-enum section")
                continue

            # If we're in the http-enum section, look for results
            if in_http_enum_section:
                # Look for lines that contain paths - common formats:
                # | /admin/: Possible admin folder
                # |   /robots.txt: robots.txt file
                # |_  /wp-admin/: Wordpress Admin

                if line_stripped.startswith('|') and ':' in line_stripped:
                    # Try to extract path from the line
                    # Pattern: | /path/: description
                    match = re.search(r'\|\s*(/[^:]+):\s*(.+)', line_stripped)
                    if match:
                        path = match.group(1).strip()
                        description = match.group(2).strip()

                        if path not in directories:
                            directories.append(path)
                            print(f"📁 Found directory: {path} - {description}")

                # Check if we've left the http-enum section
                elif line_stripped and not line_stripped.startswith('|') and not line_stripped.startswith('PORT'):
                    if in_http_enum_section and directories:
                        break  # We've found results and left the section

        print(f"🎯 Total directories/files found: {len(directories)}")

        # Enhanced debugging if no directories found
        if not directories:
            print("🔍 No directories found. Enhanced debugging...")

            # Check if http-enum was mentioned at all
            if 'http-enum' in nmap_output.lower():
                print("✅ http-enum script was mentioned in output")

                # Look for any http-enum related lines
                enum_lines = [line for line in lines if 'http-enum' in line.lower()]
                if enum_lines:
                    print(f"🔍 Http-enum related lines ({len(enum_lines)}):")
                    for line in enum_lines[:5]:  # Show first 5
                        print(f"   {line.strip()}")

                # Show a sample of the output around http-enum section
                for i, line in enumerate(lines):
                    if 'http-enum' in line.lower():
                        print(f"🔍 Context around http-enum (lines {max(0, i - 2)} to {min(len(lines), i + 5)}):")
                        for j in range(max(0, i - 2), min(len(lines), i + 5)):
                            marker = ">>> " if j == i else "    "
                            print(f"   {marker}{lines[j].strip()}")
                        break

            else:
                print("❌ http-enum script was not mentioned in output")
                print("🔍 This suggests the script didn't run or failed silently")

                # Check for common script indicators
                script_indicators = ['script scan', 'NSE', 'script args', 'script-help']
                for indicator in script_indicators:
                    if indicator in nmap_output.lower():
                        print(f"✅ Found script indicator: {indicator}")
                        break
                else:
                    print("❌ No script execution indicators found")

        return directories

    def _run_aggressive_https_scan(self, ip: str, port: int) -> Dict[str, Any]:
        """Run aggressive (comprehensive) nmap HTTPS scan"""
        try:
            # Aggressive HTTPS scan - all scripts
            cmd = [
                'wsl', 'nmap', '-sV', '-A', f'-p{port}',
                '--script', 'ssl-*,http-*',
                '--script-args', 'http-methods.url-path=/,http-enum.displayall',
                '--script-timeout', '120s',
                '--host-timeout', '600s',
                ip
            ]

            print(f"🎯 Running aggressive HTTPS scan: {' '.join(cmd)}")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=720)

            if result.returncode != 0:
                error_msg = f"Aggressive HTTPS nmap failed with return code {result.returncode}"
                if result.stderr:
                    error_msg += f": {result.stderr}"
                return {'error': error_msg}

            parsed = self._parse_nmap_https_output(result.stdout, aggressive=True)
            parsed['command_used'] = ' '.join(cmd)
            parsed['scan_type'] = 'aggressive'

            return parsed

        except subprocess.TimeoutExpired:
            return {'error': 'Aggressive HTTPS nmap scan timed out'}
        except Exception as e:
            return {'error': f'Aggressive HTTPS nmap execution failed: {str(e)}'}

    def _parse_nmap_https_output(self, nmap_output: str, aggressive: bool = False) -> Dict[str, Any]:
        """Parse nmap HTTPS output"""
        parsed = {
            'service_info': {},
            'banner': '',
            'ssl_info': {},
            'web_info': {},
            'scripts': {},
            'raw_output': nmap_output,
            'formatted_for_display': self._format_https_output(nmap_output)
        }

        lines = nmap_output.split('\n')

        for line in lines:
            line_stripped = line.strip()

            # Parse HTTPS service line
            if '/tcp' in line and ('https' in line.lower() or 'ssl' in line.lower()):
                parsed['service_info']['protocol'] = 'TCP'
                parsed['service_info']['service'] = 'HTTPS'
                parsed['banner'] = line_stripped

                # Extract server info
                server_match = re.search(r'(Apache|nginx|IIS|lighttpd)[/\s]*([\d\.]+)?', line)
                if server_match:
                    parsed['service_info']['server_type'] = server_match.group(1)
                    if server_match.group(2):
                        parsed['service_info']['server_version'] = server_match.group(2)

            # Parse SSL/HTTPS script results
            elif line_stripped.startswith('|_ssl-') or line_stripped.startswith('| ssl-'):
                script_name = self._extract_script_name(line_stripped, 'ssl')
                if script_name:
                    content = self._extract_script_content(line_stripped, script_name)
                    parsed['scripts'][script_name] = content

            elif line_stripped.startswith('|_http-') or line_stripped.startswith('| http-'):
                script_name = self._extract_script_name(line_stripped, 'http')
                if script_name:
                    content = self._extract_script_content(line_stripped, script_name)
                    parsed['scripts'][script_name] = content

        return parsed

    def _parse_https_security_findings(self, nmap_data: Dict[str, Any], aggressive: bool = False) -> Dict[str, Any]:
        """Parse HTTPS security findings from nmap results"""
        findings = {
            'vulnerabilities': [],
            'recommendations': [],
            'advanced_findings': {}
        }

        if not nmap_data or nmap_data.get('error'):
            return findings

        scripts = nmap_data.get('scripts', {})

        # SSL/TLS Security Analysis
        ssl_findings = self._analyze_ssl_findings(scripts, aggressive)
        findings['vulnerabilities'].extend(ssl_findings.get('vulnerabilities', []))
        findings['advanced_findings']['ssl_analysis'] = ssl_findings.get('ssl_analysis', {})

        # Web Security Analysis
        web_findings = self._analyze_web_findings(scripts, aggressive)
        findings['vulnerabilities'].extend(web_findings.get('vulnerabilities', []))
        findings['advanced_findings']['web_analysis'] = web_findings.get('web_analysis', {})

        # Generate recommendations
        findings['recommendations'] = self._generate_https_recommendations(findings['vulnerabilities'], aggressive)

        return findings

    def _analyze_ssl_findings(self, scripts: Dict[str, Any], aggressive: bool) -> Dict[str, Any]:
        """Analyze SSL-related findings"""
        ssl_findings = {
            'vulnerabilities': [],
            'ssl_analysis': {}
        }

        # Check for major SSL vulnerabilities
        if 'ssl-heartbleed' in scripts:
            if 'VULNERABLE' in scripts['ssl-heartbleed'].upper():
                ssl_findings['vulnerabilities'].append({
                    'id': 'SSL-HEARTBLEED-001',
                    'severity': 'Critical',
                    'title': 'Heartbleed Vulnerability Detected',
                    'description': 'Server is vulnerable to the Heartbleed attack (CVE-2014-0160)',
                    'recommendation': 'Update OpenSSL immediately and regenerate certificates',
                    'source': 'nmap_ssl',
                    'detection_method': 'ssl-heartbleed'
                })

        if 'ssl-poodle' in scripts:
            if 'VULNERABLE' in scripts['ssl-poodle'].upper():
                ssl_findings['vulnerabilities'].append({
                    'id': 'SSL-POODLE-001',
                    'severity': 'High',
                    'title': 'POODLE Vulnerability Detected',
                    'description': 'Server is vulnerable to POODLE attack',
                    'recommendation': 'Disable SSLv3 and use TLS 1.2 or higher',
                    'source': 'nmap_ssl',
                    'detection_method': 'ssl-poodle'
                })

        if 'sslv2' in scripts:
            ssl_findings['vulnerabilities'].append({
                'id': 'SSL-SSLV2-001',
                'severity': 'High',
                'title': 'SSLv2 Protocol Enabled',
                'description': 'Deprecated SSLv2 protocol is enabled',
                'recommendation': 'Disable SSLv2 and use TLS 1.2 or higher',
                'source': 'nmap_ssl',
                'detection_method': 'sslv2'
            })

        # Certificate analysis
        if 'ssl-cert' in scripts:
            ssl_findings['ssl_analysis']['certificate_info'] = scripts['ssl-cert']

        if aggressive and 'ssl-enum-ciphers' in scripts:
            ssl_findings['ssl_analysis']['cipher_analysis'] = scripts['ssl-enum-ciphers']
            # Parse weak ciphers
            weak_ciphers = self._parse_weak_ciphers(scripts['ssl-enum-ciphers'])
            if weak_ciphers:
                ssl_findings['vulnerabilities'].append({
                    'id': 'SSL-WEAK-CIPHER-001',
                    'severity': 'Medium',
                    'title': 'Weak SSL Ciphers Detected',
                    'description': f'Weak cipher suites detected: {", ".join(weak_ciphers)}',
                    'recommendation': 'Disable weak cipher suites and enable only strong encryption',
                    'source': 'nmap_ssl',
                    'detection_method': 'ssl-enum-ciphers'
                })

        return ssl_findings

    def _analyze_web_findings(self, scripts: Dict[str, Any], aggressive: bool) -> Dict[str, Any]:
        """Analyze web-related findings"""
        web_findings = {
            'vulnerabilities': [],
            'web_analysis': {}
        }

        # Security headers analysis
        if 'http-security-headers' in scripts:
            headers_analysis = self._parse_security_headers(scripts['http-security-headers'])
            web_findings['web_analysis']['security_headers'] = headers_analysis

            missing_headers = headers_analysis.get('missing_headers', [])
            if missing_headers:
                web_findings['vulnerabilities'].append({
                    'id': 'HTTP-HEADERS-001',
                    'severity': 'Medium',
                    'title': 'Missing Security Headers',
                    'description': f'Missing security headers: {", ".join(missing_headers)}',
                    'recommendation': 'Implement missing security headers to improve web security',
                    'source': 'nmap_http',
                    'detection_method': 'http-security-headers'
                })

        # Server information disclosure
        if 'http-server-header' in scripts:
            web_findings['web_analysis']['server_info'] = scripts['http-server-header']

        if aggressive:
            # Directory enumeration results
            if 'http-enum' in scripts:
                web_findings['web_analysis']['directories_found'] = scripts['http-enum']

            # Backup file detection
            if 'http-backup-finder' in scripts:
                web_findings['web_analysis']['backup_files'] = scripts['http-backup-finder']

            # Vulnerability testing results
            if 'http-sql-injection' in scripts:
                if 'VULNERABLE' in scripts['http-sql-injection'].upper():
                    web_findings['vulnerabilities'].append({
                        'id': 'HTTP-SQLI-001',
                        'severity': 'High',
                        'title': 'SQL Injection Vulnerability',
                        'description': 'Potential SQL injection vulnerability detected',
                        'recommendation': 'Implement proper input validation and parameterized queries',
                        'source': 'nmap_http',
                        'detection_method': 'http-sql-injection'
                    })

        return web_findings

    def _assess_certificate_security(self, cert_info: Dict[str, Any], aggressive: bool = False) -> List[Dict[str, Any]]:
        """Assess certificate security issues"""
        vulnerabilities = []

        if cert_info.get('certificate_expired'):
            vulnerabilities.append({
                'id': 'CERT-EXPIRED-001',
                'severity': 'High',
                'title': 'SSL Certificate Expired',
                'description': 'SSL certificate has expired',
                'recommendation': 'Renew SSL certificate immediately',
                'source': 'certificate_analysis',
                'detection_method': 'certificate_validity_check'
            })

        if cert_info.get('certificate_self_signed'):
            vulnerabilities.append({
                'id': 'CERT-SELF-SIGNED-001',
                'severity': 'Medium',
                'title': 'Self-Signed Certificate',
                'description': 'Server uses a self-signed certificate',
                'recommendation': 'Use a certificate from a trusted Certificate Authority',
                'source': 'certificate_analysis',
                'detection_method': 'certificate_issuer_check'
            })

        return vulnerabilities

    def _generate_https_recommendations(self, vulnerabilities: List[Dict], aggressive: bool) -> List[str]:
        """Generate HTTPS security recommendations"""
        recommendations = [
            'Use TLS 1.2 or higher protocols only',
            'Implement HTTP Strict Transport Security (HSTS)',
            'Use strong cipher suites and disable weak encryption',
            'Keep SSL certificates updated and from trusted CAs',
            'Implement proper security headers (CSP, X-Frame-Options, etc.)'
        ]

        if aggressive:
            recommendations.extend([
                'Regular security scanning and vulnerability assessment',
                'Implement Web Application Firewall (WAF)',
                'Use certificate pinning for mobile applications',
                'Enable perfect forward secrecy (PFS)',
                'Monitor certificate transparency logs'
            ])

        return recommendations

    # Helper methods
    def _is_certificate_valid(self, cert: Dict) -> bool:
        """Check if certificate is currently valid"""
        try:
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            return not_before <= now <= not_after
        except:
            return False

    def _is_certificate_expired(self, cert: Dict) -> bool:
        """Check if certificate is expired"""
        try:
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            return now > not_after
        except:
            return False

    def _is_self_signed_certificate(self, cert: Dict) -> bool:
        """Check if certificate is self-signed"""
        try:
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer = dict(x[0] for x in cert.get('issuer', []))
            return subject == issuer
        except:
            return False

    def _extract_script_name(self, line: str, prefix: str) -> Optional[str]:
        """Extract script name from nmap output line"""
        try:
            if line.startswith('|_'):
                parts = line.split(':', 1)
                if len(parts) >= 1:
                    return parts[0].replace('|_', '').strip()
            elif line.startswith('| '):
                parts = line.split(':', 1)
                if len(parts) >= 1:
                    return parts[0].replace('| ', '').strip()
        except:
            pass
        return None

    def _extract_script_content(self, line: str, script_name: str) -> str:
        """Extract content from script output line"""
        try:
            content = line.replace(f'|_{script_name}:', '').replace(f'| {script_name}:', '').strip()
            return content if content else 'Script executed'
        except:
            return 'Script executed'

    def _format_https_output(self, nmap_output: str) -> str:
        """Format HTTPS nmap output for display"""
        lines = nmap_output.split('\n')
        important_lines = []

        for line in lines:
            line_lower = line.lower()
            if any(keyword in line_lower for keyword in [
                'port', 'state', 'service', 'ssl-', 'http-', 'https', 'certificate',
                'cipher', 'vulnerable', 'security', 'header'
            ]):
                important_lines.append(line)

        return '\n'.join(important_lines) if important_lines else nmap_output

    def _parse_weak_ciphers(self, cipher_output: str) -> List[str]:
        """Parse weak ciphers from ssl-enum-ciphers output"""
        weak_ciphers = []
        weak_indicators = ['rc4', 'des', 'md5', 'null', 'export']

        for line in cipher_output.split('\n'):
            line_lower = line.lower()
            if any(weak in line_lower for weak in weak_indicators):
                # Extract cipher name
                parts = line.strip().split()
                if parts:
                    weak_ciphers.append(parts[0])

        return weak_ciphers[:5]  # Limit to first 5 weak ciphers

    def _parse_security_headers(self, headers_output: str) -> Dict[str, Any]:
        """Parse security headers analysis"""
        analysis = {
            'headers_present': [],
            'missing_headers': [],
            'header_details': {}
        }

        important_headers = [
            'strict-transport-security',
            'content-security-policy',
            'x-frame-options',
            'x-content-type-options',
            'x-xss-protection'
        ]

        for header in important_headers:
            if header in headers_output.lower():
                analysis['headers_present'].append(header)
            else:
                analysis['missing_headers'].append(header)

        return analysis