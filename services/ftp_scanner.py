import ftplib
import socket
import ssl
import time
import random
import re
from datetime import datetime
from typing import Dict, Any, List
from .base_scanner import BaseScanner
import subprocess


class FTPScanner(BaseScanner):
    """Advanced FTP Scanner with Kali WSL nmap integration - Fixed script names"""

    def __init__(self, timeout: int = 10):
        super().__init__(timeout)
        self.common_users = [
            'anonymous', 'ftp', 'admin', 'root', 'user', 'test', 'guest',
            'ftpuser', 'demo', 'anonymous@', 'ftp@', 'public'
        ]
        self.common_passwords = [
            '', 'anonymous', 'guest', 'ftp', 'password', '123456', 'admin',
            'test', 'demo', 'public', 'anonymous@example.com', 'ftp@ftp.com'
        ]

    def get_supported_ports(self) -> List[int]:
        return [21, 990, 2121, 8021]  # Standard FTP and FTPS

    def get_service_name(self) -> str:
        return "FTP"

    def scan(self, ip: str, port: int, **kwargs) -> Dict[str, Any]:
        """Standard FTP scanning with Kali WSL nmap integration"""
        self.scan_start_time = time.time()
        results = self.create_base_result(ip, port)

        try:
            # Step 1: Basic connectivity check
            self.mark_step_completed(results, 'connectivity')
            connectivity_info = self.check_port_connectivity(ip, port)
            results['connectivity_info'] = connectivity_info

            if not connectivity_info.get('accessible'):
                return self.create_failed_result(ip, port,
                                                 connectivity_info.get('failure_reason', 'FTP service not accessible'),
                                                 connectivity_info)

            # Step 2: Run Kali WSL nmap scan
            self.mark_step_completed(results, 'nmap_scan')
            nmap_results = self._run_nmap_scan(ip, port, aggressive=False)
            results['nmap_data'] = nmap_results

            # Extract service info from nmap
            self.update_service_info(results, nmap_results.get('service_info', {}))
            results['banner'] = nmap_results.get('banner', '')

            # Step 3: Complementary enumeration (only what nmap doesn't do)
            self.mark_step_completed(results, 'enumeration')
            enum_info = self._complementary_enumeration(ip, port)
            results['advanced_findings'].update(enum_info)

            # Step 4: Security assessment based on nmap + enumeration
            self.mark_step_completed(results, 'vulnerability')
            security_info = self._security_assessment(results['service_info'], enum_info, results['nmap_data'])
            results['vulnerabilities'] = security_info.get('vulnerabilities', [])
            results['recommendations'] = security_info.get('recommendations', [])

            return self.finalize_results(results, success=True)

        except Exception as e:
            results['error'] = str(e)
            return self.finalize_results(results, success=False)

    def scan_aggressive(self, ip: str, port: int, **kwargs) -> Dict[str, Any]:
        """Aggressive FTP scanning with comprehensive Kali WSL nmap scripts"""
        self.scan_start_time = time.time()
        results = self.create_base_result(ip, port)

        try:
            # Step 1: Basic connectivity check
            self.mark_step_completed(results, 'connectivity')
            connectivity_info = self.check_port_connectivity(ip, port)
            results['connectivity_info'] = connectivity_info

            if not connectivity_info.get('accessible'):
                return self.create_failed_result(ip, port,
                                                 connectivity_info.get('failure_reason', 'FTP service not accessible'),
                                                 connectivity_info)

            # Step 2: Run aggressive Kali WSL nmap scan with all FTP scripts
            self.mark_step_completed(results, 'aggressive_nmap_scan')
            nmap_results = self._run_nmap_scan(ip, port, aggressive=True)
            results['nmap_data'] = nmap_results
            results['scan_mode'] = 'aggressive'

            # Extract enhanced service info
            self.update_service_info(results, nmap_results.get('service_info', {}))
            results['banner'] = nmap_results.get('banner', '')

            # Step 3: Complementary enumeration for aggressive mode
            self.mark_step_completed(results, 'aggressive_enumeration')
            enum_info = self._complementary_enumeration(ip, port)
            results['advanced_findings'].update(enum_info)

            # Step 4: Enhanced security assessment for aggressive mode
            self.mark_step_completed(results, 'aggressive_vulnerability')
            security_info = self._security_assessment(results['service_info'], enum_info, results['nmap_data'],
                                                      aggressive=True)
            results['vulnerabilities'] = security_info.get('vulnerabilities', [])
            results['recommendations'] = security_info.get('recommendations', [])

            return self.finalize_results(results, success=True)

        except Exception as e:
            results['error'] = str(e)
            return self.finalize_results(results, success=False)

    def _run_nmap_scan(self, ip: str, port: int, aggressive: bool = False) -> Dict[str, Any]:
        """Run nmap scan with Kali WSL integration - EXACT SAME LOGIC"""

        # First, try WSL (Kali) - if available
        wsl_result = self._try_wsl_nmap(ip, port, aggressive)
        if not wsl_result.get('error'):
            print(f"✅ Using Kali WSL for nmap scan")
            return wsl_result

        # Fallback to original Windows logic if WSL fails
        print(f"⚠️ WSL failed, falling back to Windows nmap: {wsl_result.get('error')}")
        return self._original_nmap_scan(ip, port, aggressive)

    def _try_wsl_nmap(self, ip: str, port: int, aggressive: bool = False) -> Dict[str, Any]:
        """Try nmap through Kali WSL - SAME COMMANDS as your working Kali"""
        try:
            if aggressive:
                # EXACT same aggressive command you use in Kali
                cmd = [
                    'wsl', 'nmap', '-sV', '-sC', f'-p{port}',
                    '--script=ftp-*', '--script-timeout=45s', '--host-timeout=300s',
                    '-A', ip
                ]

                timeout = 360
                print(f"🐧 Kali WSL Aggressive FTP scan: {' '.join(cmd[1:])}")
            else:
                # EXACT same safe command you use in Kali
                cmd = ['wsl', 'nmap', '-Pn', '-sV', '-sC', f'-p{port}', '--script=ftp-anon,ftp-bounce,ftp-syst', ip]
                print(f"🐧 Kali WSL Safe FTP scan: {' '.join(cmd[1:])}")
                timeout = 120

            # Execute through WSL
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

            print(f"WSL return code: {result.returncode}")
            print(f"WSL stdout length: {len(result.stdout)}")
            if result.stderr:
                print(f"WSL stderr: {result.stderr}")

            if result.returncode != 0:
                return {'error': f'WSL nmap failed: {result.stderr}'}

            if not result.stdout:
                return {'error': 'WSL nmap returned no output'}

            # Use your EXACT SAME parsing logic
            parsed = self._parse_nmap_output(result.stdout)
            parsed['scan_type'] = 'aggressive' if aggressive else 'safe'
            parsed['command_used'] = ' '.join(cmd[1:])  # Show command without 'wsl'
            parsed['tool_used'] = 'nmap_via_kali_wsl'

            return parsed

        except FileNotFoundError:
            return {'error': 'WSL not found on this system'}
        except subprocess.TimeoutExpired:
            return {'error': 'WSL nmap timed out'}
        except Exception as e:
            return {'error': f'WSL nmap failed: {str(e)}'}

    def _original_nmap_scan(self, ip: str, port: int, aggressive: bool = False) -> Dict[str, Any]:
        """Your original nmap logic - UNCHANGED"""
        if not self.check_nmap_available():
            return {'error': 'Nmap not available on this system'}

        try:
            if aggressive:
                cmd = ['nmap', '-sV', '-sC', f'-p{port}', '--script=ftp-*', '-A', ip]
            else:
                cmd = ['nmap', '-Pn', '-sV', '-sC', f'-p{port}', '--script=ftp-anon,ftp-bounce,ftp-syst', ip]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode != 0:
                return {'error': f'Nmap scan failed: {result.stderr}'}

            parsed = self._parse_nmap_output(result.stdout)
            parsed['command_used'] = ' '.join(cmd)
            parsed['tool_used'] = 'nmap_windows'

            return parsed

        except Exception as e:
            return {'error': f'Nmap execution failed: {str(e)}'}

    def _parse_nmap_output(self, nmap_output: str) -> Dict[str, Any]:
        """Enhanced parsing for clear FTP nmap output"""
        parsed = {
            'service_info': {},
            'banner': '',
            'ssl_info': {},
            'scripts': {},
            'raw_output': nmap_output,  # Keep full output
            'formatted_for_display': self._format_for_user_display(nmap_output)
        }

        lines = nmap_output.split('\n')

        for line in lines:
            line_stripped = line.strip()

            # Parse FTP service line
            if '/tcp' in line and ('ftp' in line.lower() or 'vsftpd' in line.lower()):
                parsed['service_info']['server_type'] = self._extract_server_type(line)
                parsed['service_info']['version'] = self._extract_version(line)
                parsed['banner'] = line_stripped

            # Parse script results - improved detection
            elif line_stripped.startswith('|_ftp-anon:'):
                parsed['scripts']['ftp-anon'] = line_stripped.replace('|_ftp-anon:', '').strip()
            elif line_stripped.startswith('|_ftp-bounce:'):
                parsed['scripts']['ftp-bounce'] = line_stripped.replace('|_ftp-bounce:', '').strip()
            elif line_stripped.startswith('|_ftp-syst:'):
                parsed['scripts']['ftp-syst'] = line_stripped.replace('|_ftp-syst:', '').strip()
            elif 'Anonymous FTP login allowed' in line:
                parsed['scripts']['ftp-anon'] = line_stripped

        return parsed

    def _format_for_user_display(self, nmap_output: str) -> str:
        """Format nmap output for clear user display"""
        lines = nmap_output.split('\n')
        important_lines = []

        for line in lines:
            # Keep important lines for user display
            if any(keyword in line for keyword in [
                'PORT', 'STATE', 'SERVICE', 'VERSION',
                'ftp-anon', 'ftp-bounce', 'ftp-syst',
                'Anonymous FTP', 'vsftpd', 'proftpd'
            ]):
                important_lines.append(line)

        return '\n'.join(important_lines) if important_lines else nmap_output

    def _extract_server_type(self, line: str) -> str:
        """Extract FTP server type from nmap output"""
        line_lower = line.lower()
        if 'vsftpd' in line_lower:
            return 'vsftpd'
        elif 'proftpd' in line_lower:
            return 'ProFTPD'
        elif 'pure-ftpd' in line_lower:
            return 'Pure-FTPd'
        elif 'filezilla' in line_lower:
            return 'FileZilla Server'
        elif 'microsoft ftp' in line_lower or 'iis' in line_lower:
            return 'Microsoft FTP/IIS'
        elif 'wu-ftpd' in line_lower:
            return 'WU-FTPD'
        elif 'ftp' in line_lower:
            return 'Generic FTP Server'
        return 'Unknown FTP Server'

    def _extract_version(self, line: str) -> str:
        """Extract version from nmap output"""
        version_match = re.search(r'(\d+\.[\d\.]+)', line)
        return version_match.group(1) if version_match else ''

    def _parse_script_line(self, line: str) -> tuple:
        """Parse nmap script output line"""
        if line.startswith('|_'):
            # Single line script result
            if ':' in line:
                parts = line[2:].split(':', 1)
                if len(parts) == 2:
                    return parts[0].strip(), parts[1].strip()
            else:
                return line[2:].strip(), ''
        elif line.startswith('|') and ':' in line:
            # Multi-line script header
            parts = line[1:].split(':', 1)
            if len(parts) == 2:
                script_name = parts[0].strip()
                script_result = parts[1].strip() if parts[1].strip() else None
                return script_name, script_result

        return None, None

    def _complementary_enumeration(self, ip: str, port: int) -> Dict[str, Any]:
        """Complementary enumeration that extends nmap results"""
        enum_info = {
            'detailed_anonymous_analysis': {},
            'user_enumeration': {},
            'file_system_analysis': {}
        }

        try:
            # Detailed anonymous access analysis (more detailed than nmap ftp-anon)
            enum_info['detailed_anonymous_analysis'] = self._detailed_anonymous_access(ip, port)

            # User enumeration via timing attacks (nmap doesn't do this)
            enum_info['user_enumeration'] = self._enumerate_users_timing(ip, port)

            # File system analysis if anonymous access works
            if enum_info['detailed_anonymous_analysis'].get('allowed', False):
                enum_info['file_system_analysis'] = self._analyze_file_system(ip, port)

        except Exception as e:
            enum_info['error'] = str(e)

        return enum_info

    def _detailed_anonymous_access(self, ip: str, port: int) -> Dict[str, Any]:
        """Detailed anonymous access testing beyond nmap ftp-anon"""
        anon_info = {
            'allowed': False,
            'writable': False,
            'readable': False,
            'login_methods': [],
            'directory_listing': [],
            'write_test_result': None,
            'permissions_detail': {}
        }

        login_attempts = [
            ('anonymous', 'anonymous'),
            ('anonymous', ''),
            ('anonymous', 'guest@example.com'),
            ('anonymous', 'test@test.com'),
            ('ftp', 'ftp'),
            ('guest', ''),
            ('public', 'public')
        ]

        for username, password in login_attempts:
            try:
                ftp = ftplib.FTP()
                ftp.connect(ip, port, timeout=self.timeout)
                ftp.login(username, password)

                anon_info['allowed'] = True
                anon_info['login_methods'].append(f"{username}:{password}")

                # Test directory listing capability
                try:
                    files = []
                    ftp.dir(files.append)
                    anon_info['readable'] = True
                    anon_info['directory_listing'] = files[:10]  # First 10 entries
                except Exception as e:
                    anon_info['permissions_detail']['dir_listing_error'] = str(e)

                # Test write capability with temporary file
                try:
                    test_filename = f"reconlite_test_{random.randint(10000, 99999)}.tmp"
                    test_content = b"ReconLite write test"

                    from io import BytesIO
                    test_file = BytesIO(test_content)
                    ftp.storbinary(f'STOR {test_filename}', test_file)

                    anon_info['writable'] = True
                    anon_info['write_test_result'] = 'success'

                    # Clean up test file
                    try:
                        ftp.delete(test_filename)
                    except:
                        anon_info['write_test_result'] = 'success_but_cleanup_failed'

                except Exception as e:
                    anon_info['write_test_result'] = f'failed: {str(e)}'

                # Test directory navigation
                try:
                    current_dir = ftp.pwd()
                    ftp.cwd('..')
                    parent_dir = ftp.pwd()
                    anon_info['permissions_detail']['directory_traversal'] = parent_dir != current_dir
                    ftp.cwd(current_dir)  # Return to original
                except Exception as e:
                    anon_info['permissions_detail']['traversal_error'] = str(e)

                ftp.quit()
                break  # Success, no need to try other credentials

            except Exception as e:
                continue

        return anon_info

    def _enumerate_users_timing(self, ip: str, port: int) -> Dict[str, Any]:
        """User enumeration through timing analysis"""
        user_enum = {
            'timing_analysis': {},
            'potential_users': [],
            'analysis_method': 'response_timing',
            'baseline_time': 0
        }

        try:
            # Establish baseline with non-existent user
            baseline_times = []
            for i in range(3):
                start_time = time.time()
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(ip, port, timeout=self.timeout)
                    ftp.login(f'nonexistent_user_{i}', 'invalid_pass')
                except:
                    pass
                baseline_times.append((time.time() - start_time) * 1000)
                time.sleep(0.5)

            user_enum['baseline_time'] = sum(baseline_times) / len(baseline_times)

            # Test common usernames
            for username in self.common_users[:8]:  # Limit to avoid detection
                try:
                    start_time = time.time()
                    ftp = ftplib.FTP()
                    ftp.connect(ip, port, timeout=self.timeout)

                    try:
                        ftp.login(username, 'definitely_wrong_password_12345')
                    except ftplib.error_perm as e:
                        response_time = (time.time() - start_time) * 1000

                        user_enum['timing_analysis'][username] = {
                            'response_time': response_time,
                            'error_message': str(e),
                            'time_difference': response_time - user_enum['baseline_time']
                        }

                        # If response is significantly different, user might exist
                        if abs(response_time - user_enum['baseline_time']) > 200:  # 200ms threshold
                            user_enum['potential_users'].append(username)

                    ftp.quit()
                except:
                    pass

                time.sleep(1)  # Rate limiting

        except Exception as e:
            user_enum['error'] = str(e)

        return user_enum

    def _analyze_file_system(self, ip: str, port: int) -> Dict[str, Any]:
        """Analyze accessible file system structure"""
        fs_info = {
            'directories': [],
            'files': [],
            'file_types': {},
            'interesting_files': [],
            'total_items': 0
        }

        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=self.timeout)

            # Use first working anonymous login
            for username, password in [('anonymous', 'anonymous'), ('anonymous', ''), ('ftp', 'ftp')]:
                try:
                    ftp.login(username, password)
                    break
                except:
                    continue

            # Get detailed directory listing
            items = []
            ftp.dir(items.append)

            for item in items[:50]:  # Limit analysis
                fs_info['total_items'] += 1

                # Parse directory listing format
                if item.startswith('d'):
                    # Directory
                    dir_name = item.split()[-1]
                    fs_info['directories'].append(dir_name)
                elif item.startswith('-'):
                    # File
                    file_name = item.split()[-1]
                    fs_info['files'].append(file_name)

                    # Analyze file types
                    if '.' in file_name:
                        ext = file_name.split('.')[-1].lower()
                        fs_info['file_types'][ext] = fs_info['file_types'].get(ext, 0) + 1

                    # Check for interesting files
                    interesting_patterns = [
                        'config', 'backup', 'password', 'secret', 'private',
                        'key', 'cert', 'sql', 'db', 'log'
                    ]

                    if any(pattern in file_name.lower() for pattern in interesting_patterns):
                        fs_info['interesting_files'].append(file_name)

            ftp.quit()

        except Exception as e:
            fs_info['error'] = str(e)

        return fs_info

    def _security_assessment(self, service_info: Dict[str, Any], enum_info: Dict[str, Any],
                             nmap_data: Dict[str, Any], aggressive: bool = False) -> Dict[str, Any]:
        """Security assessment using nmap data + enumeration results"""
        vulnerabilities = []
        recommendations = []

        # Get nmap script results
        scripts = nmap_data.get('scripts', {})

        # Process nmap script findings first
        self._process_nmap_script_findings(scripts, vulnerabilities, aggressive)

        # Add findings from manual enumeration
        self._process_manual_findings(enum_info, vulnerabilities, scripts)

        # Add service-specific vulnerabilities based on version
        self._check_version_vulnerabilities(service_info, vulnerabilities)

        # Generate recommendations
        recommendations = self._generate_recommendations(vulnerabilities, service_info, aggressive)

        return {
            'vulnerabilities': vulnerabilities,
            'recommendations': recommendations
        }

    def _process_nmap_script_findings(self, scripts: Dict[str, Any], vulnerabilities: List[Dict], aggressive: bool):
        """Process nmap NSE script findings"""

        # ftp-anon script results
        if 'ftp-anon' in scripts:
            anon_result = scripts['ftp-anon'].lower()
            if 'anonymous ftp login allowed' in anon_result or 'login allowed' in anon_result:
                severity = 'Critical' if 'write' in anon_result or 'writable' in anon_result else 'High'
                vulnerabilities.append({
                    'id': 'FTP-ANON-001',
                    'severity': severity,
                    'title': 'Anonymous FTP Access Enabled',
                    'description': f'NSE Detection: {scripts["ftp-anon"]}',
                    'recommendation': 'Disable anonymous FTP access unless specifically required for public file sharing',
                    'source': 'nmap_nse',
                    'detection_method': 'ftp-anon_script'
                })

        # ftp-bounce script results
        if 'ftp-bounce' in scripts:
            bounce_result = scripts['ftp-bounce'].lower()
            if 'bounce working' in bounce_result or 'vulnerable' in bounce_result:
                vulnerabilities.append({
                    'id': 'FTP-BOUNCE-001',
                    'severity': 'Medium',
                    'title': 'FTP Bounce Attack Vulnerability',
                    'description': f'NSE Detection: {scripts["ftp-bounce"]}',
                    'recommendation': 'Configure FTP server to prevent PORT command abuse and disable bounce attacks',
                    'source': 'nmap_nse',
                    'detection_method': 'ftp-bounce_script'
                })

        # ftp-syst script results (system information disclosure)
        if 'ftp-syst' in scripts:
            syst_result = scripts['ftp-syst']
            if syst_result and len(syst_result.strip()) > 0:
                vulnerabilities.append({
                    'id': 'FTP-SYST-001',
                    'severity': 'Low',
                    'title': 'FTP System Information Disclosure',
                    'description': f'System information revealed: {syst_result}',
                    'recommendation': 'Configure FTP server to limit system information disclosure',
                    'source': 'nmap_nse',
                    'detection_method': 'ftp-syst_script'
                })

        # Process additional scripts from aggressive scan
        if aggressive:
            # Check for ProFTPD backdoor
            if 'ftp-proftpd-backdoor' in scripts:
                result = scripts['ftp-proftpd-backdoor'].lower()
                if 'vulnerable' in result or 'backdoor' in result:
                    vulnerabilities.append({
                        'id': 'FTP-PROFTPD-BACKDOOR',
                        'severity': 'Critical',
                        'title': 'ProFTPD Backdoor Vulnerability',
                        'description': f'NSE Detection: {scripts["ftp-proftpd-backdoor"]}',
                        'recommendation': 'Immediately update ProFTPD and verify system integrity',
                        'source': 'nmap_nse_aggressive',
                        'detection_method': 'ftp-proftpd-backdoor'
                    })

            # Check for vsftpd backdoor
            if 'ftp-vsftpd-backdoor' in scripts:
                result = scripts['ftp-vsftpd-backdoor'].lower()
                if 'vulnerable' in result or 'backdoor' in result:
                    vulnerabilities.append({
                        'id': 'FTP-VSFTPD-BACKDOOR',
                        'severity': 'Critical',
                        'title': 'vsftpd Backdoor Vulnerability',
                        'description': f'NSE Detection: {scripts["ftp-vsftpd-backdoor"]}',
                        'recommendation': 'Immediately replace vsftpd with a clean version',
                        'source': 'nmap_nse_aggressive',
                        'detection_method': 'ftp-vsftpd-backdoor'
                    })

            # Process any other ftp-* scripts
            for script_name, result in scripts.items():
                if script_name.startswith('ftp-') and script_name not in ['ftp-anon', 'ftp-bounce', 'ftp-syst']:
                    result_lower = result.lower()
                    if any(keyword in result_lower for keyword in ['vulnerable', 'exploit', 'backdoor', 'weakness']):
                        severity = 'Critical' if 'backdoor' in result_lower or 'exploit' in result_lower else 'High'
                        vulnerabilities.append({
                            'id': f'FTP-{script_name.upper().replace("-", "_")}',
                            'severity': severity,
                            'title': f'FTP Vulnerability: {script_name}',
                            'description': f'NSE Detection: {result}',
                            'recommendation': 'Review and remediate the detected FTP vulnerability',
                            'source': 'nmap_nse_aggressive',
                            'detection_method': script_name
                        })

    def _process_manual_findings(self, enum_info: Dict[str, Any], vulnerabilities: List[Dict], scripts: Dict[str, Any]):
        """Process manual enumeration findings"""

        # Detailed anonymous access findings
        anon_access = enum_info.get('detailed_anonymous_analysis', {})
        if anon_access.get('allowed', False):
            # Only add if nmap didn't already detect it
            if 'ftp-anon' not in scripts:
                severity = 'Critical' if anon_access.get('writable', False) else 'High'
                vulnerabilities.append({
                    'id': 'FTP-ANON-002',
                    'severity': severity,
                    'title': 'Anonymous FTP Access (Manual Verification)',
                    'description': f'Manual testing confirmed anonymous access with {len(anon_access.get("login_methods", []))} working login methods',
                    'recommendation': 'Disable anonymous FTP access unless specifically required',
                    'source': 'manual_verification',
                    'detection_method': 'manual_login_test'
                })

            # Check for writable anonymous access
            if anon_access.get('writable', False):
                vulnerabilities.append({
                    'id': 'FTP-WRITE-001',
                    'severity': 'Critical',
                    'title': 'Anonymous FTP Write Access',
                    'description': 'Anonymous users can upload files to the FTP server',
                    'recommendation': 'Remove write permissions for anonymous users immediately',
                    'source': 'manual_verification',
                    'detection_method': 'write_test'
                })

        # User enumeration findings
        user_enum = enum_info.get('user_enumeration', {})
        if user_enum.get('potential_users'):
            vulnerabilities.append({
                'id': 'FTP-ENUM-001',
                'severity': 'Medium',
                'title': 'FTP User Enumeration Possible',
                'description': f'Timing analysis suggests these users may exist: {", ".join(user_enum["potential_users"])}',
                'recommendation': 'Configure FTP server to provide consistent response times for invalid users',
                'source': 'manual_verification',
                'detection_method': 'timing_analysis'
            })

        # File system analysis findings
        fs_analysis = enum_info.get('file_system_analysis', {})
        if fs_analysis.get('interesting_files'):
            vulnerabilities.append({
                'id': 'FTP-EXPOSURE-001',
                'severity': 'Medium',
                'title': 'Sensitive Files Exposed via FTP',
                'description': f'Potentially sensitive files found: {", ".join(fs_analysis["interesting_files"][:5])}',
                'recommendation': 'Review exposed files and remove any sensitive information from public FTP access',
                'source': 'manual_verification',
                'detection_method': 'file_analysis'
            })

    def _check_version_vulnerabilities(self, service_info: Dict[str, Any], vulnerabilities: List[Dict]):
        """Check for known vulnerabilities based on FTP server version"""
        server_type = service_info.get('server_type', '').lower()
        version = service_info.get('version', '')

        # Known vulnerable versions
        if 'vsftpd' in server_type:
            if version.startswith('2.3.4'):
                vulnerabilities.append({
                    'id': 'FTP-CVE-2011-2523',
                    'severity': 'Critical',
                    'title': 'vsftpd 2.3.4 Backdoor Vulnerability',
                    'description': 'This version of vsftpd contains a backdoor that can be triggered via username containing ":)"',
                    'recommendation': 'Immediately upgrade vsftpd to version 3.0 or later',
                    'source': 'version_analysis',
                    'detection_method': 'version_banner'
                })

        elif 'proftpd' in server_type:
            if version.startswith('1.3.3'):
                vulnerabilities.append({
                    'id': 'FTP-CVE-2010-4221',
                    'severity': 'High',
                    'title': 'ProFTPD 1.3.3c Backdoor Vulnerability',
                    'description': 'This version of ProFTPD may contain a backdoor',
                    'recommendation': 'Upgrade ProFTPD to the latest stable version',
                    'source': 'version_analysis',
                    'detection_method': 'version_banner'
                })

        elif 'wu-ftpd' in server_type:
            # WU-FTPD has several known vulnerabilities
            vulnerabilities.append({
                'id': 'FTP-WUFTPD-001',
                'severity': 'High',
                'title': 'WU-FTPD Security Concerns',
                'description': 'WU-FTPD is no longer maintained and has known security issues',
                'recommendation': 'Replace WU-FTPD with a modern, actively maintained FTP server',
                'source': 'version_analysis',
                'detection_method': 'version_banner'
            })

    def _generate_recommendations(self, vulnerabilities: List[Dict], service_info: Dict[str, Any],
                                  aggressive: bool = False) -> List[str]:
        """Generate comprehensive security recommendations"""
        recommendations = []

        # Basic FTP security recommendations
        recommendations.extend([
            'Use FTPS (FTP over SSL/TLS) or SFTP instead of plain FTP',
            'Implement strong authentication mechanisms',
            'Configure proper user access controls and chroot jails',
            'Regular monitoring of FTP logs for suspicious activity'
        ])

        # SSL/TLS recommendations
        ssl_detected = service_info.get('ssl_info', {}).get('ssl_detected', False)
        if not ssl_detected:
            recommendations.append('Enable SSL/TLS encryption (FTPS) to protect data in transit')

        # Vulnerability-specific recommendations
        vuln_types = [v.get('id', '') for v in vulnerabilities]

        if any('ANON' in v_id for v_id in vuln_types):
            recommendations.extend([
                'Disable anonymous FTP access unless absolutely necessary',
                'If anonymous access is required, ensure it is read-only',
                'Place anonymous FTP in a separate, isolated directory'
            ])

        if any('BOUNCE' in v_id for v_id in vuln_types):
            recommendations.append('Configure firewall rules to prevent FTP bounce attacks')

        if any('ENUM' in v_id for v_id in vuln_types):
            recommendations.append('Implement rate limiting to prevent user enumeration attacks')

        if any('BACKDOOR' in v_id for v_id in vuln_types):
            recommendations.extend([
                'URGENT: Immediately replace the compromised FTP server software',
                'Perform full system integrity check and malware scan',
                'Review all FTP server logs for signs of compromise',
                'Change all FTP user passwords'
            ])

        if any('WRITE' in v_id for v_id in vuln_types):
            recommendations.extend([
                'Remove write permissions for anonymous users immediately',
                'Implement strict upload file type restrictions',
                'Enable virus scanning for uploaded files'
            ])

        # Aggressive scan specific recommendations
        if aggressive:
            recommendations.extend([
                'Perform regular vulnerability assessments with updated security tools',
                'Subscribe to security advisories for your FTP server software',
                'Implement intrusion detection/prevention systems (IDS/IPS)',
                'Consider replacing FTP with more secure alternatives like SFTP or SCP'
            ])

        # Server-specific recommendations
        server_type = service_info.get('server_type', '').lower()
        if 'vsftpd' in server_type:
            recommendations.append('Keep vsftpd updated to the latest stable version')
        elif 'proftpd' in server_type:
            recommendations.append('Keep ProFTPD updated and review configuration for security best practices')
        elif 'pure-ftpd' in server_type:
            recommendations.append('Configure Pure-FTPd with security hardening options')
        elif 'wu-ftpd' in server_type:
            recommendations.append(
                'Replace WU-FTPD with a modern, maintained FTP server (vsftpd, ProFTPD, or Pure-FTPd)')

        # General hardening recommendations
        recommendations.extend([
            'Disable unused FTP commands and features',
            'Implement connection limits and timeout settings',
            'Use non-standard ports to reduce automated attacks',
            'Enable comprehensive logging and log monitoring',
            'Implement network segmentation for FTP services'
        ])

        return list(set(recommendations))  # Remove duplicates

    def test_wsl_nmap(self):
        """Test if Kali WSL nmap is working"""
        try:
            # Test WSL
            wsl_test = subprocess.run(['wsl', 'echo', 'WSL works'],
                                      capture_output=True, text=True, timeout=5)
            if wsl_test.returncode != 0:
                return {'wsl_available': False, 'error': 'WSL not working'}

            # Test nmap in WSL
            nmap_test = subprocess.run(['wsl', 'nmap', '--version'],
                                       capture_output=True, text=True, timeout=10)
            if nmap_test.returncode != 0:
                return {'wsl_available': True, 'nmap_available': False, 'error': 'nmap not found in WSL'}

            return {
                'wsl_available': True,
                'nmap_available': True,
                'nmap_version': nmap_test.stdout.split('\n')[0] if nmap_test.stdout else 'Unknown',
                'status': 'ready'
            }

        except Exception as e:
            return {'wsl_available': False, 'error': str(e)}