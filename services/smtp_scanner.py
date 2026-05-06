import socket
import ssl
import time
import re
import base64
import subprocess
from datetime import datetime
from typing import Dict, Any, List, Optional
from .base_scanner import BaseScanner

try:
    import smtplib
    from email.mime.text import MIMEText

    SMTPLIB_AVAILABLE = True
except ImportError:
    SMTPLIB_AVAILABLE = False
    print("⚠️ smtplib not available - SMTP scanner will use basic functionality only")

try:
    import dns.resolver
    import dns.exception

    DNSPYTHON_AVAILABLE = True
    print("✅ dnspython available for DNS analysis")
except ImportError:
    DNSPYTHON_AVAILABLE = False
    print("⚠️ dnspython not available - using dig fallback for DNS analysis")


class SMTPScanner(BaseScanner):


    def __init__(self, timeout: int = 10):
        super().__init__(timeout)
        self.common_users = [
            'admin', 'administrator', 'root', 'postmaster', 'webmaster',
            'abuse', 'noreply', 'no-reply', 'support', 'info', 'contact',
            'mail', 'email', 'test', 'user', 'guest', 'demo'
        ]
        self.test_domains = [
            'example.com', 'test.com', 'gmail.com', 'yahoo.com', 'hotmail.com'
        ]
        self.smtp_commands = [
            'HELO', 'EHLO', 'MAIL FROM', 'RCPT TO', 'DATA', 'RSET', 'NOOP',
            'QUIT', 'AUTH', 'STARTTLS', 'HELP', 'VRFY', 'EXPN'
        ]

    def get_supported_ports(self) -> List[int]:
        return [25, 465, 587, 2525]  # SMTP, SMTPS, Submission, Alternative

    def get_service_name(self) -> str:
        return "SMTP"

    def scan(self, ip: str, port: int, **kwargs) -> Dict[str, Any]:
        """Standard SMTP scanning with DNS analysis and nmap integration"""
        self.scan_start_time = time.time()
        results = self.create_base_result(ip, port)

        # Determine if this is likely SMTPS (implicit SSL)
        is_smtps = port in [465]

        try:
            # Step 1: Basic connectivity check
            self.mark_step_completed(results, 'connectivity')
            connectivity_info = self.check_port_connectivity(ip, port)
            results['connectivity_info'] = connectivity_info

            if not connectivity_info.get('accessible'):
                return self.create_failed_result(ip, port,
                                                 connectivity_info.get('failure_reason', 'SMTP service not accessible'),
                                                 connectivity_info)

            # Step 2: Run Kali WSL nmap scan
            self.mark_step_completed(results, 'nmap_scan')
            nmap_results = self._run_nmap_scan(ip, port, aggressive=False)
            results['nmap_data'] = nmap_results

            self._current_nmap_data = nmap_results

            # Extract service info from nmap
            self.update_service_info(results, nmap_results.get('service_info', {}))
            results['banner'] = nmap_results.get('banner', '')

            # Step 3: DNS Analysis (SPF, DKIM, DMARC)
            self.mark_step_completed(results, 'dns_analysis')
            dns_info = self._analyze_dns_records(ip, results['service_info'])
            results['dns_analysis'] = dns_info
            results['advanced_findings'].update({'dns_security': dns_info})

            # Step 4: Complementary SMTP enumeration
            self.mark_step_completed(results, 'enumeration')
            enum_info = self._complementary_smtp_analysis(ip, port, is_smtps)
            results['advanced_findings'].update(enum_info)

            # Step 5: Security assessment
            self.mark_step_completed(results, 'vulnerability')
            security_info = self._security_assessment(results['service_info'], enum_info,
                                                      results['nmap_data'], dns_info)
            results['vulnerabilities'] = security_info.get('vulnerabilities', [])
            results['recommendations'] = security_info.get('recommendations', [])

            return self.finalize_results(results, success=True)

        except Exception as e:
            results['error'] = str(e)
            return self.finalize_results(results, success=False)

    # In smtp_scanner.py, update the scan_aggressive method around line 140-160

    def scan_aggressive(self, ip: str, port: int, **kwargs) -> Dict[str, Any]:
        """Aggressive SMTP scanning with enhanced enumeration and password attacks"""
        self.scan_start_time = time.time()
        results = self.create_base_result(ip, port)

        # Determine if this is likely SMTPS (implicit SSL)
        is_smtps = port in [465]

        try:
            # Step 1: Basic connectivity check
            self.mark_step_completed(results, 'connectivity')
            connectivity_info = self.check_port_connectivity(ip, port)
            results['connectivity_info'] = connectivity_info

            if not connectivity_info.get('accessible'):
                return self.create_failed_result(ip, port,
                                                 connectivity_info.get('failure_reason', 'SMTP service not accessible'),
                                                 connectivity_info)

            # Step 2: Run aggressive Kali WSL nmap scan with all SMTP scripts
            self.mark_step_completed(results, 'aggressive_nmap_scan')
            nmap_results = self._run_nmap_scan(ip, port, aggressive=True)
            results['nmap_data'] = nmap_results
            results['scan_mode'] = 'aggressive'

            # Store nmap data for conditional access
            self._current_nmap_data = nmap_results

            # Extract enhanced service info
            self.update_service_info(results, nmap_results.get('service_info', {}))
            results['banner'] = nmap_results.get('banner', '')

            # Step 3: SKIP DNS Analysis in aggressive mode (as discussed)
            print("🔄 Skipping DNS analysis in deep scan mode")
            results['dns_analysis'] = {}

            # Step 4: Enhanced Enumeration + Password Attacks (THIS IS THE KEY PART!)
            self.mark_step_completed(results, 'enhanced_enumeration_and_attacks')

            # CALL THE DEEP SCAN FUNCTION HERE - This was missing!
            enhanced_results = self._deep_scan_enumeration_and_attacks(ip, port, is_smtps)
            results['advanced_findings'].update(enhanced_results)

            print(f"🎯 Deep scan enumeration and attacks completed")
            print(f"📊 Enhanced results keys: {list(enhanced_results.keys())}")

            # Step 5: Security assessment
            self.mark_step_completed(results, 'aggressive_vulnerability')
            security_info = self._security_assessment(results['service_info'], enhanced_results,
                                                      results['nmap_data'], {}, aggressive=True)
            results['vulnerabilities'] = security_info.get('vulnerabilities', [])
            results['recommendations'] = security_info.get('recommendations', [])

            return self.finalize_results(results, success=True)

        except Exception as e:
            results['error'] = str(e)
            return self.finalize_results(results, success=False)

    def _run_nmap_scan(self, ip: str, port: int, aggressive: bool = False) -> Dict[str, Any]:
        """Run nmap scan with Kali WSL integration - EXACT SAME LOGIC as FTP/SSH"""

        # First, try WSL (Kali) - if available
        wsl_result = self._try_wsl_nmap(ip, port, aggressive)
        if not wsl_result.get('error'):
            print(f"✅ Using Kali WSL for nmap SMTP scan")
            return wsl_result

        # Fallback to original Windows logic if WSL fails
        print(f"⚠️ WSL failed, falling back to Windows nmap: {wsl_result.get('error')}")
        return self._original_nmap_scan(ip, port, aggressive)

    def _try_wsl_nmap(self, ip: str, port: int, aggressive: bool = False) -> Dict[str, Any]:
        """Try nmap through Kali WSL - SAME COMMANDS as FTP pattern"""
        try:
            if aggressive:
                cmd = [
                    'wsl', 'nmap', '-sV', '-sC', f'-p{port}',
                    '--script=smtp-*', '--script-timeout=60s', '--host-timeout=400s',
                    '-A', ip
                ]
                timeout = 420  # Longer timeout for all scripts
                print(f"🐧 Kali WSL Aggressive SMTP scan (ALL smtp-* scripts): {' '.join(cmd[1:])}")
            else:
                cmd = ['wsl', 'nmap', '-Pn', '-sV', '-sC', f'-p{port}',
                       '--script=smtp-commands,smtp-open-relay,smtp-ntlm-info', ip]
                print(f"🐧 Kali WSL Regular SMTP scan (selected scripts): {' '.join(cmd[1:])}")
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

            # Use EXACT SAME parsing logic as FTP
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
        """Original nmap logic - UNCHANGED from FTP pattern"""
        if not self.check_nmap_available():
            return {'error': 'Nmap not available on this system'}

        try:
            if aggressive:
                cmd = ['nmap', '-sV', '-sC', f'-p{port}', '--script=smtp-*', '-A', ip]
            else:
                cmd = ['nmap', '-Pn', '-sV', '-sC', f'-p{port}',
                       '--script=smtp-commands,smtp-open-relay,smtp-ntlm-info', ip]

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
        """Enhanced parsing for SMTP nmap output"""
        parsed = {
            'service_info': {},
            'banner': '',
            'scripts': {},
            'raw_output': nmap_output,  # Keep full output
            'formatted_for_display': self._format_for_user_display(nmap_output)
        }

        lines = nmap_output.split('\n')

        for line in lines:
            line_stripped = line.strip()

            # Parse SMTP service line
            if '/tcp' in line and ('smtp' in line.lower() or 'mail' in line.lower()):
                parsed['service_info']['server_type'] = self._extract_server_type(line)
                parsed['service_info']['version'] = self._extract_version(line)
                parsed['banner'] = line_stripped

            # Parse SMTP script results
            elif line_stripped.startswith('|_smtp-commands:'):
                parsed['scripts']['smtp-commands'] = line_stripped.replace('|_smtp-commands:', '').strip()
            elif line_stripped.startswith('|_smtp-open-relay:'):
                parsed['scripts']['smtp-open-relay'] = line_stripped.replace('|_smtp-open-relay:', '').strip()
            elif line_stripped.startswith('|_smtp-enum-users:'):
                parsed['scripts']['smtp-enum-users'] = line_stripped.replace('|_smtp-enum-users:', '').strip()
            elif line_stripped.startswith('|_smtp-ntlm-info:'):
                parsed['scripts']['smtp-ntlm-info'] = line_stripped.replace('|_smtp-ntlm-info:', '').strip()
            elif 'SMTP' in line and ('relay' in line.lower() or 'open' in line.lower()):
                parsed['scripts']['smtp-relay-info'] = line_stripped

        return parsed

    def _deep_scan_user_enumeration(self, ip: str, port: int, command_analysis: Dict[str, Any], is_smtps: bool) -> Dict[
        str, Any]:
        """Enhanced user enumeration for deep scan with improved connection handling"""
        enum_results = {
            'enumeration_attempted': True,
            'methods_used': [],
            'users_found': [],
            'total_tested': 0,
            'wordlist_size': 'expanded',
            'connection_issues': []
        }

        if not SMTPLIB_AVAILABLE:
            enum_results['error'] = 'smtplib not available'
            return enum_results

        try:
            # Build expanded wordlist for deep scan
            expanded_userlist = self._build_expanded_deep_scan_userlist(ip)
            enum_results['total_tested'] = len(expanded_userlist)

            print(f"📋 Deep scan using expanded wordlist: {len(expanded_userlist)} usernames")

            # Enhanced VRFY enumeration with improved connection handling
            if command_analysis.get('vrfy_available'):
                print(f"🔍 Running enhanced VRFY enumeration with connection management...")
                try:
                    vrfy_users = self._enhanced_vrfy_deep_scan_with_connection(ip, port, is_smtps, expanded_userlist)
                    enum_results['users_found'].extend(vrfy_users)
                    enum_results['methods_used'].append('Enhanced VRFY')
                    print(f"✅ VRFY completed: {len(vrfy_users)} users found")
                except Exception as vrfy_error:
                    print(f"❌ VRFY enumeration failed: {vrfy_error}")
                    enum_results['connection_issues'].append(f"VRFY: {str(vrfy_error)}")

            # Enhanced EXPN enumeration with improved connection handling
            if command_analysis.get('expn_available'):
                print(f"📤 Running enhanced EXPN enumeration with connection management...")
                try:
                    expn_users = self._enhanced_expn_deep_scan_with_connection(ip, port, is_smtps, expanded_userlist)
                    enum_results['users_found'].extend(expn_users)
                    enum_results['methods_used'].append('Enhanced EXPN')
                    print(f"✅ EXPN completed: {len(expn_users)} users found")
                except Exception as expn_error:
                    print(f"❌ EXPN enumeration failed: {expn_error}")
                    enum_results['connection_issues'].append(f"EXPN: {str(expn_error)}")

            # Remove duplicates
            enum_results['users_found'] = list(set(enum_results['users_found']))

            print(f"🎯 Deep scan enumeration completed: {len(enum_results['users_found'])} unique users found")

            if enum_results['connection_issues']:
                print(f"⚠️ Connection issues encountered: {len(enum_results['connection_issues'])}")

        except Exception as e:
            enum_results['error'] = str(e)
            print(f"❌ Deep scan enumeration error: {e}")

        return enum_results

    def _deep_scan_enumeration_and_attacks(self, ip: str, port: int, is_smtps: bool) -> Dict[str, Any]:
        """Enhanced enumeration and password attacks for deep scan mode"""
        deep_results = {
            'enumeration_attempted': True,
            'password_attacks': {},
            'attack_summary': {},
            'methods_used': [],
            'users_discovered': [],
            'deep_scan_mode': True
        }

        try:
            print(f"🎯 Starting deep scan enumeration for {ip}:{port}")

            # Get nmap command analysis
            nmap_data = getattr(self, '_current_nmap_data', {})
            scripts = nmap_data.get('scripts', {})
            command_analysis = self._analyze_smtp_commands(scripts)

            print(f"📋 Command analysis: {command_analysis}")

            # Step 1: Enhanced Usexr Enumeration
            if command_analysis.get('enumeration_possible'):
                print(f"👥 Starting enhanced user enumeration...")
                enum_results = self._deep_scan_user_enumeration(ip, port, command_analysis, is_smtps)
                deep_results.update(enum_results)

                # Store discovered users for password attacks
                discovered_users = enum_results.get('users_found', [])
                deep_results['users_discovered'] = discovered_users

                if discovered_users:
                    print(f"✅ Deep enumeration found {len(discovered_users)} users: {discovered_users}")

                    # Step 2: Password Attacks on Discovered Users
                    print(f"💥 Starting password attacks on discovered users...")
                    password_results = self._hydra_password_attacks_per_user(ip, port, discovered_users, is_smtps)
                    deep_results['password_attacks'] = password_results
                    deep_results['methods_used'].append('Hydra Password Attacks')

                    # Summary
                    deep_results['attack_summary'] = {
                        'users_enumerated': len(discovered_users),
                        'users_attacked': password_results.get('total_users_attacked', 0),
                        'credentials_found': len(password_results.get('successful_credentials', [])),
                        'total_duration': password_results.get('total_duration', 0)
                    }

                    print(f"🎯 Attack summary: {deep_results['attack_summary']}")
                else:
                    print(f"⚠️ No users discovered for password attacks")
                    deep_results['attack_summary'] = {
                        'users_enumerated': 0,
                        'users_attacked': 0,
                        'credentials_found': 0,
                        'total_duration': 0
                    }
            else:
                print(f"⚠️ User enumeration not possible - no VRFY/EXPN commands detected")
                deep_results['enumeration_skipped'] = True
                deep_results['enumeration_skip_reason'] = 'No enumeration commands available'

            return deep_results

        except Exception as e:
            print(f"❌ Deep scan enumeration error: {e}")
            deep_results['error'] = str(e)
            return deep_results

    def _enhanced_vrfy_deep_scan_with_connection(self, ip: str, port: int, is_smtps: bool, userlist: List[str]) -> List[
        str]:
        """Enhanced VRFY with proper connection management and reconnection handling"""
        found_users = []
        max_retries = 3
        batch_size = 50  # Process users in batches to avoid connection timeouts

        try:
            # Process users in batches
            for batch_start in range(0, len(userlist), batch_size):
                batch_end = min(batch_start + batch_size, len(userlist))
                batch_users = userlist[batch_start:batch_end]

                print(f"🔄 Processing VRFY batch {batch_start // batch_size + 1}: users {batch_start + 1}-{batch_end}")

                # Establish fresh connection for each batch
                smtp = None
                retry_count = 0

                while retry_count < max_retries:
                    try:
                        # Create new connection
                        if is_smtps:
                            context = ssl.create_default_context()
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                            smtp = smtplib.SMTP_SSL(ip, port, timeout=self.timeout, context=context)
                        else:
                            smtp = smtplib.SMTP(ip, port, timeout=self.timeout)

                        # Initialize connection
                        try:
                            smtp.ehlo()
                        except:
                            smtp.helo()

                        print(f"✅ SMTP connection established for batch {batch_start // batch_size + 1}")
                        break

                    except Exception as conn_error:
                        retry_count += 1
                        print(f"⚠️ Connection attempt {retry_count} failed: {conn_error}")
                        if retry_count >= max_retries:
                            print(f"❌ Failed to establish connection after {max_retries} attempts")
                            return found_users
                        time.sleep(2)  # Wait before retry

                if smtp is None:
                    print(f"❌ Could not establish SMTP connection for batch")
                    continue

                # Process users in this batch
                batch_found = []
                for i, username in enumerate(batch_users):
                    connection_retry_count = 0
                    max_connection_retries = 2

                    while connection_retry_count < max_connection_retries:
                        try:
                            # Check if connection is still alive
                            try:
                                smtp.noop()  # Test connection
                            except Exception as noop_error:
                                print(f"🔄 Connection test failed: {noop_error}")
                                raise noop_error  # Force reconnection

                            # Execute VRFY command
                            code, response = smtp.docmd(f'VRFY {username}')

                            # Enhanced response analysis
                            if code == 250:
                                response_str = response.decode('utf-8', errors='ignore') if isinstance(response,
                                                                                                       bytes) else str(
                                    response)
                                if username.lower() in response_str.lower() or '@' in response_str:
                                    batch_found.append(username)
                                    print(f"✅ VRFY found: {username}")
                            elif code == 252:  # Cannot verify but will attempt delivery
                                batch_found.append(username)
                                print(f"✅ VRFY found (252): {username}")

                            # Rate limiting
                            time.sleep(0.3)

                            # Progress indicator
                            if (i + 1) % 10 == 0:
                                print(f"🔄 Batch progress: {i + 1}/{len(batch_users)}, found: {len(batch_found)}")

                            break  # Success, exit retry loop

                        except Exception as cmd_error:
                            connection_retry_count += 1
                            error_msg = str(cmd_error).lower()

                            # Check if it's a connection-related error
                            is_connection_error = (
                                    'connection' in error_msg or
                                    'connect()' in error_msg or
                                    'not connected' in error_msg or
                                    'closed' in error_msg or
                                    'broken pipe' in error_msg or
                                    'winerror 10054' in error_msg
                            )

                            if is_connection_error and connection_retry_count < max_connection_retries:
                                print(
                                    f"🔄 Connection lost for {username}, attempting reconnection ({connection_retry_count}/{max_connection_retries})")

                                # Close old connection safely
                                try:
                                    smtp.quit()
                                except:
                                    pass

                                # Wait before reconnecting
                                time.sleep(1)

                                # Establish new connection
                                try:
                                    if is_smtps:
                                        context = ssl.create_default_context()
                                        context.check_hostname = False
                                        context.verify_mode = ssl.CERT_NONE
                                        smtp = smtplib.SMTP_SSL(ip, port, timeout=self.timeout, context=context)
                                    else:
                                        smtp = smtplib.SMTP(ip, port, timeout=self.timeout)

                                    # Initialize new connection
                                    try:
                                        smtp.ehlo()
                                    except:
                                        smtp.helo()

                                    print(f"✅ Reconnected successfully")

                                except Exception as reconnect_error:
                                    print(f"❌ Reconnection failed: {reconnect_error}")
                                    if connection_retry_count >= max_connection_retries:
                                        print(f"❌ Max connection retries reached, ending batch early")
                                        return found_users
                                    continue
                            else:
                                # Non-connection error or max retries reached
                                if is_connection_error:
                                    print(f"❌ Connection lost for {username}, max retries reached, ending batch early")
                                    return found_users
                                else:
                                    print(f"⚠️ VRFY error for {username}: {cmd_error}")
                                    time.sleep(0.5)
                                    break  # Skip this user, continue with next

                # Close connection properly
                try:
                    smtp.quit()
                except:
                    pass

                found_users.extend(batch_found)
                print(f"✅ Batch {batch_start // batch_size + 1} completed: {len(batch_found)} users found")

                # Pause between batches
                if batch_end < len(userlist):
                    time.sleep(2)

        except Exception as conn_error:
            print(f"❌ VRFY batch processing error: {conn_error}")

        return found_users

        return found_users

    def _enhanced_expn_deep_scan_with_connection(self, ip: str, port: int, is_smtps: bool, userlist: List[str]) -> List[
        str]:
        """Enhanced EXPN with proper connection management and reconnection handling"""
        found_users = []
        max_retries = 3

        try:
            # Focus on group/list names for EXPN
            expn_candidates = [user for user in userlist if user in [
                'admin', 'all', 'staff', 'everyone', 'users', 'team',
                'support', 'help', 'info', 'sales', 'marketing', 'management',
                'developers', 'operations', 'security'
            ]]

            if not expn_candidates:
                print(f"ℹ️ No suitable EXPN candidates found in userlist")
                return found_users

            print(f"📤 Testing EXPN with {len(expn_candidates)} candidates")

            # Establish connection with retry logic
            smtp = None
            retry_count = 0

            while retry_count < max_retries:
                try:
                    if is_smtps:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        smtp = smtplib.SMTP_SSL(ip, port, timeout=self.timeout, context=context)
                    else:
                        smtp = smtplib.SMTP(ip, port, timeout=self.timeout)

                    # Initialize connection
                    try:
                        smtp.ehlo()
                    except:
                        smtp.helo()

                    print(f"✅ SMTP connection established for EXPN testing")
                    break

                except Exception as conn_error:
                    retry_count += 1
                    print(f"⚠️ EXPN connection attempt {retry_count} failed: {conn_error}")
                    if retry_count >= max_retries:
                        print(f"❌ Failed to establish EXPN connection after {max_retries} attempts")
                        return found_users
                    time.sleep(2)

            if smtp is None:
                return found_users

            # Test each EXPN candidate
            for username in expn_candidates:
                connection_retry_count = 0
                max_connection_retries = 2

                while connection_retry_count < max_connection_retries:
                    try:
                        # Test connection before each command
                        try:
                            smtp.noop()
                        except Exception as noop_error:
                            print(f"🔄 EXPN connection test failed: {noop_error}")
                            raise noop_error  # Force reconnection

                        code, response = smtp.docmd(f'EXPN {username}')

                        if code == 250:
                            response_str = response.decode('utf-8', errors='ignore') if isinstance(response,
                                                                                                   bytes) else str(
                                response)
                            if '@' in response_str:
                                # Extract usernames from email addresses
                                import re
                                emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                                                    response_str)
                                for email in emails:
                                    user_part = email.split('@')[0]
                                    if user_part not in found_users:
                                        found_users.append(user_part)
                                        print(f"✅ EXPN found: {user_part} (from {email})")

                        time.sleep(0.5)
                        break  # Success, exit retry loop

                    except Exception as cmd_error:
                        connection_retry_count += 1
                        error_msg = str(cmd_error).lower()

                        # Check if it's a connection-related error
                        is_connection_error = (
                                'connection' in error_msg or
                                'connect()' in error_msg or
                                'not connected' in error_msg or
                                'closed' in error_msg or
                                'broken pipe' in error_msg or
                                'winerror 10054' in error_msg
                        )

                        if is_connection_error and connection_retry_count < max_connection_retries:
                            print(
                                f"🔄 EXPN connection lost for {username}, attempting reconnection ({connection_retry_count}/{max_connection_retries})")

                            # Close old connection safely
                            try:
                                smtp.quit()
                            except:
                                pass

                            # Wait before reconnecting
                            time.sleep(1)

                            # Establish new connection
                            try:
                                if is_smtps:
                                    context = ssl.create_default_context()
                                    context.check_hostname = False
                                    context.verify_mode = ssl.CERT_NONE
                                    smtp = smtplib.SMTP_SSL(ip, port, timeout=self.timeout, context=context)
                                else:
                                    smtp = smtplib.SMTP(ip, port, timeout=self.timeout)

                                # Initialize new connection
                                try:
                                    smtp.ehlo()
                                except:
                                    smtp.helo()

                                print(f"✅ EXPN reconnected successfully")

                            except Exception as reconnect_error:
                                print(f"❌ EXPN reconnection failed: {reconnect_error}")
                                if connection_retry_count >= max_connection_retries:
                                    print(f"❌ EXPN max connection retries reached, ending enumeration")
                                    return found_users
                                continue
                        else:
                            # Non-connection error or max retries reached
                            if is_connection_error:
                                print(f"❌ EXPN connection lost for {username}, max retries reached")
                                return found_users
                            else:
                                print(f"⚠️ EXPN error for {username}: {cmd_error}")
                                break  # Skip this user, continue with next

            # Close connection
            try:
                smtp.quit()
            except:
                pass

        except Exception as conn_error:
            print(f"❌ EXPN connection error: {conn_error}")

        return found_users



    def _build_expanded_deep_scan_userlist(self, ip: str) -> List[str]:
        """Build comprehensive wordlist for deep scan"""
        userlist = []

        # 1. System accounts (expanded)
        system_users = [
            'admin', 'administrator', 'root', 'postmaster', 'webmaster',
            'abuse', 'noreply', 'no-reply', 'support', 'info', 'contact',
            'mail', 'email', 'test', 'user', 'guest', 'demo', 'help',
            'sales', 'marketing', 'hr', 'it', 'security', 'backup',
            'service', 'operator', 'manager', 'director', 'ceo', 'cto',
            'cio', 'cfo', 'president', 'owner', 'sysadmin', 'netadmin'
        ]
        userlist.extend(system_users)

        # 2. Common first names (expanded)
        common_names = [
            'john', 'jane', 'mike', 'sarah', 'david', 'lisa', 'mary',
            'james', 'robert', 'michael', 'william', 'richard', 'charles',
            'thomas', 'christopher', 'daniel', 'matthew', 'anthony', 'mark',
            'donald', 'steven', 'paul', 'andrew', 'joshua', 'kenneth',
            'kevin', 'brian', 'george', 'edward', 'ronald', 'timothy',
            'jason', 'jeffrey', 'ryan', 'jacob', 'gary', 'nicholas',
            'eric', 'jonathan', 'stephen', 'larry', 'justin', 'scott',
            'brandon', 'benjamin', 'samuel', 'frank', 'nancy', 'betty',
            'helen', 'sandra', 'donna', 'carol', 'ruth', 'sharon',
            'michelle', 'laura', 'emily', 'karen', 'deborah', 'dorothy'
        ]
        userlist.extend(common_names)

        # 3. Department accounts (expanded)
        departments = [
            'accounting', 'finance', 'legal', 'operations', 'research',
            'development', 'qa', 'testing', 'training', 'helpdesk',
            'reception', 'facilities', 'maintenance', 'purchasing',
            'inventory', 'shipping', 'logistics', 'compliance',
            'audit', 'payroll', 'benefits', 'recruiting'
        ]
        userlist.extend(departments)

        # 4. Service accounts (expanded)
        services = [
            'apache', 'nginx', 'mysql', 'postgres', 'oracle', 'mongodb',
            'redis', 'jenkins', 'gitlab', 'svn', 'git', 'ftp', 'ssh',
            'ldap', 'radius', 'vpn', 'firewall', 'proxy', 'dns',
            'dhcp', 'ntp', 'syslog', 'snmp', 'nagios', 'zabbix'
        ]
        userlist.extend(services)

        # 5. Common patterns with numbers
        base_patterns = ['admin', 'user', 'test', 'guest', 'demo']
        for base in base_patterns:
            for i in range(1, 21):  # 1-20
                userlist.append(f"{base}{i}")
                if i < 10:
                    userlist.append(f"{base}0{i}")

            # Year patterns
            for year in ['2024', '2025', '23', '24', '25']:
                userlist.append(f"{base}{year}")

        # 6. Email-specific patterns
        email_patterns = [
            'newsletter', 'notifications', 'alerts', 'reports',
            'billing', 'invoices', 'orders', 'customers',
            'partners', 'vendors', 'suppliers'
        ]
        userlist.extend(email_patterns)

        # Remove duplicates
        unique_userlist = list(dict.fromkeys(userlist))

        print(f"📊 Built expanded deep scan wordlist: {len(unique_userlist)} usernames")
        return unique_userlist

    def _enhanced_vrfy_deep_scan(self, smtp, userlist: List[str]) -> List[str]:
        """Enhanced VRFY for deep scan"""
        found_users = []

        for i, username in enumerate(userlist):
            try:
                code, response = smtp.docmd(f'VRFY {username}')

                # Enhanced response analysis
                if code == 250:
                    response_str = response.decode('utf-8', errors='ignore') if isinstance(response, bytes) else str(
                        response)
                    if username.lower() in response_str.lower() or '@' in response_str:
                        found_users.append(username)
                elif code == 252:  # Cannot verify but will attempt delivery
                    found_users.append(username)

                # Rate limiting for deep scan
                time.sleep(0.3)  # Slightly faster than regular scan

                # Progress indicator
                if (i + 1) % 50 == 0:
                    print(f"🔄 VRFY progress: {i + 1}/{len(userlist)}, found: {len(found_users)}")

            except Exception:
                time.sleep(0.5)
                continue

        return found_users

    def _enhanced_expn_deep_scan(self, smtp, userlist: List[str]) -> List[str]:
        """Enhanced EXPN for deep scan"""
        found_users = []

        # Focus on group/list names for EXPN
        expn_candidates = [user for user in userlist if user in [
            'admin', 'all', 'staff', 'everyone', 'users', 'team',
            'support', 'help', 'info', 'sales', 'marketing', 'management',
            'developers', 'operations', 'security'
        ]]

        for username in expn_candidates:
            try:
                code, response = smtp.docmd(f'EXPN {username}')

                if code == 250:
                    response_str = response.decode('utf-8', errors='ignore') if isinstance(response, bytes) else str(
                        response)
                    if '@' in response_str:
                        # Extract usernames from email addresses
                        import re
                        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', response_str)
                        for email in emails:
                            user_part = email.split('@')[0]
                            if user_part not in found_users:
                                found_users.append(user_part)

                time.sleep(0.5)

            except Exception:
                continue

        return found_users



    def _analyze_smtp_commands(self, scripts: Dict[str, str]) -> Dict[str, Any]:
        """Analyze SMTP commands from nmap smtp-commands script"""
        analysis = {
            'commands_detected': [],
            'dangerous_commands': [],
            'enumeration_possible': False,
            'vrfy_available': False,
            'expn_available': False,
            'turn_available': False
        }

        if 'smtp-commands' in scripts:
            commands_str = scripts['smtp-commands'].upper()

            # Parse available commands
            analysis['commands_detected'] = [cmd.strip() for cmd in commands_str.split() if cmd.strip()]

            # Check for dangerous enumeration commands
            if 'VRFY' in commands_str:
                analysis['vrfy_available'] = True
                analysis['dangerous_commands'].append('VRFY')

            if 'EXPN' in commands_str:
                analysis['expn_available'] = True
                analysis['dangerous_commands'].append('EXPN')

            if 'TURN' in commands_str:
                analysis['turn_available'] = True
                analysis['dangerous_commands'].append('TURN')

            # Determine if enumeration is possible
            analysis['enumeration_possible'] = analysis['vrfy_available'] or analysis['expn_available']

            print(f"📋 SMTP commands detected: {analysis['commands_detected']}")
            if analysis['dangerous_commands']:
                print(f"⚠️ Dangerous commands found: {analysis['dangerous_commands']}")

        return analysis

    def _run_smtp_user_enum_conditional(self, ip: str, port: int, command_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Run smtp-user-enum conditionally based on detected commands"""
        enum_results = {
            'tool_used': 'smtp-user-enum',
            'enumeration_attempted': True,
            'users_found': [],
            'method_used': None,
            'success': False
        }

        try:
            # Determine best method based on available commands
            if command_analysis.get('vrfy_available'):
                method = 'VRFY'
            elif command_analysis.get('expn_available'):
                method = 'EXPN'
            else:
                enum_results['error'] = 'No suitable enumeration method available'
                return enum_results

            # Create temporary username file
            usernames = self.common_users[:15]  # Use more usernames than manual method
            username_content = '\n'.join(usernames)

            # Run smtp-user-enum
            cmd = [
                'wsl', 'smtp-user-enum',
                '-M', method,
                '-U', '-',  # Read from stdin
                '-t', ip,
                '-p', str(port)
            ]

            print(f"🚀 Running: smtp-user-enum -M {method} -t {ip}:{port}")

            result = subprocess.run(
                cmd,
                input=username_content,
                capture_output=True,
                text=True,
                timeout=120
            )

            # Parse results
            if result.returncode == 0 and result.stdout:
                enum_results.update(self._parse_smtp_user_enum_output(result.stdout, method))
                enum_results['method_used'] = method
                enum_results['raw_output'] = result.stdout

                if enum_results.get('users_found'):
                    enum_results['success'] = True
                    print(f"✅ smtp-user-enum found {len(enum_results['users_found'])} users via {method}")
                else:
                    print(f"ℹ️ smtp-user-enum completed but found no users via {method}")
            else:
                enum_results['error'] = f"smtp-user-enum failed: {result.stderr}"

        except subprocess.TimeoutExpired:
            enum_results['error'] = 'smtp-user-enum timed out'
        except Exception as e:
            enum_results['error'] = str(e)

        return enum_results

    def _parse_smtp_user_enum_output(self, stdout: str, method: str) -> Dict[str, Any]:
        """Parse smtp-user-enum output for usernames"""
        results = {
            'users_found': [],
            'total_tested': 0,
            'successful_enum': 0
        }

        if not stdout:
            return results

        lines = stdout.split('\n')
        for line in lines:
            line = line.strip()

            # Look for successful enumeration patterns
            if 'exists' in line.lower() or f'{method.lower()}:' in line.lower():
                # Extract username from line (format: "ip: username exists")
                parts = line.split(':')
                if len(parts) >= 2:
                    username_part = parts[-1].strip()
                    if 'exists' in username_part:
                        username = username_part.replace('exists', '').strip()
                        if username and username not in results['users_found']:
                            results['users_found'].append(username)
                            results['successful_enum'] += 1

            # Count total tests
            elif 'Scan completed' in line or 'results.' in line:
                try:
                    # Try to extract total count
                    numbers = [int(s) for s in line.split() if s.isdigit()]
                    if numbers:
                        results['total_tested'] = numbers[0]
                except:
                    pass

        return results

    def _store_discovered_users(self, ip: str, port: int, usernames: List[str]):
        """Store discovered usernames for deep scan password attacks"""
        if not hasattr(self, '_discovered_credentials'):
            self._discovered_credentials = {}

        target_key = f"{ip}:{port}"
        self._discovered_credentials[target_key] = {
            'usernames': usernames,
            'timestamp': time.time(),
            'enumeration_method': 'smtp-user-enum',
            'port': port
        }

        print(f"💾 Stored {len(usernames)} usernames for deep scan attacks: {usernames}")



    def _extract_server_type(self, line: str) -> str:
        """Extract SMTP server type from nmap output"""
        line_lower = line.lower()
        if 'postfix' in line_lower:
            return 'Postfix'
        elif 'sendmail' in line_lower:
            return 'Sendmail'
        elif 'exim' in line_lower:
            return 'Exim'
        elif 'microsoft' in line_lower or 'exchange' in line_lower:
            return 'Microsoft Exchange'
        elif 'qmail' in line_lower:
            return 'qmail'
        elif 'zimbra' in line_lower:
            return 'Zimbra'
        elif 'courier' in line_lower:
            return 'Courier'
        else:
            return 'Unknown SMTP Server'

    def _extract_version(self, line: str) -> str:
        """Extract version from nmap output"""
        version_match = re.search(r'(\d+\.[\d\.]+)', line)
        return version_match.group(1) if version_match else ''

    def _format_for_user_display(self, nmap_output: str) -> str:
        """Format nmap output for clear user display"""
        lines = nmap_output.split('\n')
        important_lines = []

        for line in lines:
            # Keep important lines for user display
            if any(keyword in line for keyword in [
                'PORT', 'STATE', 'SERVICE', 'VERSION',
                'smtp-commands', 'smtp-open-relay', 'smtp-enum-users', 'smtp-ntlm-info',
                'Open mail relay', 'postfix', 'sendmail', 'exim'
            ]):
                important_lines.append(line)

        return '\n'.join(important_lines) if important_lines else nmap_output

    def _analyze_dns_records(self, ip: str, service_info: Dict[str, Any], comprehensive: bool = False) -> Dict[
        str, Any]:
        """Analyze DNS records for SPF, DKIM, and DMARC - Enhanced version"""
        dns_analysis = {
            'domain_extracted': None,
            'spf_record': None,
            'dkim_records': {},
            'dmarc_record': None,
            'dns_vulnerabilities': [],
            'dns_recommendations': [],
            'method_used': 'unknown'
        }

        try:
            # Extract domain from SMTP banner or perform reverse DNS
            domain = self._extract_domain_from_smtp(service_info, ip)
            if not domain:
                dns_analysis['domain_extracted'] = f"Could not extract domain for {ip}"
                return dns_analysis

            dns_analysis['domain_extracted'] = domain
            print(f"🔍 Analyzing DNS records for domain: {domain}")

            # Try WSL dig first, then dnspython fallback
            if comprehensive:
                dns_analysis = self._comprehensive_dns_analysis_wsl(domain, dns_analysis)
            else:
                dns_analysis = self._basic_dns_analysis_wsl(domain, dns_analysis)

            # Add vulnerabilities based on findings
            self._analyze_dns_security(dns_analysis)

        except Exception as e:
            dns_analysis['error'] = str(e)
            print(f"❌ DNS analysis failed: {e}")

        return dns_analysis

    def _extract_domain_from_smtp(self, service_info: Dict[str, Any], ip: str) -> str:
        """Extract domain from SMTP service information"""
        # Try to get from banner
        banner = service_info.get('banner', '')
        if banner:
            # Look for domain in SMTP banner (250 mail.example.com ESMTP)
            domain_match = re.search(r'250[- ]([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', banner)
            if domain_match:
                return domain_match.group(1)

        # Try reverse DNS lookup
        try:
            import socket
            hostname = socket.gethostbyaddr(ip)[0]
            if '.' in hostname and not hostname.endswith('.in-addr.arpa'):
                return hostname
        except:
            pass

        # Default fallback
        return f"mail.{ip}.test"  # Use a test domain for analysis

    def _basic_dns_analysis_wsl(self, domain: str, dns_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Basic DNS analysis using WSL dig"""
        try:
            # SPF Record
            spf_result = self._wsl_dig_query(domain, 'TXT')
            if spf_result:
                spf_records = [record for record in spf_result if 'v=spf1' in record.lower()]
                if spf_records:
                    dns_analysis['spf_record'] = spf_records[0]
                    dns_analysis['spf_analysis'] = self._analyze_spf_record(spf_records[0])

            # DMARC Record
            dmarc_result = self._wsl_dig_query(f'_dmarc.{domain}', 'TXT')
            if dmarc_result:
                dmarc_records = [record for record in dmarc_result if 'v=DMARC1' in record]
                if dmarc_records:
                    dns_analysis['dmarc_record'] = dmarc_records[0]
                    dns_analysis['dmarc_analysis'] = self._analyze_dmarc_record(dmarc_records[0])

            # Basic DKIM check (common selectors)
            dns_analysis['dkim_records'] = self._check_basic_dkim_selectors(domain)
            dns_analysis['method_used'] = 'wsl_dig'

        except Exception as e:
            print(f"⚠️ WSL dig failed, trying dnspython fallback: {e}")
            dns_analysis = self._dnspython_fallback(domain, dns_analysis)

        return dns_analysis

    def _comprehensive_dns_analysis_wsl(self, domain: str, dns_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive DNS analysis for aggressive mode"""
        try:
            # All the basic analysis
            dns_analysis = self._basic_dns_analysis_wsl(domain, dns_analysis)

            # Extended DKIM selector list for aggressive mode
            extended_selectors = [
                'default', 'google', 'k1', 'k2', 'selector1', 'selector2', 'dkim',
                'key1', 'key2', 'mail', 'email', 'mta', 'mx', 's1', 's2',
                'dk', 'domainkey', 'pm', 'protonmail', 'zendesk', 'mailgun'
            ]

            print(f"🔍 Aggressive DKIM analysis with {len(extended_selectors)} selectors")
            dns_analysis['dkim_records'] = self._check_extended_dkim_selectors(domain, extended_selectors)

            # Additional MX record analysis
            mx_result = self._wsl_dig_query(domain, 'MX')
            if mx_result:
                dns_analysis['mx_records'] = mx_result
                dns_analysis['mx_analysis'] = self._analyze_mx_records(mx_result)

            dns_analysis['method_used'] = 'wsl_dig_comprehensive'

        except Exception as e:
            print(f"⚠️ Comprehensive WSL analysis failed: {e}")
            dns_analysis = self._dnspython_fallback(domain, dns_analysis)

        return dns_analysis

    def _wsl_dig_query(self, domain: str, record_type: str) -> List[str]:
        """Execute dig query through WSL"""
        try:
            cmd = ['wsl', 'dig', record_type, domain, '+short']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0 and result.stdout.strip():
                records = [line.strip().strip('"') for line in result.stdout.strip().split('\n')
                           if line.strip() and not line.startswith(';')]
                return records

        except Exception as e:
            print(f"WSL dig query failed for {domain} {record_type}: {e}")

        return []

    def _check_basic_dkim_selectors(self, domain: str) -> Dict[str, str]:
        """Check basic DKIM selectors"""
        basic_selectors = ['default', 'google', 'k1', 'selector1', 'dkim']
        dkim_records = {}

        for selector in basic_selectors:
            dkim_domain = f'{selector}._domainkey.{domain}'
            dkim_result = self._wsl_dig_query(dkim_domain, 'TXT')
            if dkim_result:
                for record in dkim_result:
                    if 'v=DKIM1' in record or 'p=' in record:
                        dkim_records[selector] = record
                        break

        return dkim_records

    def _check_extended_dkim_selectors(self, domain: str, selectors: List[str]) -> Dict[str, str]:
        """Check extended DKIM selectors for aggressive mode"""
        dkim_records = {}

        for selector in selectors:
            dkim_domain = f'{selector}._domainkey.{domain}'
            dkim_result = self._wsl_dig_query(dkim_domain, 'TXT')
            if dkim_result:
                for record in dkim_result:
                    if 'v=DKIM1' in record or 'p=' in record:
                        dkim_records[selector] = record
                        break

        return dkim_records

    def _dnspython_fallback(self, domain: str, dns_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback to dnspython if available"""
        if not DNSPYTHON_AVAILABLE:
            dns_analysis['method_used'] = 'none_available'
            dns_analysis['error'] = 'Neither WSL dig nor dnspython available'
            return dns_analysis

        try:
            # SPF Record
            txt_records = dns.resolver.resolve(domain, 'TXT')
            for record in txt_records:
                record_str = str(record).strip('"')
                if 'v=spf1' in record_str.lower():
                    dns_analysis['spf_record'] = record_str
                    dns_analysis['spf_analysis'] = self._analyze_spf_record(record_str)
                    break

            # DMARC Record
            try:
                dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                for record in dmarc_records:
                    record_str = str(record).strip('"')
                    if 'v=DMARC1' in record_str:
                        dns_analysis['dmarc_record'] = record_str
                        dns_analysis['dmarc_analysis'] = self._analyze_dmarc_record(record_str)
                        break
            except dns.exception.DNSException:
                pass

            # Basic DKIM
            basic_selectors = ['default', 'google', 'k1', 'selector1']
            for selector in basic_selectors:
                try:
                    dkim_records = dns.resolver.resolve(f'{selector}._domainkey.{domain}', 'TXT')
                    for record in dkim_records:
                        record_str = str(record).strip('"')
                        if 'v=DKIM1' in record_str or 'p=' in record_str:
                            dns_analysis['dkim_records'][selector] = record_str
                            break
                except dns.exception.DNSException:
                    continue

            dns_analysis['method_used'] = 'dnspython_fallback'

        except Exception as e:
            dns_analysis['error'] = f'dnspython fallback failed: {str(e)}'
            dns_analysis['method_used'] = 'failed'

        return dns_analysis

    def _analyze_spf_record(self, spf_record: str) -> Dict[str, Any]:
        """Analyze SPF record for security issues"""
        analysis = {
            'record': spf_record,
            'mechanisms': [],
            'all_mechanism': None,
            'include_count': 0,
            'issues': [],
            'security_level': 'good'
        }

        if not spf_record:
            return analysis

        try:
            mechanisms = spf_record.split()
            analysis['mechanisms'] = mechanisms

            # Count includes (DNS lookup limit is 10)
            includes = [m for m in mechanisms if m.startswith('include:')]
            analysis['include_count'] = len(includes)

            if analysis['include_count'] > 8:
                analysis['issues'].append('Too many DNS lookups (>8 includes)')
                analysis['security_level'] = 'warning'

            # Check all mechanism
            all_mechanisms = [m for m in mechanisms if m.endswith('all')]
            if all_mechanisms:
                all_mech = all_mechanisms[0]
                analysis['all_mechanism'] = all_mech

                if all_mech == '+all':
                    analysis['issues'].append('CRITICAL: +all allows any sender')
                    analysis['security_level'] = 'critical'
                elif all_mech == '?all':
                    analysis['issues'].append('Neutral policy (?all) provides minimal protection')
                    analysis['security_level'] = 'warning'
                elif all_mech == '~all':
                    analysis['security_level'] = 'good'
                elif all_mech == '-all':
                    analysis['security_level'] = 'excellent'
            else:
                analysis['issues'].append('No all mechanism specified')
                analysis['security_level'] = 'warning'

        except Exception as e:
            analysis['error'] = str(e)

        return analysis

    def _analyze_dmarc_record(self, dmarc_record: str) -> Dict[str, Any]:
        """Analyze DMARC record for security issues"""
        analysis = {
            'record': dmarc_record,
            'policy': None,
            'subdomain_policy': None,
            'percentage': 100,
            'issues': [],
            'security_level': 'good'
        }

        if not dmarc_record:
            return analysis

        try:
            # Parse DMARC tags
            parts = dmarc_record.split(';')
            for part in parts:
                if '=' in part:
                    key, value = part.split('=', 1)
                    key = key.strip()
                    value = value.strip()

                    if key == 'p':
                        analysis['policy'] = value
                    elif key == 'sp':
                        analysis['subdomain_policy'] = value
                    elif key == 'pct':
                        try:
                            analysis['percentage'] = int(value)
                        except ValueError:
                            pass

            # Analyze policy strength
            if analysis['policy'] == 'none':
                analysis['issues'].append('DMARC policy is set to none (monitoring only)')
                analysis['security_level'] = 'warning'
            elif analysis['policy'] == 'quarantine':
                analysis['security_level'] = 'good'
            elif analysis['policy'] == 'reject':
                analysis['security_level'] = 'excellent'
            else:
                analysis['issues'].append('No clear DMARC policy found')
                analysis['security_level'] = 'warning'

            # Check percentage
            if analysis['percentage'] < 100:
                analysis['issues'].append(f'DMARC only applies to {analysis["percentage"]}% of emails')
                if analysis['security_level'] == 'excellent':
                    analysis['security_level'] = 'good'

        except Exception as e:
            analysis['error'] = str(e)

        return analysis

    def _analyze_mx_records(self, mx_records: List[str]) -> Dict[str, Any]:
        """Analyze MX records for security"""
        analysis = {
            'count': len(mx_records),
            'records': mx_records,
            'issues': [],
            'redundancy': 'good' if len(mx_records) > 1 else 'single_point_failure'
        }

        if len(mx_records) == 1:
            analysis['issues'].append('Single MX record - no redundancy')

        return analysis

    def _analyze_dns_security(self, dns_analysis: Dict[str, Any]):
        """Analyze overall DNS security and add vulnerabilities"""
        vulnerabilities = []
        recommendations = []

        # SPF Analysis
        spf_analysis = dns_analysis.get('spf_analysis', {})
        if not dns_analysis.get('spf_record'):
            vulnerabilities.append({
                'id': 'SMTP-DNS-001',
                'severity': 'High',
                'title': 'Missing SPF Record',
                'description': 'No SPF record found - emails can be easily spoofed',
                'recommendation': 'Implement SPF record to specify authorized mail servers',
                'source': 'dns_analysis',
                'detection_method': 'spf_lookup'
            })
        elif spf_analysis.get('security_level') == 'critical':
            vulnerabilities.append({
                'id': 'SMTP-DNS-002',
                'severity': 'Critical',
                'title': 'Dangerous SPF Configuration',
                'description': f'SPF record allows all senders: {dns_analysis.get("spf_record", "")}',
                'recommendation': 'Fix SPF record to use -all or ~all instead of +all',
                'source': 'dns_analysis',
                'detection_method': 'spf_analysis'
            })

        # DMARC Analysis
        dmarc_analysis = dns_analysis.get('dmarc_analysis', {})
        if not dns_analysis.get('dmarc_record'):
            vulnerabilities.append({
                'id': 'SMTP-DNS-003',
                'severity': 'Medium',
                'title': 'Missing DMARC Record',
                'description': 'No DMARC record found - limited email authentication',
                'recommendation': 'Implement DMARC record for enhanced email security',
                'source': 'dns_analysis',
                'detection_method': 'dmarc_lookup'
            })
        elif dmarc_analysis.get('security_level') == 'warning':
            vulnerabilities.append({
                'id': 'SMTP-DNS-004',
                'severity': 'Medium',
                'title': 'Weak DMARC Policy',
                'description': f'DMARC policy is not enforcing: {dns_analysis.get("dmarc_record", "")}',
                'recommendation': 'Strengthen DMARC policy to quarantine or reject',
                'source': 'dns_analysis',
                'detection_method': 'dmarc_analysis'
            })

        # DKIM Analysis
        dkim_records = dns_analysis.get('dkim_records', {})
        if not dkim_records:
            vulnerabilities.append({
                'id': 'SMTP-DNS-005',
                'severity': 'Medium',
                'title': 'Missing DKIM Records',
                'description': 'No DKIM records found for common selectors',
                'recommendation': 'Implement DKIM signing for email authentication',
                'source': 'dns_analysis',
                'detection_method': 'dkim_lookup'
            })

        dns_analysis['dns_vulnerabilities'] = vulnerabilities

        # Generate recommendations
        if dns_analysis.get('spf_record'):
            recommendations.append('Review SPF record for optimal security configuration')
        else:
            recommendations.append('Implement SPF record to prevent email spoofing')

        if dns_analysis.get('dmarc_record'):
            recommendations.append('Consider strengthening DMARC policy for better protection')
        else:
            recommendations.append('Implement DMARC record for comprehensive email security')

        if not dkim_records:
            recommendations.append('Implement DKIM signing to improve email deliverability and security')

        recommendations.extend([
            'Monitor DNS configuration changes regularly',
            'Use multiple MX records for redundancy',
            'Consider implementing BIMI for brand protection',
            'Regular SPF/DKIM/DMARC compliance testing'
        ])

        dns_analysis['dns_recommendations'] = list(set(recommendations))

    def _complementary_smtp_analysis(self, ip: str, port: int, is_smtps: bool) -> Dict[str, Any]:
        """Complementary SMTP analysis with conditional smtp-user-enum"""
        enum_info = {
            'nmap_command_detection': {},
            'conditional_user_enumeration': {},
            'connection_analysis': {}
        }

        try:
            # Get nmap script results
            nmap_data = getattr(self, '_current_nmap_data', {})
            scripts = nmap_data.get('scripts', {})

            # Analyze SMTP commands detected by nmap
            command_analysis = self._analyze_smtp_commands(scripts)
            enum_info['nmap_command_detection'] = command_analysis

            # Conditional smtp-user-enum execution
            if command_analysis.get('enumeration_possible'):
                print(f"🎯 nmap detected enumeration commands: {command_analysis['dangerous_commands']}")
                print(f"🚀 Running smtp-user-enum for targeted enumeration...")

                user_enum_results = self._run_smtp_user_enum_conditional(ip, port, command_analysis)
                enum_info['conditional_user_enumeration'] = user_enum_results

                # Store usernames for deep scan password attacks
                if user_enum_results.get('users_found'):
                    self._store_discovered_users(ip, port, user_enum_results['users_found'])

            else:
                print(f"✅ No enumeration commands detected - skipping smtp-user-enum")
                enum_info['conditional_user_enumeration'] = {
                    'skipped': True,
                    'reason': 'No VRFY/EXPN commands detected by nmap'
                }

            # Basic connection analysis (existing code)
            enum_info['connection_analysis'] = self._analyze_smtp_connection(ip, port, is_smtps)

        except Exception as e:
            enum_info['error'] = str(e)

        return enum_info

    def _analyze_smtp_connection(self, ip: str, port: int, is_smtps: bool) -> Dict[str, Any]:
        """Analyze SMTP connection characteristics"""
        connection_info = {
            'response_times': [],
            'connection_stability': True,
            'ssl_detected': is_smtps,
            'banner_analysis': {}
        }

        try:
            for i in range(3):
                start_time = time.time()

                if is_smtps:
                    # SMTPS connection
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    ssl_sock = context.wrap_socket(sock)
                    ssl_sock.connect((ip, port))

                    banner = ssl_sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    response_time = (time.time() - start_time) * 1000
                    connection_info['response_times'].append(response_time)

                    if i == 0:  # First connection
                        connection_info['banner_analysis'] = self._analyze_smtp_banner(banner)

                    ssl_sock.close()
                else:
                    # Regular SMTP connection
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((ip, port))

                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    response_time = (time.time() - start_time) * 1000
                    connection_info['response_times'].append(response_time)

                    if i == 0:  # First connection
                        connection_info['banner_analysis'] = self._analyze_smtp_banner(banner)

                    sock.close()

                time.sleep(0.5)

            if connection_info['response_times']:
                avg_time = sum(connection_info['response_times']) / len(connection_info['response_times'])
                connection_info['average_response_time'] = round(avg_time, 2)

        except Exception as e:
            connection_info['error'] = str(e)
            connection_info['connection_stability'] = False

        return connection_info

    def _analyze_smtp_banner(self, banner: str) -> Dict[str, Any]:
        """Analyze SMTP banner for information disclosure"""
        analysis = {
            'banner': banner,
            'server_software': 'Unknown',
            'version_disclosed': False,
            'hostname_disclosed': False,
            'information_leakage': []
        }

        if not banner:
            return analysis

        banner_lower = banner.lower()

        # Identify server software
        if 'postfix' in banner_lower:
            analysis['server_software'] = 'Postfix'
            version_match = re.search(r'postfix\s+([\d\.]+)', banner_lower)
            if version_match:
                analysis['version_disclosed'] = True
                analysis['information_leakage'].append(f'Version: {version_match.group(1)}')

        elif 'sendmail' in banner_lower:
            analysis['server_software'] = 'Sendmail'
            version_match = re.search(r'sendmail\s+([\d\.]+)', banner_lower)
            if version_match:
                analysis['version_disclosed'] = True
                analysis['information_leakage'].append(f'Version: {version_match.group(1)}')

        elif 'exim' in banner_lower:
            analysis['server_software'] = 'Exim'
            version_match = re.search(r'exim\s+([\d\.]+)', banner_lower)
            if version_match:
                analysis['version_disclosed'] = True
                analysis['information_leakage'].append(f'Version: {version_match.group(1)}')

        elif 'microsoft' in banner_lower or 'exchange' in banner_lower:
            analysis['server_software'] = 'Microsoft Exchange'

        # Check for hostname disclosure
        hostname_match = re.search(r'^220[- ]([a-zA-Z0-9.-]+)', banner)
        if hostname_match:
            hostname = hostname_match.group(1)
            if '.' in hostname and not hostname.startswith('220'):
                analysis['hostname_disclosed'] = True
                analysis['information_leakage'].append(f'Hostname: {hostname}')

        return analysis

    def _test_smtp_commands(self, ip: str, port: int, is_smtps: bool) -> Dict[str, Any]:
        """Test SMTP commands availability"""
        command_info = {
            'supported_commands': [],
            'dangerous_commands': [],
            'ehlo_response': '',
            'starttls_available': False
        }

        if not SMTPLIB_AVAILABLE:
            command_info['note'] = 'Advanced SMTP testing unavailable - smtplib not available'
            return command_info

        try:
            if is_smtps:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                smtp = smtplib.SMTP_SSL(ip, port, timeout=self.timeout, context=context)
            else:
                smtp = smtplib.SMTP(ip, port, timeout=self.timeout)

            # Get EHLO response
            try:
                code, response = smtp.ehlo()
                if code == 250:
                    command_info['ehlo_response'] = response.decode('utf-8', errors='ignore')
                    extensions = self._parse_ehlo_extensions(response.decode('utf-8', errors='ignore'))
                    command_info['supported_commands'] = extensions

                    # Check for STARTTLS
                    if 'STARTTLS' in [ext.upper() for ext in extensions]:
                        command_info['starttls_available'] = True

                    # Check for dangerous commands
                    dangerous = ['VRFY', 'EXPN', 'TURN']
                    for cmd in dangerous:
                        if cmd in [ext.upper() for ext in extensions]:
                            command_info['dangerous_commands'].append(cmd)
            except:
                pass

            smtp.quit()

        except Exception as e:
            command_info['error'] = str(e)

        return command_info

    def _parse_ehlo_extensions(self, ehlo_response: str) -> List[str]:
        """Parse EHLO response to extract supported extensions"""
        extensions = []
        lines = ehlo_response.split('\n')

        for line in lines:
            line = line.strip()
            if line.startswith('250-') or line.startswith('250 '):
                extension = line[4:].strip()
                if extension and not extension.startswith('Hello') and extension not in extensions:
                    extensions.append(extension)

        return extensions

    def _basic_relay_test(self, ip: str, port: int, is_smtps: bool) -> Dict[str, Any]:
        """Basic relay testing (complement to nmap)"""
        relay_info = {
            'relay_test_attempted': True,
            'relay_results': {},
            'open_relay_detected': False
        }

        if not SMTPLIB_AVAILABLE:
            return relay_info

        try:
            if is_smtps:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                smtp = smtplib.SMTP_SSL(ip, port, timeout=self.timeout, context=context)
            else:
                smtp = smtplib.SMTP(ip, port, timeout=self.timeout)

            # Test basic relay patterns
            test_cases = [
                ('test@example.com', 'test@gmail.com'),  # External to external
                ('user@localhost', 'user@yahoo.com'),  # Local to external
            ]

            for mail_from, rcpt_to in test_cases:
                try:
                    smtp.mail(mail_from)
                    code, response = smtp.rcpt(rcpt_to)
                    smtp.rset()  # Reset without sending

                    test_key = f'{mail_from}->{rcpt_to}'
                    if code == 250:
                        relay_info['relay_results'][test_key] = 'ACCEPTED - Potential open relay'
                        relay_info['open_relay_detected'] = True
                    else:
                        relay_info['relay_results'][test_key] = f'REJECTED ({code})'

                except Exception as e:
                    relay_info['relay_results'][f'{mail_from}->{rcpt_to}'] = f'ERROR: {str(e)}'

            smtp.quit()

        except Exception as e:
            relay_info['error'] = str(e)

        return relay_info

    def _extensive_command_testing(self, ip: str, port: int, is_smtps: bool) -> Dict[str, Any]:
        """Extensive SMTP command testing for aggressive mode"""
        command_info = {
            'vrfy_testing': {},
            'expn_testing': {},
            'help_command': '',
            'extended_commands': []
        }

        if not SMTPLIB_AVAILABLE:
            return command_info

        try:
            if is_smtps:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                smtp = smtplib.SMTP_SSL(ip, port, timeout=self.timeout, context=context)
            else:
                smtp = smtplib.SMTP(ip, port, timeout=self.timeout)

            # Test VRFY command with common users
            vrfy_results = {}
            for user in self.common_users[:5]:  # Limit to avoid being too noisy
                try:
                    code, response = smtp.docmd(f'VRFY {user}')
                    vrfy_results[user] = {
                        'code': code,
                        'response': response.decode('utf-8', errors='ignore') if isinstance(response, bytes) else str(
                            response)
                    }
                    if code == 250:
                        command_info['vrfy_enabled'] = True
                except Exception as e:
                    vrfy_results[user] = {'error': str(e)}

            command_info['vrfy_testing'] = vrfy_results

            # Test EXPN command
            try:
                code, response = smtp.docmd('EXPN root')
                command_info['expn_testing'] = {
                    'code': code,
                    'response': response.decode('utf-8', errors='ignore') if isinstance(response, bytes) else str(
                        response)
                }
            except Exception as e:
                command_info['expn_testing'] = {'error': str(e)}

            # Test HELP command
            try:
                code, response = smtp.docmd('HELP')
                if code == 214:
                    command_info['help_command'] = response.decode('utf-8', errors='ignore') if isinstance(response,
                                                                                                           bytes) else str(
                        response)
            except Exception as e:
                command_info['help_error'] = str(e)

            smtp.quit()

        except Exception as e:
            command_info['error'] = str(e)

        return command_info

    def _comprehensive_relay_testing(self, ip: str, port: int, is_smtps: bool) -> Dict[str, Any]:
        """Comprehensive relay testing for aggressive mode"""
        relay_info = {
            'extensive_relay_tests': {},
            'relay_patterns_tested': 0,
            'open_relay_confidence': 'none'
        }

        if not SMTPLIB_AVAILABLE:
            return relay_info

        try:
            if is_smtps:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                smtp = smtplib.SMTP_SSL(ip, port, timeout=self.timeout, context=context)
            else:
                smtp = smtplib.SMTP(ip, port, timeout=self.timeout)

            # Comprehensive relay test patterns
            test_patterns = [
                ('test@example.com', 'victim@target.com'),
                ('user@localhost', 'external@gmail.com'),
                ('postmaster@localhost', 'test@yahoo.com'),
                ('""@localhost', 'user@hotmail.com'),  # Empty sender
                ('user@[192.168.1.1]', 'test@example.org'),  # IP literal
            ]

            successful_relays = 0
            for mail_from, rcpt_to in test_patterns:
                try:
                    smtp.mail(mail_from)
                    code, response = smtp.rcpt(rcpt_to)
                    smtp.rset()

                    test_key = f'{mail_from} -> {rcpt_to}'
                    if code == 250:
                        relay_info['extensive_relay_tests'][test_key] = f'ACCEPTED ({code})'
                        successful_relays += 1
                    else:
                        relay_info['extensive_relay_tests'][test_key] = f'REJECTED ({code})'

                    relay_info['relay_patterns_tested'] += 1

                except Exception as e:
                    relay_info['extensive_relay_tests'][f'{mail_from} -> {rcpt_to}'] = f'ERROR: {str(e)}'

                time.sleep(1)  # Rate limiting

            # Determine confidence level
            if successful_relays >= 3:
                relay_info['open_relay_confidence'] = 'high'
            elif successful_relays >= 1:
                relay_info['open_relay_confidence'] = 'medium'
            else:
                relay_info['open_relay_confidence'] = 'none'

            smtp.quit()

        except Exception as e:
            relay_info['error'] = str(e)

        return relay_info

    def _smtp_user_enumeration(self, ip: str, port: int, is_smtps: bool) -> Dict[str, Any]:
        """SMTP user enumeration via VRFY/EXPN"""
        enum_info = {
            'enumeration_methods': [],
            'valid_users': [],
            'vrfy_enabled': False,
            'expn_enabled': False
        }

        if not SMTPLIB_AVAILABLE:
            return enum_info

        try:
            if is_smtps:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                smtp = smtplib.SMTP_SSL(ip, port, timeout=self.timeout, context=context)
            else:
                smtp = smtplib.SMTP(ip, port, timeout=self.timeout)

            # Test VRFY with common usernames
            for username in self.common_users[:8]:  # Limit to avoid detection
                try:
                    code, response = smtp.docmd(f'VRFY {username}')
                    if code == 250:
                        enum_info['vrfy_enabled'] = True
                        if 'VRFY' not in enum_info['enumeration_methods']:
                            enum_info['enumeration_methods'].append('VRFY')
                        enum_info['valid_users'].append(username)
                except:
                    continue

                time.sleep(0.5)  # Rate limiting

            # Test EXPN
            try:
                code, response = smtp.docmd('EXPN root')
                if code == 250:
                    enum_info['expn_enabled'] = True
                    if 'EXPN' not in enum_info['enumeration_methods']:
                        enum_info['enumeration_methods'].append('EXPN')
            except:
                pass

            smtp.quit()

        except Exception as e:
            enum_info['error'] = str(e)

        return enum_info

    def _smtp_timing_analysis(self, ip: str, port: int, is_smtps: bool) -> Dict[str, Any]:
        """SMTP timing analysis for user enumeration"""
        timing_info = {
            'baseline_time': 0,
            'timing_differences': {},
            'potential_user_enum': False
        }

        if not SMTPLIB_AVAILABLE:
            return timing_info

        try:
            # Establish baseline with non-existent user
            baseline_times = []
            for i in range(3):
                start_time = time.time()
                try:
                    if is_smtps:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        smtp = smtplib.SMTP_SSL(ip, port, timeout=self.timeout, context=context)
                    else:
                        smtp = smtplib.SMTP(ip, port, timeout=self.timeout)

                    smtp.docmd(f'VRFY nonexistent_user_{i}')
                    smtp.quit()
                except:
                    pass
                baseline_times.append((time.time() - start_time) * 1000)
                time.sleep(1)

            timing_info['baseline_time'] = sum(baseline_times) / len(baseline_times)

            # Test common usernames for timing differences
            for username in ['root', 'admin', 'postmaster']:
                try:
                    start_time = time.time()
                    if is_smtps:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        smtp = smtplib.SMTP_SSL(ip, port, timeout=self.timeout, context=context)
                    else:
                        smtp = smtplib.SMTP(ip, port, timeout=self.timeout)

                    smtp.docmd(f'VRFY {username}')
                    response_time = (time.time() - start_time) * 1000

                    timing_info['timing_differences'][username] = {
                        'response_time': response_time,
                        'difference': response_time - timing_info['baseline_time']
                    }

                    # If response is significantly different, potential enum
                    if abs(response_time - timing_info['baseline_time']) > 200:
                        timing_info['potential_user_enum'] = True

                    smtp.quit()
                except:
                    pass

                time.sleep(2)

        except Exception as e:
            timing_info['error'] = str(e)

        return timing_info

    def _hydra_password_attacks_per_user(self, ip: str, port: int, usernames: List[str], is_smtps: bool) -> Dict[
        str, Any]:
        """Enhanced manual SMTP password attacks - No Hydra dependency"""
        attack_results = {
            'total_users_attacked': len(usernames),
            'individual_attacks': {},
            'successful_credentials': [],
            'total_duration': 0,
            'attack_method': 'enhanced_manual_smtp',
            'tool_used': 'python_smtplib_enhanced'
        }

        if not SMTPLIB_AVAILABLE:
            attack_results['error'] = 'smtplib not available for password attacks'
            return attack_results

        try:
            # Enhanced password list with user-specific variations
            base_passwords = [
                'password', '123456', 'admin', 'root', 'smtp', 'mail',
                'postfix', 'sendmail', 'email', 'server', 'test', 'guest',
                'user', 'pass', '12345', 'qwerty', 'letmein', 'welcome',
                'password123', 'admin123', 'root123', '1234', '123',
                'password1', 'admin1', 'changeme', 'default', 'login',
                '', 'blank', 'password321', '654321', 'abc123',
                'Password1', 'Password123', 'Admin123', 'Root123',
                'service', 'daemon', 'system', 'backup', 'mysql',
                'postgres', 'database', 'ftp', 'ssh', 'web'
            ]

            total_start_time = time.time()
            print(f"🔓 Starting enhanced manual SMTP password attacks on {len(usernames)} users...")
            print(f"🎯 Using {len(base_passwords)} base passwords + user-specific variations")

            for username in usernames:
                user_attack_start = time.time()
                print(f"🔓 Enhanced testing user: {username}")

                user_result = {
                    'username': username,
                    'attack_duration': 0,
                    'passwords_tested': 0,
                    'success': False,
                    'password_found': None,
                    'method': 'enhanced_manual_smtp_auth',
                    'connection_attempts': 0
                }

                # Generate user-specific password list
                user_passwords = self._generate_user_specific_passwords(username, base_passwords)
                print(f"📋 Generated {len(user_passwords)} passwords for {username}")

                # Test each password for this user
                for i, password in enumerate(user_passwords):
                    try:
                        success = self._test_smtp_auth_enhanced(ip, port, username, password, is_smtps)
                        user_result['passwords_tested'] += 1
                        user_result['connection_attempts'] += 1

                        if success:
                            user_result['success'] = True
                            user_result['password_found'] = password
                            attack_results['successful_credentials'].append({
                                'username': username,
                                'password': password,
                                'service': 'smtp',
                                'verified': True,
                                'attack_method': 'enhanced_manual'
                            })
                            print(f"🔓 SUCCESS: {username}:{password}")
                            break

                        # Progressive rate limiting (faster for common passwords)
                        if i < 10:
                            time.sleep(0.5)  # Fast for top 10
                        elif i < 20:
                            time.sleep(1)  # Medium for next 10
                        else:
                            time.sleep(1.5)  # Slower for remaining

                        # Progress indicator
                        if (i + 1) % 10 == 0:
                            print(f"🔄 Progress for {username}: {i + 1}/{len(user_passwords)} passwords tested")

                    except Exception as auth_error:
                        error_msg = str(auth_error).lower()

                        # Handle different types of errors
                        if 'authentication' in error_msg or 'auth' in error_msg:
                            # Authentication failed - continue testing
                            time.sleep(1)
                            continue
                        elif 'connection' in error_msg or 'timeout' in error_msg:
                            # Connection issues - longer delay and retry
                            print(f"⚠️ Connection issue for {username}:{password}: {auth_error}")
                            time.sleep(3)

                            # Try to recover with a test connection
                            if not self._test_smtp_connectivity(ip, port, is_smtps):
                                print(f"❌ SMTP server not responding, skipping remaining passwords for {username}")
                                user_result['error'] = 'SMTP server unresponsive'
                                break
                            continue
                        else:
                            print(f"⚠️ Unexpected error for {username}:{password}: {auth_error}")
                            time.sleep(2)
                            continue

                user_result['attack_duration'] = round(time.time() - user_attack_start, 2)
                attack_results['individual_attacks'][username] = user_result

                if not user_result['success']:
                    print(
                        f"❌ Failed: {username} (no valid passwords found from {user_result['passwords_tested']} attempts)")

                print(f"⏱️ {username} completed in {user_result['attack_duration']}s")

                # Delay between users to avoid detection
                time.sleep(5)

            attack_results['total_duration'] = round(time.time() - total_start_time, 2)
            print(
                f"🎯 Enhanced manual attack summary: {len(attack_results['successful_credentials'])} credentials found in {attack_results['total_duration']}s")

            # Print detailed results
            if attack_results['successful_credentials']:
                print(f"🔓 Successful credentials:")
                for cred in attack_results['successful_credentials']:
                    print(f"   ✅ {cred['username']}:{cred['password']}")

        except Exception as e:
            attack_results['error'] = str(e)
            print(f"❌ Enhanced manual password attacks error: {e}")

        return attack_results

    def _generate_user_specific_passwords(self, username: str, base_passwords: List[str]) -> List[str]:
        """Generate user-specific password variations"""
        user_passwords = []

        # Start with empty password (common for service accounts)
        user_passwords.append('')

        # Add username as password
        user_passwords.append(username)
        user_passwords.append(username.upper())
        user_passwords.append(username.capitalize())

        # Username + common suffixes
        for suffix in ['123', '1', '12', '321', 'pass', 'password']:
            user_passwords.append(f"{username}{suffix}")
            user_passwords.append(f"{username.capitalize()}{suffix}")

        # Username + common prefixes
        for prefix in ['pass', 'pwd']:
            user_passwords.append(f"{prefix}{username}")

        # Service-specific passwords
        service_passwords = {
            'root': ['toor', 'root123', 'rootpass', 'admin'],
            'admin': ['admin123', 'administrator', 'admin1'],
            'postmaster': ['postmaster123', 'mail', 'email'],
            'mail': ['mail123', 'mailpass', 'postfix'],
            'mysql': ['mysql123', 'root', 'database', 'db'],
            'postgres': ['postgres123', 'postgresql', 'database'],
            'ftp': ['ftp123', 'ftppass', 'anonymous'],
            'backup': ['backup123', 'backuppass', 'bak'],
            'user': ['user123', 'userpass', 'guest'],
            'guest': ['guest123', 'guestpass', 'visitor'],
            'test': ['test123', 'testing', 'testpass'],
            'service': ['service123', 'daemon', 'srv']
        }

        if username.lower() in service_passwords:
            user_passwords.extend(service_passwords[username.lower()])

        # Add base passwords
        user_passwords.extend(base_passwords)

        # Remove duplicates while preserving order
        seen = set()
        unique_passwords = []
        for pwd in user_passwords:
            if pwd not in seen:
                seen.add(pwd)
                unique_passwords.append(pwd)

        # Limit to reasonable number to avoid being too noisy
        return unique_passwords[:40]

    def _test_smtp_auth_enhanced(self, ip: str, port: int, username: str, password: str, is_smtps: bool) -> bool:
        """Enhanced SMTP authentication test with better error handling"""
        max_retries = 2

        for attempt in range(max_retries):
            try:
                # Create connection with timeout
                if is_smtps:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    smtp = smtplib.SMTP_SSL(ip, port, timeout=self.timeout, context=context)
                else:
                    smtp = smtplib.SMTP(ip, port, timeout=self.timeout)

                # Initialize connection
                try:
                    smtp.ehlo()
                except:
                    smtp.helo()

                # Test if authentication is supported
                if hasattr(smtp, 'has_extn') and not smtp.has_extn('AUTH'):
                    # SMTP server doesn't support authentication
                    smtp.quit()
                    return False

                # Attempt authentication
                try:
                    if password == '':
                        # Test empty password differently
                        smtp.login(username, '')
                    else:
                        smtp.login(username, password)

                    smtp.quit()
                    return True

                except smtplib.SMTPAuthenticationError as auth_error:
                    smtp.quit()
                    # Authentication failed - this is expected for wrong passwords
                    return False

                except smtplib.SMTPNotSupportedError:
                    smtp.quit()
                    # Authentication not supported
                    return False

                except Exception as auth_error:
                    smtp.quit()
                    error_msg = str(auth_error).lower()

                    # Check if it's actually an auth failure or server issue
                    if any(keyword in error_msg for keyword in ['auth', 'login', 'credential', 'password']):
                        return False  # Authentication failed
                    else:
                        # Other error - might be worth retrying
                        if attempt < max_retries - 1:
                            time.sleep(1)
                            continue
                        raise auth_error

            except Exception as conn_error:
                if attempt < max_retries - 1:
                    print(f"🔄 Connection retry {attempt + 1} for {username}:{password}")
                    time.sleep(2)
                    continue
                else:
                    # Final attempt failed
                    raise conn_error

        return False

    def _test_smtp_connectivity(self, ip: str, port: int, is_smtps: bool) -> bool:
        """Test basic SMTP connectivity"""
        try:
            if is_smtps:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                smtp = smtplib.SMTP_SSL(ip, port, timeout=5, context=context)
            else:
                smtp = smtplib.SMTP(ip, port, timeout=5)

            smtp.ehlo()
            smtp.quit()
            return True

        except Exception:
            return False

    def _parse_hydra_single_user_output(self, stdout: str, username: str) -> Dict[str, Any]:
        """Parse Hydra output for single user attack"""
        return None


    def _security_assessment(self, service_info: Dict[str, Any], enum_info: Dict[str, Any],
                             nmap_data: Dict[str, Any], dns_info: Dict[str, Any], aggressive: bool = False) -> Dict[
        str, Any]:
        """Comprehensive SMTP security assessment using nmap data + enumeration + DNS analysis"""
        vulnerabilities = []
        recommendations = []

        # Get nmap script results
        scripts = nmap_data.get('scripts', {})

        # Process nmap script findings first
        self._process_nmap_script_findings(scripts, vulnerabilities, aggressive)

        # Add findings from manual enumeration
        self._process_manual_findings(enum_info, vulnerabilities)

        # Add DNS vulnerabilities
        dns_vulnerabilities = dns_info.get('dns_vulnerabilities', [])
        vulnerabilities.extend(dns_vulnerabilities)

        # Add service-specific vulnerabilities based on version
        self._check_version_vulnerabilities(service_info, vulnerabilities)

        # Generate recommendations
        recommendations = self._generate_recommendations(vulnerabilities, service_info, dns_info, aggressive)

        return {
            'vulnerabilities': vulnerabilities,
            'recommendations': recommendations
        }

    def _process_nmap_script_findings(self, scripts: Dict[str, Any], vulnerabilities: List[Dict], aggressive: bool):
        """Process nmap NSE script findings with corrected logic"""

        # smtp-open-relay script results - FIXED LOGIC
        if 'smtp-open-relay' in scripts:
            relay_result = scripts['smtp-open-relay'].lower()

            # Check for ACTUAL open relay indicators (BAD - create vulnerability)
            if ('server relays mail' in relay_result or
                    'open relay detected' in relay_result or
                    'relay appears to be open' in relay_result or
                    'relaying allowed' in relay_result or
                    'relay test succeeded' in relay_result):

                vulnerabilities.append({
                    'id': 'SMTP-RELAY-001',
                    'severity': 'Critical',
                    'title': 'Open Mail Relay Detected',
                    'description': f'NSE Detection: {scripts["smtp-open-relay"]}',
                    'recommendation': 'Configure SMTP server to prevent unauthorized mail relay',
                    'source': 'nmap_nse',
                    'detection_method': 'smtp-open-relay_script'
                })

            # Check for secure relay configuration (GOOD - no vulnerability)
            elif ('doesn\'t seem to be an open relay' in relay_result or
                  'all tests failed' in relay_result or
                  'not an open relay' in relay_result or
                  'relay test failed' in relay_result or
                  'no relay' in relay_result):

                # This is GOOD - server is properly secured
                # Don't create a vulnerability for good security
                print(f"✅ SMTP relay security verified: {scripts['smtp-open-relay']}")

            # If result is unclear, create informational finding
            else:
                vulnerabilities.append({
                    'id': 'SMTP-RELAY-INFO',
                    'severity': 'Info',
                    'title': 'SMTP Relay Test Results',
                    'description': f'NSE Detection: {scripts["smtp-open-relay"]}',
                    'recommendation': 'Review SMTP relay configuration and test results',
                    'source': 'nmap_nse',
                    'detection_method': 'smtp-open-relay_script'
                })

        # smtp-enum-users script results
        if 'smtp-enum-users' in scripts:
            enum_result = scripts['smtp-enum-users']

            # Check for successful user enumeration (BAD)
            if ('valid' in enum_result.lower() or
                    'found' in enum_result.lower() or
                    'user exists' in enum_result.lower() or
                    'enumerated' in enum_result.lower()):

                vulnerabilities.append({
                    'id': 'SMTP-ENUM-001',
                    'severity': 'Medium',
                    'title': 'SMTP User Enumeration Possible',
                    'description': f'NSE Detection: {enum_result}',
                    'recommendation': 'Disable VRFY and EXPN commands to prevent user enumeration',
                    'source': 'nmap_nse',
                    'detection_method': 'smtp-enum-users_script'
                })

            # Check for failed enumeration (GOOD)
            elif ('no users' in enum_result.lower() or
                  'enumeration failed' in enum_result.lower() or
                  'disabled' in enum_result.lower()):

                # This is GOOD - enumeration is prevented
                print(f"✅ SMTP user enumeration prevented: {enum_result}")

        # smtp-commands script results
        if 'smtp-commands' in scripts:
            commands_result = scripts['smtp-commands']
            dangerous_commands = ['VRFY', 'EXPN', 'TURN']

            for cmd in dangerous_commands:
                if cmd in commands_result:
                    severity = 'High' if cmd == 'TURN' else 'Medium'
                    vulnerabilities.append({
                        'id': f'SMTP-CMD-{cmd}',
                        'severity': severity,
                        'title': f'Dangerous SMTP Command Enabled: {cmd}',
                        'description': f'SMTP server supports {cmd} command: {commands_result}',
                        'recommendation': f'Disable {cmd} command to improve security',
                        'source': 'nmap_nse',
                        'detection_method': 'smtp-commands_script'
                    })

        # smtp-ntlm-info script results
        if 'smtp-ntlm-info' in scripts:
            ntlm_result = scripts['smtp-ntlm-info']
            if ntlm_result and len(ntlm_result.strip()) > 0:
                vulnerabilities.append({
                    'id': 'SMTP-NTLM-001',
                    'severity': 'Low',
                    'title': 'SMTP NTLM Information Disclosure',
                    'description': f'NTLM information revealed: {ntlm_result}',
                    'recommendation': 'Review NTLM configuration to limit information disclosure',
                    'source': 'nmap_nse',
                    'detection_method': 'smtp-ntlm-info_script'
                })

        # Process additional scripts from aggressive scan
        if aggressive:
            for script_name, result in scripts.items():
                if script_name.startswith('smtp-') and script_name not in [
                    'smtp-open-relay', 'smtp-enum-users', 'smtp-commands', 'smtp-ntlm-info'
                ]:
                    result_lower = result.lower()

                    # Look for actual vulnerability indicators
                    if any(keyword in result_lower for keyword in [
                        'vulnerable', 'exploit', 'weakness', 'backdoor', 'attack',
                        'security issue', 'flaw', 'bypass', 'injection'
                    ]):
                        severity = 'Critical' if any(critical_word in result_lower for critical_word in [
                            'backdoor', 'exploit', 'injection', 'bypass'
                        ]) else 'High'

                        vulnerabilities.append({
                            'id': f'SMTP-{script_name.upper().replace("-", "_")}',
                            'severity': severity,
                            'title': f'SMTP Vulnerability: {script_name}',
                            'description': f'NSE Detection: {result}',
                            'recommendation': 'Review and remediate the detected SMTP vulnerability',
                            'source': 'nmap_nse_aggressive',
                            'detection_method': script_name
                        })

                    # Look for informational findings (not vulnerabilities)
                    elif any(info_word in result_lower for info_word in [
                        'information', 'banner', 'version', 'configuration',
                        'supported', 'available', 'enabled'
                    ]) and not any(vuln_word in result_lower for vuln_word in [
                        'vulnerable', 'exploit', 'weakness', 'attack'
                    ]):
                        vulnerabilities.append({
                            'id': f'SMTP-INFO-{script_name.upper().replace("-", "_")}',
                            'severity': 'Info',
                            'title': f'SMTP Information: {script_name}',
                            'description': f'NSE Detection: {result}',
                            'recommendation': 'Review SMTP configuration for security best practices',
                            'source': 'nmap_nse_aggressive',
                            'detection_method': script_name
                        })

    def _process_manual_findings(self, enum_info: Dict[str, Any], vulnerabilities: List[Dict]):
        """Process manual enumeration findings"""

        # Connection analysis findings
        connection_analysis = enum_info.get('connection_analysis', {})
        banner_analysis = connection_analysis.get('banner_analysis', {})

        if banner_analysis.get('version_disclosed'):
            vulnerabilities.append({
                'id': 'SMTP-INFO-001',
                'severity': 'Low',
                'title': 'SMTP Version Information Disclosure',
                'description': f'SMTP banner reveals version information: {banner_analysis.get("banner", "")}',
                'recommendation': 'Configure SMTP server to hide version information in banner',
                'source': 'manual_verification',
                'detection_method': 'banner_analysis'
            })

        # Command testing findings
        command_testing = enum_info.get('command_testing', {}) or enum_info.get('extensive_command_testing', {})
        dangerous_commands = command_testing.get('dangerous_commands', [])

        for cmd in dangerous_commands:
            vulnerabilities.append({
                'id': f'SMTP-MANUAL-{cmd}',
                'severity': 'Medium',
                'title': f'Dangerous SMTP Command: {cmd}',
                'description': f'Manual testing confirmed {cmd} command is enabled',
                'recommendation': f'Disable {cmd} command to prevent information disclosure',
                'source': 'manual_verification',
                'detection_method': 'command_testing'
            })

        # Relay testing findings
        relay_testing = enum_info.get('relay_testing', {}) or enum_info.get('comprehensive_relay_testing', {})
        if relay_testing.get('open_relay_detected') or relay_testing.get('open_relay_confidence') == 'high':
            vulnerabilities.append({
                'id': 'SMTP-RELAY-002',
                'severity': 'Critical',
                'title': 'Open Mail Relay (Manual Verification)',
                'description': 'Manual testing confirmed open mail relay configuration',
                'recommendation': 'Immediately configure SMTP server to prevent unauthorized relay',
                'source': 'manual_verification',
                'detection_method': 'relay_testing'
            })

        # User enumeration findings
        user_enum = enum_info.get('user_enumeration', {})
        if user_enum.get('vrfy_enabled') or user_enum.get('expn_enabled'):
            methods = []
            if user_enum.get('vrfy_enabled'):
                methods.append('VRFY')
            if user_enum.get('expn_enabled'):
                methods.append('EXPN')

            vulnerabilities.append({
                'id': 'SMTP-ENUM-002',
                'severity': 'Medium',
                'title': 'SMTP User Enumeration (Manual Verification)',
                'description': f'Manual testing confirmed user enumeration via {", ".join(methods)} commands',
                'recommendation': f'Disable {", ".join(methods)} commands to prevent user enumeration',
                'source': 'manual_verification',
                'detection_method': 'user_enumeration'
            })

        # Timing analysis findings
        timing_analysis = enum_info.get('timing_analysis', {})
        if timing_analysis.get('potential_user_enum'):
            vulnerabilities.append({
                'id': 'SMTP-TIMING-001',
                'severity': 'Low',
                'title': 'SMTP Timing-Based User Enumeration',
                'description': 'Timing analysis suggests user enumeration may be possible',
                'recommendation': 'Configure SMTP server to provide consistent response times',
                'source': 'manual_verification',
                'detection_method': 'timing_analysis'
            })

    def _check_version_vulnerabilities(self, service_info: Dict[str, Any], vulnerabilities: List[Dict]):
        """Check for known vulnerabilities based on SMTP server version"""
        server_type = service_info.get('server_type', '').lower()
        version = service_info.get('version', '')

        # Known vulnerable versions
        if 'postfix' in server_type:
            if version.startswith('2.'):
                vulnerabilities.append({
                    'id': 'SMTP-VERSION-001',
                    'severity': 'Medium',
                    'title': 'Outdated Postfix Version',
                    'description': f'Postfix version {version} may have known vulnerabilities',
                    'recommendation': 'Update Postfix to the latest stable version',
                    'source': 'version_analysis',
                    'detection_method': 'version_banner'
                })

        elif 'sendmail' in server_type:
            if version and version.startswith('8.'):
                # Check for specific vulnerable versions
                vulnerable_versions = ['8.13.0', '8.13.1', '8.14.0']
                if any(version.startswith(v) for v in vulnerable_versions):
                    vulnerabilities.append({
                        'id': 'SMTP-SENDMAIL-001',
                        'severity': 'High',
                        'title': 'Vulnerable Sendmail Version',
                        'description': f'Sendmail version {version} has known security vulnerabilities',
                        'recommendation': 'Upgrade Sendmail to the latest patched version',
                        'source': 'version_analysis',
                        'detection_method': 'version_banner'
                    })

        elif 'exim' in server_type:
            if version and version.startswith('4.'):
                # Exim 4.x versions before 4.94 have vulnerabilities
                try:
                    version_parts = version.split('.')
                    major = int(version_parts[0])
                    minor = int(version_parts[1]) if len(version_parts) > 1 else 0

                    if major == 4 and minor < 94:
                        vulnerabilities.append({
                            'id': 'SMTP-EXIM-001',
                            'severity': 'High',
                            'title': 'Vulnerable Exim Version',
                            'description': f'Exim version {version} has known security vulnerabilities',
                            'recommendation': 'Upgrade Exim to version 4.94 or later',
                            'source': 'version_analysis',
                            'detection_method': 'version_banner'
                        })
                except ValueError:
                    pass

    def _generate_recommendations(self, vulnerabilities: List[Dict], service_info: Dict[str, Any],
                                  dns_info: Dict[str, Any], aggressive: bool = False) -> List[str]:
        """Generate comprehensive security recommendations"""
        recommendations = []

        # Basic SMTP security recommendations
        recommendations.extend([
            'Use SMTP over SSL/TLS (SMTPS) or STARTTLS for encrypted communication',
            'Implement strong authentication mechanisms for mail submission',
            'Configure proper access controls and rate limiting',
            'Regular monitoring of SMTP logs for suspicious activity',
            'Keep SMTP server software updated to the latest version'
        ])

        # DNS-based recommendations
        dns_recommendations = dns_info.get('dns_recommendations', [])
        recommendations.extend(dns_recommendations)

        # Vulnerability-specific recommendations
        vuln_types = [v.get('id', '') for v in vulnerabilities]

        if any('RELAY' in v_id for v_id in vuln_types):
            recommendations.extend([
                'URGENT: Configure SMTP server to prevent open mail relay',
                'Implement proper relay restrictions and authentication',
                'Test relay configuration regularly with external tools'
            ])

        if any('ENUM' in v_id for v_id in vuln_types):
            recommendations.extend([
                'Disable VRFY and EXPN commands to prevent user enumeration',
                'Implement rate limiting to prevent enumeration attacks',
                'Use generic error messages for invalid recipients'
            ])

        if any('CMD' in v_id for v_id in vuln_types):
            recommendations.append('Disable unnecessary SMTP commands (VRFY, EXPN, TURN)')

        if any('INFO' in v_id for v_id in vuln_types):
            recommendations.extend([
                'Hide version information in SMTP banner',
                'Use generic hostname in SMTP banner',
                'Minimize information disclosure in error messages'
            ])

        # DNS security recommendations
        if not dns_info.get('spf_record'):
            recommendations.append('Implement SPF record to prevent email spoofing')

        if not dns_info.get('dmarc_record'):
            recommendations.append('Implement DMARC record for enhanced email security')

        if not dns_info.get('dkim_records'):
            recommendations.append('Implement DKIM signing for email authentication')

        # Aggressive scan specific recommendations
        if aggressive:
            recommendations.extend([
                'Perform regular comprehensive SMTP security assessments',
                'Subscribe to security advisories for your SMTP server software',
                'Implement intrusion detection/prevention systems (IDS/IPS)',
                'Consider using email security gateways for additional protection',
                'Regular penetration testing of email infrastructure',
                'Implement BIMI (Brand Indicators for Message Identification)',
                'Monitor for email spoofing and phishing attempts',
                'Use threat intelligence feeds for email security'
            ])

        # Server-specific recommendations
        server_type = service_info.get('server_type', '').lower()
        if 'postfix' in server_type:
            recommendations.append('Configure Postfix security settings according to hardening guides')
        elif 'sendmail' in server_type:
            recommendations.append('Consider migrating from Sendmail to more secure alternatives')
        elif 'exim' in server_type:
            recommendations.append('Keep Exim updated and review configuration for security best practices')
        elif 'exchange' in server_type:
            recommendations.append('Apply latest Microsoft Exchange security updates and patches')

        # General hardening recommendations
        recommendations.extend([
            'Implement connection limits and timeout settings',
            'Use non-standard ports to reduce automated attacks',
            'Enable comprehensive logging and log monitoring',
            'Implement network segmentation for mail services',
            'Use reputation-based filtering and blacklists',
            'Configure proper reverse DNS (PTR) records',
            'Implement email content filtering and anti-malware scanning'
        ])

        return list(set(recommendations))  # Remove duplicates

    def test_wsl_dig(self):
        """Test if Kali WSL dig is working"""
        try:
            # Test WSL
            wsl_test = subprocess.run(['wsl', 'echo', 'WSL works'],
                                      capture_output=True, text=True, timeout=5)
            if wsl_test.returncode != 0:
                return {'wsl_available': False, 'error': 'WSL not working'}

            # Test dig in WSL
            dig_test = subprocess.run(['wsl', 'dig', 'google.com', '+short'],
                                      capture_output=True, text=True, timeout=10)
            if dig_test.returncode != 0:
                return {'wsl_available': True, 'dig_available': False, 'error': 'dig not found in WSL'}

            return {
                'wsl_available': True,
                'dig_available': True,
                'dig_version': 'Available via WSL',
                'status': 'ready'
            }

        except Exception as e:
            return {'wsl_available': False, 'error': str(e)}

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