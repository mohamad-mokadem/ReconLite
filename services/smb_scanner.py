import socket
import time
import subprocess
import re
import struct
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from .base_scanner import BaseScanner

# Force nmap-only mode
NMAP_ONLY_MODE = True
print("🎯 SMB Scanner: Using nmap-only mode for reliability")


class SMBScanner(BaseScanner):
    """SMB Scanner with nmap-only implementation - Normal and Aggressive modes"""

    def __init__(self, timeout: int = 10):
        super().__init__(timeout)
        # Remove unnecessary attributes since we're nmap-only
        self.nmap_only = True

    def get_supported_ports(self) -> List[int]:
        return [139, 445]  # NetBIOS and SMB

    def get_service_name(self) -> str:
        return "SMB"

    def scan(self, ip: str, port: int, **kwargs) -> Dict[str, Any]:
        """Standard SMB scanning - SAFE nmap scripts only"""
        self.scan_start_time = time.time()
        results = self.create_base_result(ip, port)

        try:
            # Step 1: Basic connectivity check
            self.mark_step_completed(results, 'connectivity')
            connectivity_info = self.check_port_connectivity(ip, port)
            results['connectivity_info'] = connectivity_info

            if not connectivity_info.get('accessible'):
                return self.create_failed_result(ip, port,
                                                 connectivity_info.get('failure_reason', 'SMB service not accessible'),
                                                 connectivity_info)

            # Step 2: Run safe nmap scan
            self.mark_step_completed(results, 'nmap_scan')
            nmap_results = self._run_safe_nmap_scan(ip, port)
            results['nmap_data'] = nmap_results

            if nmap_results.get('error'):
                return self.create_failed_result(ip, port,
                                                 f"Nmap scan failed: {nmap_results['error']}")

            # Extract service info from nmap
            self.update_service_info(results, nmap_results.get('service_info', {}))
            results['banner'] = nmap_results.get('banner', '')

            # Step 3: Parse nmap script results for advanced findings
            self.mark_step_completed(results, 'script_analysis')
            script_findings = self._parse_nmap_scripts(nmap_results, aggressive=False)
            results['advanced_findings'].update(script_findings)

            # Step 4: No deep scan plan needed - results interpreted from nmap output

            # Step 5: Security assessment from nmap results
            self.mark_step_completed(results, 'vulnerability')
            security_info = self._assess_security_from_nmap(nmap_results, script_findings, aggressive=False)
            results['vulnerabilities'] = security_info.get('vulnerabilities', [])
            results['recommendations'] = security_info.get('recommendations', [])

            return self.finalize_results(results, success=True)

        except Exception as e:
            results['error'] = str(e)
            return self.finalize_results(results, success=False)

    def scan_aggressive(self, ip: str, port: int, **kwargs) -> Dict[str, Any]:
        """Aggressive SMB scanning - ALL nmap scripts including brute force"""
        self.scan_start_time = time.time()
        results = self.create_base_result(ip, port)

        try:
            # Get normal scan results for context
            normal_results = kwargs.get('normal_scan_results')
            print(f"🎯 Starting SMB Aggressive Scan with all nmap scripts...")

            # Step 1: Basic connectivity check
            self.mark_step_completed(results, 'connectivity')
            connectivity_info = self.check_port_connectivity(ip, port)
            results['connectivity_info'] = connectivity_info

            if not connectivity_info.get('accessible'):
                return self.create_failed_result(ip, port,
                                                 connectivity_info.get('failure_reason', 'SMB service not accessible'),
                                                 connectivity_info)

            # Step 2: Run aggressive nmap scan
            self.mark_step_completed(results, 'aggressive_nmap_scan')
            nmap_results = self._run_aggressive_nmap_scan(ip, port)
            results['nmap_data'] = nmap_results
            results['scan_mode'] = 'aggressive'

            if nmap_results.get('error'):
                return self.create_failed_result(ip, port,
                                                 f"Aggressive nmap scan failed: {nmap_results['error']}")

            # Extract enhanced service info
            self.update_service_info(results, nmap_results.get('service_info', {}))
            results['banner'] = nmap_results.get('banner', '')

            # Step 3: Parse aggressive nmap script results
            self.mark_step_completed(results, 'aggressive_script_analysis')
            script_findings = self._parse_nmap_scripts(nmap_results, aggressive=True)
            results['advanced_findings'].update(script_findings)

            # Step 4: Enhanced security assessment
            self.mark_step_completed(results, 'aggressive_vulnerability')
            security_info = self._assess_security_from_nmap(nmap_results, script_findings, aggressive=True)
            results['vulnerabilities'] = security_info.get('vulnerabilities', [])
            results['recommendations'] = security_info.get('recommendations', [])

            return self.finalize_results(results, success=True)

        except Exception as e:
            results['error'] = str(e)
            return self.finalize_results(results, success=False)

    def _run_safe_nmap_scan(self, ip: str, port: int) -> Dict[str, Any]:
        """Run safe nmap scan with basic SMB scripts"""
        try:

            cmd = [
                'wsl','nmap', '-sC','-sT', f'-p{port}',
                '--script', 'smb-os-discovery,smb-enum-shares,smb-security-mode',
                '--script-timeout', '60s',
                '--host-timeout', '300s',
                ip
            ]

            print(f"🎯 Running safe SMB nmap: {' '.join(cmd)}")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=360)

            if result.returncode != 0:
                error_msg = f"Nmap failed with return code {result.returncode}"
                if result.stderr:
                    error_msg += f": {result.stderr}"
                return {'error': error_msg}

            parsed = self._parse_nmap_output(result.stdout, aggressive=False)
            parsed['command_used'] = ' '.join(cmd)
            parsed['tool_used'] = 'nmap_safe'
            parsed['scan_type'] = 'safe'

            return parsed

        except subprocess.TimeoutExpired:
            return {'error': 'Nmap scan timed out after 6 minutes'}
        except Exception as e:
            return {'error': f'Nmap execution failed: {str(e)}'}

    def _run_aggressive_nmap_scan(self, ip: str, port: int) -> Dict[str, Any]:
        """Run aggressive nmap scan with all SMB scripts including brute force"""
        try:
            # Aggressive nmap command: nmap -sV -sC -p 445 --script "smb-enum*,smb-vuln*,smb-brute" -Pn -T4 <target>
            cmd = [
                'wsl','nmap', '-sV', '-sC', f'-p{port}',
                '--script', 'smb-enum*,smb-vuln*,smb-brute',
                '-Pn', '-T4',
                '--script-timeout', '120s',
                '--host-timeout', '600s',
                ip
            ]

            print(f"🎯 Running aggressive SMB nmap: {' '.join(cmd)}")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=720)

            if result.returncode != 0:
                error_msg = f"Aggressive nmap failed with return code {result.returncode}"
                if result.stderr:
                    error_msg += f": {result.stderr}"
                return {'error': error_msg}

            parsed = self._parse_nmap_output(result.stdout, aggressive=True)
            parsed['command_used'] = ' '.join(cmd)
            parsed['tool_used'] = 'nmap_aggressive'
            parsed['scan_type'] = 'aggressive'

            return parsed

        except subprocess.TimeoutExpired:
            return {'error': 'Aggressive nmap scan timed out after 12 minutes'}
        except Exception as e:
            return {'error': f'Aggressive nmap execution failed: {str(e)}'}

    def _parse_nmap_output(self, nmap_output: str, aggressive: bool = False) -> Dict[str, Any]:
        """Enhanced parsing for SMB nmap output"""
        parsed = {
            'service_info': {},
            'banner': '',
            'scripts': {},
            'raw_output': nmap_output,
            'formatted_for_display': self._format_for_user_display(nmap_output),
            'scan_mode': 'aggressive' if aggressive else 'safe'
        }

        lines = nmap_output.split('\n')

        for line in lines:
            line_stripped = line.strip()

            # Parse SMB service line
            if '/tcp' in line and (
                    'netbios' in line.lower() or 'microsoft-ds' in line.lower() or 'smb' in line.lower()):
                parsed['service_info']['server_type'] = self._extract_server_type(line)
                parsed['service_info']['version'] = self._extract_version(line)
                parsed['banner'] = line_stripped

            # Parse SMB script results - enhanced for new scripts
            elif line_stripped.startswith('|_smb-os-discovery:') or line_stripped.startswith('| smb-os-discovery:'):
                parsed['scripts']['smb-os-discovery'] = self._extract_script_content(line_stripped, 'smb-os-discovery')
            elif line_stripped.startswith('|_smb-security-mode:') or line_stripped.startswith('| smb-security-mode:'):
                parsed['scripts']['smb-security-mode'] = self._extract_script_content(line_stripped,
                                                                                      'smb-security-mode')
            elif line_stripped.startswith('|_smb-enum-shares:') or line_stripped.startswith('| smb-enum-shares:'):
                parsed['scripts']['smb-enum-shares'] = self._extract_script_content(line_stripped, 'smb-enum-shares')

            # Aggressive mode script parsing
            elif aggressive and (line_stripped.startswith('|_smb-enum-') or line_stripped.startswith('| smb-enum-')):
                script_name = self._extract_script_name(line_stripped)
                if script_name:
                    parsed['scripts'][script_name] = self._extract_script_content(line_stripped, script_name)

            elif aggressive and (line_stripped.startswith('|_smb-vuln-') or line_stripped.startswith('| smb-vuln-')):
                script_name = self._extract_script_name(line_stripped)
                if script_name:
                    parsed['scripts'][script_name] = self._extract_script_content(line_stripped, script_name)

            elif aggressive and (line_stripped.startswith('|_smb-brute') or line_stripped.startswith('| smb-brute')):
                parsed['scripts']['smb-brute'] = self._extract_script_content(line_stripped, 'smb-brute')

        return parsed

    def _extract_script_name(self, line: str) -> Optional[str]:
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

    def _parse_nmap_scripts(self, nmap_data: Dict[str, Any], aggressive: bool = False) -> Dict[str, Any]:
        """Parse nmap script results into structured findings directly from nmap output"""
        findings = {}
        scripts = nmap_data.get('scripts', {})
        raw_output = nmap_data.get('raw_output', '')

        # Parse OS discovery from raw output
        if 'smb-os-discovery' in scripts or 'OS:' in raw_output or 'Computer name:' in raw_output:
            findings['os_discovery'] = self._parse_os_discovery_from_raw(raw_output,
                                                                         scripts.get('smb-os-discovery', ''))

        # Parse security mode from raw output
        if 'smb-security-mode' in scripts or 'Message signing' in raw_output:
            findings['security_mode'] = self._parse_security_mode_from_raw(raw_output,
                                                                           scripts.get('smb-security-mode', ''))

        # Parse share enumeration from raw output
        if 'smb-enum-shares' in scripts or 'Sharename' in raw_output:
            findings['share_enumeration'] = self._parse_share_enumeration_from_raw(raw_output,
                                                                                   scripts.get('smb-enum-shares', ''))

        if aggressive:
            # Parse vulnerability findings from raw output
            vuln_findings = self._parse_vulnerability_findings_from_raw(raw_output, scripts)
            if vuln_findings:
                findings['vulnerability_findings'] = vuln_findings


            # Parse brute force results from raw output
            brute_results = self._parse_brute_force_from_raw(raw_output, scripts.get('smb-brute', ''))
            if brute_results:
                findings['brute_force_results'] = brute_results

        return findings

    def _parse_os_discovery_from_raw(self, raw_output: str, script_result: str) -> Dict[str, Any]:
        """Parse OS discovery from raw nmap output"""
        parsed = {
            'os_detected': False,
            'computer_name': None,
            'domain': None,
            'workgroup': None,
            'os_version': None,
            'fqdn': None
        }

        # Combine script result and raw output for comprehensive parsing
        combined_text = f"{script_result}\n{raw_output}"

        lines = combined_text.split('\n')
        for line in lines:
            line = line.strip()

            if 'Computer name:' in line:
                parsed['os_detected'] = True
                try:
                    parsed['computer_name'] = line.split('Computer name:')[1].strip()
                except:
                    pass

            elif 'Domain name:' in line:
                try:
                    parsed['domain'] = line.split('Domain name:')[1].strip()
                except:
                    pass

            elif 'Workgroup:' in line:
                try:
                    parsed['workgroup'] = line.split('Workgroup:')[1].strip()
                except:
                    pass

            elif 'FQDN:' in line:
                try:
                    parsed['fqdn'] = line.split('FQDN:')[1].strip()
                except:
                    pass

            elif 'OS:' in line and 'Windows' in line:
                parsed['os_detected'] = True
                try:
                    parsed['os_version'] = line.split('OS:')[1].strip()
                except:
                    pass

        return parsed

    def _parse_security_mode_from_raw(self, raw_output: str, script_result: str) -> Dict[str, Any]:
        """Parse security mode from raw nmap output"""
        parsed = {
            'message_signing': 'unknown',
            'smb_version': None,
            'authentication': 'unknown'
        }

        combined_text = f"{script_result}\n{raw_output}".lower()

        # Parse message signing
        if 'message signing enabled but not required' in combined_text:
            parsed['message_signing'] = 'enabled but not required'
        elif 'message signing enabled and required' in combined_text:
            parsed['message_signing'] = 'required'
        elif 'message signing disabled' in combined_text:
            parsed['message_signing'] = 'disabled'
        elif 'signing' in combined_text:
            if 'required' in combined_text:
                parsed['message_signing'] = 'required'
            elif 'enabled' in combined_text:
                parsed['message_signing'] = 'enabled'
            elif 'disabled' in combined_text:
                parsed['message_signing'] = 'disabled'

        # Parse SMB version
        import re
        smb_match = re.search(r'smb[\s]*([0-9\.]+)', combined_text)
        if smb_match:
            parsed['smb_version'] = smb_match.group(1)

        return parsed

    def _parse_share_enumeration_from_raw(self, raw_output: str, script_result: str) -> Dict[str, Any]:
        """Parse share enumeration from raw nmap output"""
        parsed = {
            'shares_found': [],
            'accessible_shares': [],
            'anonymous_access': False
        }

        combined_text = f"{script_result}\n{raw_output}"
        lines = combined_text.split('\n')

        for line in lines:
            line = line.strip()

            # Look for share listings
            if ('Disk' in line or 'IPC' in line or 'Print' in line) and ('|' in line or 'Sharename' in line):
                # Parse share names
                parts = line.split()
                for part in parts:
                    if part and not part.startswith('|') and not part in ['Disk', 'IPC', 'Print', 'Type', 'Comment']:
                        if part not in parsed['shares_found'] and len(part) > 1:
                            parsed['shares_found'].append(part)

                # Check if accessible
                if 'READ' in line.upper() or 'WRITE' in line.upper() or 'accessible' in line.lower():
                    for part in parts:
                        if part and part not in parsed['accessible_shares'] and part in parsed['shares_found']:
                            parsed['accessible_shares'].append(part)

        # Check for anonymous access
        if 'anonymous' in combined_text.lower() or 'guest' in combined_text.lower() or 'null session' in combined_text.lower():
            parsed['anonymous_access'] = True

        return parsed

    def _parse_vulnerability_findings_from_raw(self, raw_output: str, scripts: Dict[str, Any]) -> Dict[str, Any]:
        """Parse vulnerability findings from raw nmap output"""
        vuln_findings = {}

        # Get vulnerability scripts from scripts dict
        for script_name, result in scripts.items():
            if script_name.startswith('smb-vuln-'):
                vuln_findings[script_name] = result

        # Also parse from raw output for additional context
        lines = raw_output.split('\n')
        current_script = None

        for line in lines:
            line = line.strip()
            if line.startswith('|') and 'smb-vuln-' in line:
                # Extract script name
                if ':' in line:
                    current_script = line.split(':', 1)[0].replace('|_', '').replace('| ', '').strip()
                    if current_script not in vuln_findings:
                        vuln_findings[current_script] = line.split(':', 1)[
                            1].strip() if ':' in line else 'Script executed'
            elif current_script and line.startswith('|') and 'smb-vuln-' not in line:
                # Continue parsing script output
                if current_script in vuln_findings:
                    vuln_findings[current_script] += '\n' + line.replace('|', '').strip()

        return vuln_findings



    def _parse_brute_force_from_raw(self, raw_output: str, script_result: str) -> Dict[str, Any]:
        """Parse brute force results from raw nmap output"""
        parsed = {
            'credentials_found': [],
            'brute_attempted': False,
            'success': False
        }

        combined_text = f"{script_result}\n{raw_output}"

        # Check if brute force was attempted
        if 'smb-brute' in combined_text.lower() or 'brute' in combined_text.lower():
            parsed['brute_attempted'] = True

        # Look for successful credentials
        lines = combined_text.split('\n')
        for line in lines:
            line = line.strip()

            # Look for credential patterns
            if ('valid credentials' in line.lower() or
                    'successful' in line.lower() or
                    'login successful' in line.lower() or
                    '\\' in line and ':' in line):

                parsed['success'] = True

                # Extract credential if it looks like username:password or domain\username:password
                import re
                cred_patterns = [
                    r'([a-zA-Z0-9_-]+)[\\\/]([a-zA-Z0-9_-]+):([a-zA-Z0-9_@#$%^&*-]+)',  # domain\user:pass
                    r'([a-zA-Z0-9_-]+):([a-zA-Z0-9_@#$%^&*-]+)',  # user:pass
                    r'Account found: ([^\s]+)',  # Account found: format
                ]

                for pattern in cred_patterns:
                    matches = re.findall(pattern, line)
                    for match in matches:
                        if isinstance(match, tuple):
                            if len(match) == 3:  # domain\user:pass
                                cred = f"{match[0]}\\{match[1]}:{match[2]}"
                            else:  # user:pass
                                cred = f"{match[0]}:{match[1]}"
                        else:
                            cred = str(match)

                        if cred not in parsed['credentials_found']:
                            parsed['credentials_found'].append(cred)

        return parsed

    def _build_deep_scan_plan_from_nmap(self, nmap_data: Dict[str, Any]) -> Dict[str, Any]:
        """Build attack plan based on nmap findings"""
        plan = {
            'attacks_planned': ['aggressive_nmap_scan'],
            'estimated_time_minutes': 8,
            'risk_level': 'medium',
            'attack_reasoning': ['🎯 NMAP AGGRESSIVE: Full SMB enumeration and vulnerability assessment']
        }

        scripts = nmap_data.get('scripts', {})

        # Check for specific findings that warrant aggressive scanning
        if 'smb-security-mode' in scripts:
            security_result = scripts['smb-security-mode']
            if 'disabled' in security_result.lower() or 'not required' in security_result.lower():
                plan['attack_reasoning'].append('🔓 NO SIGNING: SMB signing disabled - brute force attacks possible')
                plan['risk_level'] = 'high'

        if 'smb-enum-shares' in scripts:
            shares_result = scripts['smb-enum-shares']
            if 'anonymous' in shares_result.lower() or 'guest' in shares_result.lower():
                plan['attack_reasoning'].append('👤 ANONYMOUS ACCESS: Guest/anonymous access detected')

        if 'smb-os-discovery' in scripts:
            os_result = scripts['smb-os-discovery']
            if 'Windows' in os_result and ('2008' in os_result or 'Windows 7' in os_result):
                plan['attack_reasoning'].append('⚠️ LEGACY OS: Older Windows version may have vulnerabilities')
                plan['risk_level'] = 'high'

        return plan

    def _assess_security_from_nmap(self, nmap_data: Dict[str, Any], script_findings: Dict[str, Any],
                                   aggressive: bool = False) -> Dict[str, Any]:
        """Assess security based on nmap results"""
        vulnerabilities = []
        recommendations = []

        scripts = nmap_data.get('scripts', {})

        # Analyze security mode findings
        if 'security_mode' in script_findings:
            sec_mode = script_findings['security_mode']
            if sec_mode.get('message_signing') in ['disabled', 'not required']:
                vulnerabilities.append({
                    'id': 'SMB-SIGNING-001',
                    'severity': 'Medium',
                    'title': 'SMB Signing Not Required',
                    'description': f'SMB signing is {sec_mode.get("message_signing")} - allows man-in-the-middle attacks',
                    'recommendation': 'Enable SMB signing requirement in Group Policy',
                    'source': 'nmap_nse',
                    'detection_method': 'smb-security-mode'
                })

        # Analyze OS discovery findings
        if 'os_discovery' in script_findings and script_findings['os_discovery'].get('os_detected'):
            os_info = script_findings['os_discovery']
            recommendations.append('Review SMB configuration for information disclosure')

        # Analyze share enumeration
        if 'share_enumeration' in script_findings:
            shares = script_findings['share_enumeration']
            if shares.get('anonymous_access'):
                vulnerabilities.append({
                    'id': 'SMB-ANON-001',
                    'severity': 'Medium',
                    'title': 'Anonymous SMB Access Enabled',
                    'description': 'Anonymous access to SMB shares is enabled',
                    'recommendation': 'Disable anonymous access to SMB shares',
                    'source': 'nmap_nse',
                    'detection_method': 'smb-enum-shares'
                })

        if aggressive:
            # Process vulnerability script results
            if 'vulnerability_findings' in script_findings:
                for script_name, result in script_findings['vulnerability_findings'].items():
                    if 'vulnerable' in result.lower() or 'risk' in result.lower():
                        severity = 'Critical' if 'ms17-010' in script_name else 'High'
                        vulnerabilities.append({
                            'id': f'SMB-VULN-{script_name.upper().replace("-", "_")}',
                            'severity': severity,
                            'title': f'SMB Vulnerability: {script_name}',
                            'description': result[:200] + '...' if len(result) > 200 else result,
                            'recommendation': 'Apply security patches immediately',
                            'source': 'nmap_nse_aggressive',
                            'detection_method': script_name
                        })

            # Process brute force results
            if 'brute_force_results' in script_findings:
                brute_results = script_findings['brute_force_results']
                if brute_results.get('success'):
                    vulnerabilities.append({
                        'id': 'SMB-BRUTE-001',
                        'severity': 'Critical',
                        'title': 'Weak SMB Credentials Found',
                        'description': 'Brute force attack succeeded - weak credentials detected',
                        'recommendation': 'Change passwords immediately and implement account lockout policies',
                        'source': 'nmap_nse_aggressive',
                        'detection_method': 'smb-brute'
                    })

        # Standard recommendations
        recommendations.extend([
            'Implement SMB signing to prevent man-in-the-middle attacks',
            'Disable SMBv1 protocol if not required for legacy systems',
            'Use strong authentication mechanisms for SMB access',
            'Implement proper network segmentation for SMB services',
            'Regular monitoring of SMB access logs for suspicious activity'
        ])

        return {
            'vulnerabilities': vulnerabilities,
            'recommendations': list(set(recommendations))
        }

    def _format_for_user_display(self, nmap_output: str) -> str:
        """Format nmap output for clear user display with enhanced SMB parsing"""
        lines = nmap_output.split('\n')
        important_lines = []

        # Track if we're in a script output section
        in_script_section = False
        current_script = None

        for line in lines:
            original_line = line
            line_lower = line.lower()

            # Always include these key lines
            if any(keyword in line_lower for keyword in [
                'port', 'state', 'service', 'version',
                'computer name', 'domain name', 'workgroup', 'fqdn',
                'message signing', 'authentication', 'sharename',
                'vulnerable', 'ms17-010', 'eternalblue',
                'valid credentials', 'brute force', 'login successful'
            ]):
                important_lines.append(original_line)

            # Include script headers and results
            elif line.strip().startswith('|') and ('smb-' in line_lower):
                important_lines.append(original_line)
                if ':' in line:
                    current_script = line.split(':')[0].replace('|_', '').replace('| ', '').strip()
                in_script_section = True

            # Include script continuation lines
            elif in_script_section and line.strip().startswith('|'):
                important_lines.append(original_line)

            # End of script section
            elif in_script_section and not line.strip().startswith('|'):
                in_script_section = False
                current_script = None

            # Include error or warning lines
            elif any(keyword in line_lower for keyword in ['error', 'warning', 'failed', 'timeout']):
                important_lines.append(original_line)

        # If we didn't capture much, include more of the original output
        if len(important_lines) < 5:
            return nmap_output

        return '\n'.join(important_lines)

    def _extract_server_type(self, line: str) -> str:
        """Extract SMB server type from nmap output"""
        line_lower = line.lower()
        if 'samba' in line_lower:
            return 'Samba'
        elif 'windows' in line_lower or 'microsoft' in line_lower:
            return 'Windows SMB'
        elif 'netbios' in line_lower:
            return 'NetBIOS/SMB'
        else:
            return 'Unknown SMB Server'

    def _extract_version(self, line: str) -> str:
        """Extract version from nmap output"""
        version_match = re.search(r'(\d+\.[\d\.]+)', line)
        return version_match.group(1) if version_match else ''