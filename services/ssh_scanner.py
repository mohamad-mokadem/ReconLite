import json
import socket
import time
import subprocess
import re
import sys
from datetime import datetime
from typing import Dict, Any, List
from .base_scanner import BaseScanner


class SSHScanner(BaseScanner):
    """Advanced SSH Scanner with WSL ssh-audit + nmap integration - FIXED VERSION"""

    def __init__(self, timeout: int = 10):
        super().__init__(timeout)
        self.ssh_audit_available = self._check_ssh_audit_availability()
        self.nmap_available = self._check_nmap_availability()
        self.ssh_audit_command = None

    def get_supported_ports(self) -> List[int]:
        return [22, 2222, 22000, 2200]  # SSH and common alternatives

    def get_service_name(self) -> str:
        return "SSH"

    def _check_ssh_audit_availability(self) -> bool:
        """Check if ssh_audit tool is available - Enhanced for WSL"""
        try:
            # Method 1: Try WSL ssh-audit first
            wsl_result = subprocess.run(['wsl', 'ssh-audit', '--help'],
                                        capture_output=True, text=True, timeout=5)
            if wsl_result.returncode == 0:
                print("✅ ssh-audit available via Kali WSL")
                self.ssh_audit_command = ['wsl', 'ssh-audit']
                return True

            # Method 2: Try Python module
            result = subprocess.run([sys.executable, '-m', 'ssh_audit', '--help'],
                                    capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print("✅ ssh-audit available as Python module")
                self.ssh_audit_command = [sys.executable, '-m', 'ssh_audit']
                return True

            # Method 3: Try direct command
            result = subprocess.run(['ssh-audit', '--help'],
                                    capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print("✅ ssh-audit available as direct command")
                self.ssh_audit_command = ['ssh-audit']
                return True

            print("⚠️ ssh-audit not available - install with: pip install ssh-audit")
            return False

        except Exception as e:
            print(f"⚠️ Error checking ssh-audit availability: {e}")
            return False

    def _check_nmap_availability(self) -> bool:
        """Check if nmap is available for aggressive scripts"""
        try:
            result = subprocess.run(['nmap', '--version'],
                                    capture_output=True, text=True, timeout=5)
            available = result.returncode == 0
            if available:
                print("✅ nmap available for SSH aggressive scanning")
            else:
                print("⚠️ nmap not available for SSH aggressive scripts")
            return available
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print("⚠️ nmap not found in PATH for SSH aggressive scanning")
            return False
        except Exception as e:
            print(f"⚠️ Error checking nmap availability: {e}")
            return False

    def scan(self, ip: str, port: int, **kwargs) -> Dict[str, Any]:
        """Standard SSH scanning with WSL ssh-audit integration - FIXED VERSION"""
        self.scan_start_time = time.time()
        results = self.create_base_result(ip, port)

        try:
            print(f"🔍 SSH Debug - Starting scan for {ip}:{port}")

            # Step 1: Basic connectivity check
            self.mark_step_completed(results, 'connectivity')
            connectivity_info = self.check_port_connectivity(ip, port)
            results['connectivity_info'] = connectivity_info

            if not connectivity_info.get('accessible'):
                return self.create_failed_result(ip, port,
                                                 connectivity_info.get('failure_reason', 'SSH service not accessible'),
                                                 connectivity_info)

            # Step 2: Run WSL ssh-audit scan
            self.mark_step_completed(results, 'ssh_audit_scan')
            ssh_audit_results = self._run_ssh_audit_scan(ip, port)
            results['ssh_audit_data'] = ssh_audit_results

            print(f"🔍 SSH Debug - ssh_audit_data keys: {list(ssh_audit_results.keys())}")
            print(f"🔍 SSH Debug - ssh_audit_data has error: {ssh_audit_results.get('error')}")

            # Extract service info from ssh-audit
            service_info = ssh_audit_results.get('service_info', {})
            self.update_service_info(results, service_info)
            results['banner'] = ssh_audit_results.get('banner', '')

            print(f"🔍 SSH Debug - Service info updated: {results['service_info']}")
            print(f"🔍 SSH Debug - Banner: {results['banner']}")

            # Step 3: Complementary enumeration
            self.mark_step_completed(results, 'enumeration')
            enum_info = self._complementary_ssh_analysis(ip, port)
            results['advanced_findings'].update(enum_info)

            # Step 4: Security assessment
            self.mark_step_completed(results, 'vulnerability')
            security_info = self._security_assessment_ssh_audit(results['service_info'], enum_info,
                                                                results['ssh_audit_data'])
            results['vulnerabilities'] = security_info.get('vulnerabilities', [])
            results['recommendations'] = security_info.get('recommendations', [])

            print(f"🔍 SSH Debug - Final vulnerabilities count: {len(results['vulnerabilities'])}")
            print(f"🔍 SSH Debug - Final recommendations count: {len(results['recommendations'])}")

            return self.finalize_results(results, success=True)

        except Exception as e:
            print(f"❌ SSH Debug - Scan error: {str(e)}")
            results['error'] = str(e)
            return self.finalize_results(results, success=False)

    def _run_ssh_audit_scan(self, ip: str, port: int) -> Dict[str, Any]:
        """Run ssh-audit with WSL integration - FIXED VERSION"""
        print(f"🔍 SSH Debug - Starting ssh-audit scan for {ip}:{port}")

        # First, try WSL ssh-audit
        wsl_result = self._try_wsl_ssh_audit(ip, port)
        if not wsl_result.get('error'):
            print(f"✅ Using Kali WSL for ssh-audit scan")
            return wsl_result

        # Fallback to original logic if WSL fails
        print(f"⚠️ WSL failed, falling back to local ssh-audit: {wsl_result.get('error')}")
        return self._original_ssh_audit_scan(ip, port)

    def _try_wsl_ssh_audit(self, ip: str, port: int) -> Dict[str, Any]:
        """Try ssh-audit through Kali WSL - FIXED VERSION"""
        try:

            cmd = ['wsl', 'ssh-audit', '--json', f'{ip}:{port}']
            timeout = 30

            print(f"🐧 Kali WSL SSH-Audit scan: {' '.join(cmd[1:])}")

            # Execute through WSL
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

            print(f"WSL return code: {result.returncode}")
            print(f"WSL stdout length: {len(result.stdout) if result.stdout else 0}")
            if result.stderr:
                print(f"WSL stderr: {result.stderr}")

            # If JSON command fails, try without JSON
            if result.returncode != 0 or not result.stdout:
                print("🔄 Trying WSL ssh-audit without --json flag")
                cmd_no_json = ['wsl', 'ssh-audit', f'{ip}:{port}']
                result = subprocess.run(cmd_no_json, capture_output=True, text=True, timeout=timeout)

                if result.returncode != 0 and not result.stdout:
                    return {'error': f'WSL ssh-audit failed: {result.stderr}'}

            if not result.stdout:
                return {'error': 'WSL ssh-audit returned no output'}

            # Parse ssh-audit output with enhanced parsing
            parsed = self._parse_ssh_audit_output_enhanced(result.stdout)
            parsed['scan_type'] = 'professional_assessment'
            parsed['command_used'] = ' '.join(cmd[1:])  # Show command without 'wsl'
            parsed['tool_used'] = 'ssh_audit_via_kali_wsl'

            return parsed

        except FileNotFoundError:
            return {'error': 'WSL not found on this system'}
        except subprocess.TimeoutExpired:
            return {'error': 'WSL ssh-audit timed out'}
        except Exception as e:
            return {'error': f'WSL ssh-audit failed: {str(e)}'}

    def _original_ssh_audit_scan(self, ip: str, port: int) -> Dict[str, Any]:
        """Original ssh-audit logic - fallback"""
        if not self.ssh_audit_available:
            return self._fallback_ssh_scan(ip, port)

        try:
            # Try JSON output first
            cmd = self.ssh_audit_command + ['--json', '--timeout', '10', f'{ip}:{port}']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            # If JSON fails, try without JSON
            if result.returncode != 0 or not result.stdout:
                print("🔄 Trying local ssh-audit without --json flag")
                cmd_no_json = self.ssh_audit_command + ['--timeout', '10', f'{ip}:{port}']
                result = subprocess.run(cmd_no_json, capture_output=True, text=True, timeout=30)

            if result.returncode != 0 and not result.stdout:
                return {'error': f'ssh-audit scan failed: {result.stderr}'}

            parsed = self._parse_ssh_audit_output_enhanced(result.stdout)
            parsed['command_used'] = ' '.join(cmd)
            parsed['tool_used'] = 'ssh_audit_local'

            return parsed

        except Exception as e:
            return {'error': f'ssh-audit execution failed: {str(e)}'}

    def _parse_ssh_audit_output_enhanced(self, output: str) -> Dict[str, Any]:
        """Enhanced parsing for ssh-audit output - COMPLETELY REWRITTEN"""
        print(f"🔍 SSH Debug - Parsing ssh-audit output ({len(output)} chars)")

        parsed = {
            'service_info': {},
            'banner': '',
            'algorithms': {
                'kex': [],
                'host_key': [],
                'encryption': [],
                'mac': []
            },
            'vulnerabilities': [],
            'recommendations': [],
            'security_score': 100,
            'raw_output': output,
            'formatted_for_display': '',
            'scripts': {}
        }

        try:
            # First, try to parse as JSON
            if output.strip().startswith('{'):
                print("🔍 SSH Debug - Attempting JSON parsing")
                json_data = json.loads(output)
                return self._parse_ssh_audit_json_enhanced(json_data)
            else:
                print("🔍 SSH Debug - Attempting text parsing")
                return self._parse_ssh_audit_text_enhanced(output)

        except json.JSONDecodeError as e:
            print(f"🔍 SSH Debug - JSON parsing failed: {e}")
            return self._parse_ssh_audit_text_enhanced(output)
        except Exception as e:
            print(f"❌ SSH Debug - Parsing failed completely: {e}")
            # Return minimal working data
            parsed['error'] = f'Parsing error: {str(e)}'
            parsed['formatted_for_display'] = self._create_fallback_display(output)
            return parsed

    def _parse_ssh_audit_json_enhanced(self, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced JSON parsing for ssh-audit"""
        print("🔍 SSH Debug - Parsing JSON data")

        parsed = {
            'service_info': {},
            'banner': '',
            'algorithms': {
                'kex': [],
                'host_key': [],
                'encryption': [],
                'mac': []
            },
            'vulnerabilities': [],
            'recommendations': [],
            'security_score': 100,
            'raw_output': json.dumps(json_data, indent=2),
            'formatted_for_display': '',
            'scripts': {}
        }

        # Extract banner info
        if 'banner' in json_data:
            banner_info = json_data['banner']
            parsed['banner'] = banner_info.get('raw', '')
            parsed['service_info']['software'] = banner_info.get('software', '')
            parsed['service_info']['server_type'] = self._extract_ssh_server_type(banner_info.get('software', ''))
            parsed['service_info']['protocol_version'] = banner_info.get('protocol', '')

        # Extract algorithm information
        if 'algorithms' in json_data:
            algs = json_data['algorithms']

            # Map algorithm types
            alg_mapping = {
                'kex': 'kex',
                'key': 'host_key',
                'enc': 'encryption',
                'mac': 'mac'
            }

            for json_key, parsed_key in alg_mapping.items():
                if json_key in algs and isinstance(algs[json_key], list):
                    for alg_name in algs[json_key]:
                        parsed['algorithms'][parsed_key].append({
                            'algorithm': alg_name,
                            'status': 'info',  # Default, will be updated by recommendations
                            'description': f'{alg_name} algorithm'
                        })

            # Process recommendations to mark bad algorithms
            if 'recommendations' in algs:
                recs = algs['recommendations']

                # Mark algorithms that should be removed as failed
                for severity in ['critical', 'warning']:
                    if severity in recs and 'del' in recs[severity]:
                        for bad_alg in recs[severity]['del']:
                            self._mark_algorithm_as_bad(parsed, bad_alg, severity)

                # Add to recommendations list
                if 'critical' in recs:
                    if 'del' in recs['critical']:
                        for alg in recs['critical']['del']:
                            parsed['recommendations'].append(f"Remove critical algorithm: {alg}")
                    if 'add' in recs['critical']:
                        for alg in recs['critical']['add']:
                            parsed['recommendations'].append(f"Add recommended algorithm: {alg}")

                if 'warning' in recs:
                    if 'del' in recs['warning']:
                        for alg in recs['warning']['del']:
                            parsed['recommendations'].append(f"Consider removing: {alg}")

        # Calculate security score
        parsed['security_score'] = self._calculate_ssh_security_score_enhanced(parsed)

        # Create formatted display
        parsed['formatted_for_display'] = self._format_json_for_display_enhanced(json_data)

        # Add summary to scripts for UI
        total_algs = sum(len(algs) for algs in parsed['algorithms'].values())
        parsed['scripts'][
            'ssh-audit-summary'] = f"Professional SSH security assessment completed - {total_algs} algorithms analyzed"

        print(
            f"🔍 SSH Debug - JSON parsing complete: {len(parsed['vulnerabilities'])} vulnerabilities, score: {parsed['security_score']}")
        return parsed

    def _parse_ssh_audit_text_enhanced(self, output: str) -> Dict[str, Any]:
        """Enhanced text parsing for ssh-audit - COMPLETELY REWRITTEN"""
        print("🔍 SSH Debug - Starting enhanced text parsing")

        parsed = {
            'service_info': {},
            'banner': '',
            'algorithms': {
                'kex': [],
                'host_key': [],
                'encryption': [],
                'mac': []
            },
            'vulnerabilities': [],
            'recommendations': [],
            'security_score': 100,
            'raw_output': output,
            'formatted_for_display': '',
            'scripts': {}
        }

        lines = output.split('\n')
        current_section = None
        algorithm_count = 0

        for line_num, line in enumerate(lines):
            original_line = line
            line = line.strip()

            # Remove ANSI color codes
            line = re.sub(r'\x1b\[[0-9;]*m', '', line)

            if not line:
                continue

            print(f"🔍 SSH Debug - Line {line_num}: {line[:80]}...")

            # Extract general information
            if line.startswith('(gen) banner:'):
                parsed['banner'] = line.split(':', 1)[1].strip()
                parsed['service_info']['banner'] = parsed['banner']
                print(f"✅ Found banner: {parsed['banner']}")

            elif line.startswith('(gen) software:'):
                software = line.split(':', 1)[1].strip()
                parsed['service_info']['software'] = software
                parsed['service_info']['server_type'] = self._extract_ssh_server_type(software)
                parsed['service_info']['version'] = self._extract_ssh_version(software)
                print(f"✅ Found software: {software}")

            elif line.startswith('(gen) compatibility:'):
                parsed['service_info']['compatibility'] = line.split(':', 1)[1].strip()

            elif line.startswith('(gen) compression:'):
                parsed['service_info']['compression'] = line.split(':', 1)[1].strip()

            # Detect algorithm sections - IMPROVED DETECTION
            elif any(keyword in line.lower() for keyword in ['key exchange algorithms', 'kex algorithms']):
                current_section = 'kex'
                print(f"🔍 SSH Debug - Entering KEX section")

            elif any(keyword in line.lower() for keyword in ['host-key algorithms', 'host key algorithms']):
                current_section = 'host_key'
                print(f"🔍 SSH Debug - Entering host key section")

            elif any(keyword in line.lower() for keyword in ['encryption algorithms', 'ciphers']):
                current_section = 'encryption'
                print(f"🔍 SSH Debug - Entering encryption section")

            elif any(keyword in line.lower() for keyword in ['message authentication', 'mac algorithms']):
                current_section = 'mac'
                print(f"🔍 SSH Debug - Entering MAC section")

            elif 'algorithm recommendations' in line.lower():
                current_section = 'recommendations'
                print(f"🔍 SSH Debug - Entering recommendations section")

            elif line.startswith('# ') or line.startswith('##'):
                current_section = None
                print(f"🔍 SSH Debug - Section ended")

            # Parse algorithm entries
            elif current_section and line.startswith('(') and current_section != 'recommendations':
                alg_info = self._parse_algorithm_line_enhanced(line, current_section)
                if alg_info:
                    parsed['algorithms'][current_section].append(alg_info)
                    algorithm_count += 1
                    print(f"✅ Added {current_section} algorithm: {alg_info['algorithm']} ({alg_info['status']})")

                    # Create vulnerability for failed algorithms
                    if alg_info['status'] in ['fail', 'warn']:
                        vuln = self._create_vulnerability_from_algorithm(alg_info, current_section)
                        parsed['vulnerabilities'].append(vuln)
                        print(f"🚨 Created vulnerability: {vuln['id']}")

            # Parse recommendations
            elif current_section == 'recommendations' and line.startswith('(rec)'):
                rec_text = line.replace('(rec)', '').strip()
                if rec_text:
                    parsed['recommendations'].append(rec_text)
                    print(f"✅ Added recommendation: {rec_text[:50]}...")

        # Calculate security score
        parsed['security_score'] = self._calculate_ssh_security_score_enhanced(parsed)

        # Create formatted display
        parsed['formatted_for_display'] = self._create_formatted_display_enhanced(parsed, output)

        # Add to scripts field for UI
        parsed['scripts'][
            'ssh-audit-summary'] = f"SSH security analysis completed - {algorithm_count} algorithms analyzed"
        if parsed['vulnerabilities']:
            parsed['scripts']['ssh-audit-vulnerabilities'] = f"{len(parsed['vulnerabilities'])} security issues found"

        print(f"🔍 SSH Debug - Text parsing complete:")
        print(f"   Total algorithms: {algorithm_count}")
        print(f"   Vulnerabilities: {len(parsed['vulnerabilities'])}")
        print(f"   Recommendations: {len(parsed['recommendations'])}")
        print(f"   Security score: {parsed['security_score']}")

        return parsed

    def _parse_algorithm_line_enhanced(self, line: str, section: str) -> Dict[str, Any]:
        """Enhanced algorithm line parsing"""
        try:
            print(f"🔍 SSH Debug - Parsing algorithm line: {line}")

            # Pattern: (type) algorithm-name -- [status] description
            # Extract parts after the closing parenthesis
            if ') ' not in line:
                return None

            parts = line.split(') ', 1)
            if len(parts) != 2:
                return None

            remaining = parts[1]

            # Split on ' -- ' to separate algorithm from status/description
            if ' -- ' in remaining:
                alg_name = remaining.split(' -- ')[0].strip()
                status_part = remaining.split(' -- ', 1)[1]

                # Extract status from [brackets]
                status = 'info'  # default
                description = status_part

                if '[fail]' in status_part:
                    status = 'fail'
                    description = status_part.replace('[fail]', '').strip()
                elif '[warn]' in status_part:
                    status = 'warn'
                    description = status_part.replace('[warn]', '').strip()
                elif '[info]' in status_part:
                    status = 'info'
                    description = status_part.replace('[info]', '').strip()

            else:
                # No status info, just algorithm name
                alg_name = remaining.strip()
                status = 'info'
                description = 'No description available'

            result = {
                'algorithm': alg_name,
                'status': status,
                'description': description,
                'type': section
            }

            print(f"✅ Parsed algorithm: {alg_name} -> {status}")
            return result

        except Exception as e:
            print(f"❌ Failed to parse algorithm line: {e}")
            return None

    def _mark_algorithm_as_bad(self, parsed: Dict[str, Any], bad_alg: str, severity: str):
        """Mark an algorithm as failed/warning based on recommendations"""
        status = 'fail' if severity == 'critical' else 'warn'

        # Find and update the algorithm in all categories
        for alg_type, algorithms in parsed['algorithms'].items():
            for alg in algorithms:
                if alg['algorithm'] == bad_alg:
                    alg['status'] = status
                    alg['description'] = f"Recommended for removal ({severity})"
                    # Create vulnerability
                    vuln = self._create_vulnerability_from_algorithm(alg, alg_type)
                    parsed['vulnerabilities'].append(vuln)
                    print(f"🚨 Marked {bad_alg} as {status}")
                    return

    def _create_vulnerability_from_algorithm(self, alg_info: Dict[str, Any], alg_type: str) -> Dict[str, Any]:
        """Create vulnerability from algorithm info"""
        severity_map = {
            'fail': 'High',
            'warn': 'Medium',
            'info': 'Low'
        }

        alg_name = alg_info.get('algorithm', 'Unknown')
        status = alg_info.get('status', 'info')
        description = alg_info.get('description', '')

        return {
            'id': f'SSH-{alg_type.upper()}-{alg_name.upper().replace("-", "_").replace(".", "_")}',
            'severity': severity_map.get(status, 'Medium'),
            'title': f'Weak SSH {alg_type.replace("_", " ").title()}: {alg_name}',
            'description': f'SSH-audit detected: {description}' if description else f'Weak {alg_type} algorithm detected',
            'recommendation': f'Disable {alg_name} and use stronger alternatives',
            'source': 'ssh_audit',
            'detection_method': 'algorithm_analysis',
            'algorithm_type': alg_type,
            'algorithm_name': alg_name
        }

    def _calculate_ssh_security_score_enhanced(self, parsed_data: Dict[str, Any]) -> int:
        """Enhanced security score calculation"""
        score = 100

        # Count algorithm issues
        fail_count = 0
        warn_count = 0
        total_count = 0

        for alg_type, algorithms in parsed_data.get('algorithms', {}).items():
            for alg in algorithms:
                total_count += 1
                status = alg.get('status', 'info')
                if status == 'fail':
                    fail_count += 1
                    score -= 15
                elif status == 'warn':
                    warn_count += 1
                    score -= 8

        # Deduct for vulnerabilities
        for vuln in parsed_data.get('vulnerabilities', []):
            severity = vuln.get('severity', '').lower()
            if severity == 'critical':
                score -= 25
            elif severity == 'high':
                score -= 15
            elif severity == 'medium':
                score -= 10

        return max(score, 0)

    def _create_formatted_display_enhanced(self, parsed_data: Dict[str, Any], raw_output: str) -> str:
        """Create enhanced formatted display"""
        lines = []

        lines.append("🔐 SSH Security Assessment Results")
        lines.append("=" * 50)
        lines.append("")

        # Server information
        service_info = parsed_data.get('service_info', {})
        if service_info.get('software'):
            lines.append(f"SSH Server: {service_info['software']}")
        if service_info.get('banner'):
            lines.append(f"Banner: {service_info['banner']}")
        if service_info.get('compatibility'):
            lines.append(f"Compatibility: {service_info['compatibility']}")
        lines.append("")

        # Algorithm summary
        algorithms = parsed_data.get('algorithms', {})
        if any(algorithms.values()):
            lines.append("Algorithm Summary:")
            lines.append("-" * 20)

            for alg_type, alg_list in algorithms.items():
                if alg_list:
                    title = alg_type.replace('_', ' ').title()
                    lines.append(f"{title}: {len(alg_list)} algorithms")

                    # Show problematic algorithms
                    for alg in alg_list:
                        if alg.get('status') in ['fail', 'warn']:
                            icon = '❌' if alg['status'] == 'fail' else '⚠️'
                            lines.append(f"  {icon} {alg['algorithm']} ({alg['status'].upper()})")
            lines.append("")

        # Security summary
        vulnerabilities = parsed_data.get('vulnerabilities', [])
        if vulnerabilities:
            lines.append(f"🚨 Security Issues Found: {len(vulnerabilities)}")
            for vuln in vulnerabilities[:5]:  # Show first 5
                lines.append(f"  • {vuln.get('title', 'Security issue')}")
            if len(vulnerabilities) > 5:
                lines.append(f"  ... and {len(vulnerabilities) - 5} more issues")
            lines.append("")

        # Recommendations
        recommendations = parsed_data.get('recommendations', [])
        if recommendations:
            lines.append("💡 Recommendations:")
            lines.append("-" * 20)
            for rec in recommendations[:5]:  # Show first 5
                lines.append(f"  • {rec}")
            if len(recommendations) > 5:
                lines.append(f"  ... and {len(recommendations) - 5} more recommendations")
            lines.append("")

        # Security score
        score = parsed_data.get('security_score', 0)
        if score >= 90:
            level = "🟢 EXCELLENT"
        elif score >= 80:
            level = "🟡 GOOD"
        elif score >= 60:
            level = "🟠 FAIR"
        else:
            level = "🔴 POOR"

        lines.append(f"Security Level: {level} (Score: {score}/100)")

        return '\n'.join(lines)

    def _format_json_for_display_enhanced(self, json_data: Dict[str, Any]) -> str:
        """Enhanced JSON formatting for display"""
        lines = []

        lines.append("🔐 SSH Security Assessment Results")
        lines.append("=" * 50)
        lines.append("")

        # Banner information
        if 'banner' in json_data:
            banner = json_data['banner']
            lines.append(f"SSH Server: {banner.get('software', 'Unknown')}")
            lines.append(f"Protocol: {banner.get('protocol', 'Unknown')}")
            lines.append(f"Banner: {banner.get('raw', 'Unknown')}")
            lines.append("")

        # Algorithm summary
        if 'algorithms' in json_data:
            algs = json_data['algorithms']
            lines.append("Algorithm Summary:")
            lines.append("-" * 20)

            alg_types = {
                'kex': '🔑 Key Exchange',
                'key': '🏠 Host Key',
                'enc': '🔒 Encryption',
                'mac': '✅ MAC'
            }

            for alg_type, title in alg_types.items():
                if alg_type in algs and algs[alg_type]:
                    lines.append(f"{title}: {len(algs[alg_type])} algorithms")
            lines.append("")

        # Recommendations
        if 'algorithms' in json_data and 'recommendations' in json_data['algorithms']:
            recs = json_data['algorithms']['recommendations']
            lines.append("⚠️ Security Recommendations:")
            lines.append("-" * 30)

            if 'critical' in recs and 'del' in recs['critical']:
                lines.append("🚨 CRITICAL - Remove these algorithms:")
                for alg in recs['critical']['del'][:5]:
                    lines.append(f"  • {alg}")
                lines.append("")

            if 'warning' in recs and 'del' in recs['warning']:
                lines.append("⚠️ WARNING - Consider removing:")
                for alg in recs['warning']['del'][:5]:
                    lines.append(f"  • {alg}")
                lines.append("")

        lines.append("✅ SSH security audit completed")
        return '\n'.join(lines)

    def _create_fallback_display(self, output: str) -> str:
        """Create fallback display when parsing fails"""
        lines = []
        lines.append("🔐 SSH Security Assessment")
        lines.append("=" * 30)
        lines.append("")
        lines.append("⚠️ Advanced parsing encountered issues")
        lines.append("Raw ssh-audit output:")
        lines.append("-" * 20)

        # Show first 20 lines of output
        output_lines = output.split('\n')[:20]
        for line in output_lines:
            clean_line = re.sub(r'\x1b\[[0-9;]*m', '', line.strip())
            if clean_line:
                lines.append(clean_line)

        if len(output.split('\n')) > 20:
            lines.append("... (output truncated)")

        return '\n'.join(lines)

    def _extract_ssh_server_type(self, text: str) -> str:
        """Extract SSH server type from text"""
        text_lower = text.lower()
        if 'openssh' in text_lower:
            return 'OpenSSH'
        elif 'libssh' in text_lower:
            return 'libssh'
        elif 'dropbear' in text_lower:
            return 'Dropbear SSH'
        elif 'paramiko' in text_lower:
            return 'Paramiko'
        elif 'putty' in text_lower:
            return 'PuTTY'
        elif 'bitvise' in text_lower:
            return 'Bitvise SSH'
        elif 'tectia' in text_lower:
            return 'Tectia SSH'
        return 'Unknown SSH Server'

    def _extract_ssh_version(self, text: str) -> str:
        """Extract SSH version from text"""
        version_match = re.search(r'(\d+\.[\d\.]+)', text)
        return version_match.group(1) if version_match else ''

    def _fallback_ssh_scan(self, ip: str, port: int) -> Dict[str, Any]:
        """Fallback SSH scanning when ssh_audit is not available"""
        print("🔍 SSH Debug - Using fallback SSH scan")

        fallback_data = {
            'service_info': {},
            'banner': '',
            'security_score': 50,
            'tool_used': 'fallback',
            'error': 'ssh-audit not available - using basic SSH detection',
            'formatted_for_display': '',
            'scripts': {},
            'algorithms': {'kex': [], 'host_key': [], 'encryption': [], 'mac': []},
            'vulnerabilities': [],
            'recommendations': []
        }

        try:
            # Basic SSH banner grabbing
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()

            if banner.startswith('SSH-'):
                fallback_data['banner'] = banner
                fallback_data['service_info']['ssh_version'] = banner.split()[0] if ' ' in banner else banner
                fallback_data['service_info']['software'] = banner
                fallback_data['service_info']['server_type'] = self._extract_ssh_server_type(banner)
                fallback_data['security_score'] = 50

                # Create basic formatted display
                fallback_data['formatted_for_display'] = f"""🔐 Basic SSH Detection Results
===================================

SSH Banner: {banner}
Server Type: {fallback_data['service_info']['server_type']}

⚠️ Limited Analysis Available
ssh-audit tool not found - install for detailed security assessment
pip install ssh-audit

Basic SSH service detected and accessible."""

                fallback_data['scripts']['basic-ssh-detection'] = "SSH service detected and accessible"

        except Exception as e:
            fallback_data['error'] = f'Fallback SSH scan failed: {str(e)}'
            fallback_data['formatted_for_display'] = f"""🔐 SSH Scan Failed
==================

Error: {str(e)}

Please verify:
- Target is accessible
- SSH service is running on port {port}
- Network connectivity is available"""

        return fallback_data

    def _complementary_ssh_analysis(self, ip: str, port: int) -> Dict[str, Any]:
        """Basic SSH analysis that complements ssh_audit"""
        analysis_info = {
            'connection_analysis': {},
            'protocol_analysis': {}
        }

        try:
            # Basic connection analysis
            analysis_info['connection_analysis'] = self._analyze_ssh_connection(ip, port)

            # Protocol behavior analysis
            analysis_info['protocol_analysis'] = self._analyze_ssh_protocol(ip, port)

        except Exception as e:
            analysis_info['error'] = str(e)

        return analysis_info

    def _analyze_ssh_connection(self, ip: str, port: int) -> Dict[str, Any]:
        """Analyze SSH connection characteristics"""
        connection_info = {
            'response_times': [],
            'connection_stability': True
        }

        try:
            for i in range(3):
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)

                try:
                    sock.connect((ip, port))
                    response_time = (time.time() - start_time) * 1000
                    connection_info['response_times'].append(response_time)
                    sock.close()
                except Exception:
                    connection_info['connection_stability'] = False

                time.sleep(0.5)

            if connection_info['response_times']:
                avg_time = sum(connection_info['response_times']) / len(connection_info['response_times'])
                connection_info['average_response_time'] = round(avg_time, 2)

        except Exception as e:
            connection_info['error'] = str(e)

        return connection_info

    def _analyze_ssh_protocol(self, ip: str, port: int) -> Dict[str, Any]:
        """Analyze SSH protocol behavior"""
        protocol_info = {
            'banner_variations': [],
            'protocol_compliance': True
        }

        try:
            for i in range(2):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((ip, port))

                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner and banner not in protocol_info['banner_variations']:
                    protocol_info['banner_variations'].append(banner)

                sock.close()
                time.sleep(1)

            if len(protocol_info['banner_variations']) > 1:
                protocol_info['protocol_compliance'] = False

        except Exception as e:
            protocol_info['error'] = str(e)

        return protocol_info

    def _security_assessment_ssh_audit(self, service_info: Dict[str, Any], enum_info: Dict[str, Any],
                                       ssh_audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Security assessment based on ssh_audit results"""
        vulnerabilities = []
        recommendations = []

        # Get vulnerabilities from ssh-audit data
        vulnerabilities = ssh_audit_data.get('vulnerabilities', [])

        # Add findings from basic enumeration
        self._process_basic_ssh_findings(enum_info, vulnerabilities)

        # Add version-specific vulnerabilities
        self._check_ssh_version_vulnerabilities(service_info, vulnerabilities)

        # Generate recommendations
        recommendations = self._generate_ssh_audit_recommendations(vulnerabilities, service_info, ssh_audit_data)

        return {
            'vulnerabilities': vulnerabilities,
            'recommendations': recommendations
        }

    def _process_basic_ssh_findings(self, enum_info: Dict[str, Any], vulnerabilities: List[Dict]):
        """Process basic SSH enumeration findings"""
        connection_analysis = enum_info.get('connection_analysis', {})
        if not connection_analysis.get('connection_stability', True):
            vulnerabilities.append({
                'id': 'SSH-STABILITY',
                'severity': 'Low',
                'title': 'SSH Connection Instability',
                'description': 'SSH service shows connection stability issues',
                'recommendation': 'Investigate SSH server configuration and system resources',
                'source': 'manual_verification',
                'detection_method': 'connection_test'
            })

        protocol_analysis = enum_info.get('protocol_analysis', {})
        if not protocol_analysis.get('protocol_compliance', True):
            vulnerabilities.append({
                'id': 'SSH-PROTOCOL',
                'severity': 'Medium',
                'title': 'SSH Protocol Inconsistency',
                'description': 'SSH server shows inconsistent protocol behavior',
                'recommendation': 'Review SSH server configuration for consistency',
                'source': 'manual_verification',
                'detection_method': 'protocol_analysis'
            })

    def _check_ssh_version_vulnerabilities(self, service_info: Dict[str, Any], vulnerabilities: List[Dict]):
        """Check for known SSH version vulnerabilities"""
        software = service_info.get('software', '').lower()

        if 'openssh' in software:
            if any(version in software for version in ['7.4', '7.5', '7.6']):
                vulnerabilities.append({
                    'id': 'SSH-CVE-2018-15473',
                    'severity': 'Medium',
                    'title': 'OpenSSH Username Enumeration Vulnerability',
                    'description': 'This OpenSSH version is vulnerable to username enumeration (CVE-2018-15473)',
                    'recommendation': 'Update OpenSSH to version 7.7 or later',
                    'source': 'version_analysis',
                    'detection_method': 'version_banner'
                })

            if any(version in software for version in ['6.', '7.0', '7.1', '7.2', '7.3']):
                vulnerabilities.append({
                    'id': 'SSH-CVE-2016-0777',
                    'severity': 'High',
                    'title': 'OpenSSH Client Information Disclosure',
                    'description': 'This OpenSSH version may be vulnerable to information disclosure',
                    'recommendation': 'Update OpenSSH to the latest stable version',
                    'source': 'version_analysis',
                    'detection_method': 'version_banner'
                })

    def _generate_ssh_audit_recommendations(self, vulnerabilities: List[Dict], service_info: Dict[str, Any],
                                            ssh_audit_data: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on ssh_audit assessment"""
        recommendations = []

        # Get recommendations from ssh-audit data
        audit_recs = ssh_audit_data.get('recommendations', [])
        recommendations.extend(audit_recs)

        # Add general SSH security recommendations
        general_recs = [
            'Use SSH key-based authentication instead of passwords',
            'Disable SSH root login (PermitRootLogin no)',
            'Implement fail2ban or similar intrusion prevention',
            'Enable SSH protocol version 2 only',
            'Configure appropriate SSH timeouts and limits'
        ]
        recommendations.extend(general_recs)

        # Algorithm-specific recommendations
        algorithms = ssh_audit_data.get('algorithms', {})
        if algorithms:
            for alg_type, alg_list in algorithms.items():
                for alg in alg_list:
                    if alg.get('status') in ['fail', 'warn']:
                        recommendations.append(f'Disable weak {alg_type} algorithm: {alg.get("algorithm")}')

        # Security score recommendations
        security_score = ssh_audit_data.get('security_score', 100)
        if security_score < 80:
            recommendations.extend([
                'Review SSH configuration with ssh_audit recommendations',
                'Implement SSH hardening guidelines from security frameworks'
            ])

        return list(set(recommendations))  # Remove duplicates

    def scan_aggressive(self, ip: str, port: int, **kwargs) -> Dict[str, Any]:
        """Aggressive SSH scanning with comprehensive nmap scripts"""
        self.scan_start_time = time.time()
        results = self.create_base_result(ip, port)

        try:
            print(f"🔍 SSH Debug - Starting aggressive scan for {ip}:{port}")

            # Step 1: Basic connectivity check
            self.mark_step_completed(results, 'connectivity')
            connectivity_info = self.check_port_connectivity(ip, port)
            results['connectivity_info'] = connectivity_info

            if not connectivity_info.get('accessible'):
                return self.create_failed_result(ip, port,
                                                 connectivity_info.get('failure_reason', 'SSH service not accessible'),
                                                 connectivity_info)

            # Step 2: Run aggressive nmap scan with all SSH scripts
            self.mark_step_completed(results, 'aggressive_nmap_scan')
            nmap_results = self._run_nmap_ssh_scripts(ip, port, aggressive=True)
            results['nmap_data'] = nmap_results
            results['scan_mode'] = 'aggressive'

            # Extract enhanced service info
            service_info = nmap_results.get('service_info', {})
            self.update_service_info(results, service_info)
            results['banner'] = nmap_results.get('banner', '')

            # Step 3: Enhanced enumeration for aggressive mode
            self.mark_step_completed(results, 'aggressive_enumeration')
            enum_info = self._aggressive_ssh_enumeration(ip, port)
            results['advanced_findings'].update(enum_info)

            # Step 4: Enhanced security assessment for aggressive mode
            self.mark_step_completed(results, 'aggressive_vulnerability')
            security_info = self._security_assessment_nmap(results['service_info'], enum_info, results['nmap_data'])
            results['vulnerabilities'] = security_info.get('vulnerabilities', [])
            results['recommendations'] = security_info.get('recommendations', [])

            return self.finalize_results(results, success=True)

        except Exception as e:
            print(f"❌ SSH Debug - Aggressive scan error: {str(e)}")
            results['error'] = str(e)
            return self.finalize_results(results, success=False)

    def _run_nmap_ssh_scripts(self, ip: str, port: int, aggressive: bool = False) -> Dict[str, Any]:
        """Run nmap SSH scripts with WSL integration"""
        # First, try WSL (Kali) - if available
        wsl_result = self._try_wsl_nmap_ssh(ip, port, aggressive)
        if not wsl_result.get('error'):
            print(f"✅ Using Kali WSL for nmap SSH scan")
            return wsl_result

        # Fallback to original Windows logic if WSL fails
        print(f"⚠️ WSL failed, falling back to Windows nmap: {wsl_result.get('error')}")
        return self._original_nmap_ssh_scan(ip, port, aggressive)

    def _try_wsl_nmap_ssh(self, ip: str, port: int, aggressive: bool = False) -> Dict[str, Any]:
        """Try nmap SSH scripts through Kali WSL"""
        try:
            if aggressive:

                cmd = [
                    'wsl', 'nmap', '-sV', '-sC', f'-p{port}',
                    '--script=ssh-*', '--script-timeout=45s', '--host-timeout=300s',
                    '-A', ip
                ]
                timeout = 360
                print(f"🐧 Kali WSL Aggressive SSH scan: {' '.join(cmd[1:])}")
            else:
                # Safe command with basic SSH scripts
                cmd = ['wsl', 'nmap', '-Pn', '-sV', '-sC', f'-p{port}',
                       '--script=ssh2-enum-algos,ssh-hostkey,ssh-auth-methods', ip]
                print(f"🐧 Kali WSL Safe SSH scan: {' '.join(cmd[1:])}")
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

            # Parse nmap output
            parsed = self._parse_nmap_ssh_output(result.stdout)
            parsed['scan_type'] = 'aggressive' if aggressive else 'safe'
            parsed['command_used'] = ' '.join(cmd[1:])  # Show command without 'wsl'
            parsed['tool_used'] = 'nmap_ssh_via_kali_wsl'

            return parsed

        except FileNotFoundError:
            return {'error': 'WSL not found on this system'}
        except subprocess.TimeoutExpired:
            return {'error': 'WSL nmap SSH timed out'}
        except Exception as e:
            return {'error': f'WSL nmap SSH failed: {str(e)}'}

    def _original_nmap_ssh_scan(self, ip: str, port: int, aggressive: bool = False) -> Dict[str, Any]:
        """Original nmap SSH logic - fallback"""
        if not self.nmap_available:
            return {'error': 'Nmap not available for SSH scanning'}

        try:
            if aggressive:
                cmd = ['nmap', '-sV', '-sC', f'-p{port}', '--script=ssh-*', '-A', ip]
            else:
                cmd = ['nmap', '-Pn', '-sV', '-sC', f'-p{port}',
                       '--script=ssh2-enum-algos,ssh-hostkey,ssh-auth-methods', ip]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode != 0:
                return {'error': f'Nmap SSH scan failed: {result.stderr}'}

            parsed = self._parse_nmap_ssh_output(result.stdout)
            parsed['command_used'] = ' '.join(cmd)
            parsed['tool_used'] = 'nmap_ssh_local'

            return parsed

        except Exception as e:
            return {'error': f'Nmap SSH execution failed: {str(e)}'}

    def _parse_nmap_ssh_output(self, nmap_output: str) -> Dict[str, Any]:
        """Parse nmap SSH output"""
        parsed = {
            'service_info': {},
            'banner': '',
            'scripts': {},
            'raw_output': nmap_output,
            'formatted_for_display': self._format_ssh_nmap_for_user_display(nmap_output),
            'vulnerabilities': [],
            'recommendations': []
        }

        lines = nmap_output.split('\n')

        for line in lines:
            line_stripped = line.strip()

            # Parse SSH service line
            if '/tcp' in line and ('ssh' in line.lower() or 'openssh' in line.lower()):
                parsed['service_info']['server_type'] = self._extract_ssh_server_type(line)
                parsed['service_info']['version'] = self._extract_ssh_version(line)
                parsed['banner'] = line_stripped

            # Parse SSH script results
            elif line_stripped.startswith('|_ssh2-enum-algos:'):
                parsed['scripts']['ssh2-enum-algos'] = line_stripped.replace('|_ssh2-enum-algos:', '').strip()
            elif line_stripped.startswith('|_ssh-hostkey:'):
                parsed['scripts']['ssh-hostkey'] = line_stripped.replace('|_ssh-hostkey:', '').strip()
            elif line_stripped.startswith('|_ssh-auth-methods:'):
                parsed['scripts']['ssh-auth-methods'] = line_stripped.replace('|_ssh-auth-methods:', '').strip()
            elif 'SSH-' in line:
                parsed['scripts']['ssh-banner'] = line_stripped

        return parsed

    def _format_ssh_nmap_for_user_display(self, nmap_output: str) -> str:
        """Format SSH nmap output for clear user display"""
        lines = nmap_output.split('\n')
        important_lines = []

        for line in lines:
            if any(keyword in line for keyword in [
                'PORT', 'STATE', 'SERVICE', 'VERSION',
                'ssh2-enum-algos', 'ssh-hostkey', 'ssh-auth-methods',
                'OpenSSH', 'SSH-'
            ]):
                important_lines.append(line)

        return '\n'.join(important_lines) if important_lines else nmap_output

    def _aggressive_ssh_enumeration(self, ip: str, port: int) -> Dict[str, Any]:
        """Aggressive SSH enumeration for nmap mode"""
        enum_info = {
            'timing_analysis': {},
            'connection_stress_test': {},
            'protocol_probing': {}
        }

        try:
            # Timing-based analysis
            enum_info['timing_analysis'] = self._ssh_timing_analysis(ip, port)

            # Connection stress testing
            enum_info['connection_stress_test'] = self._ssh_connection_stress_test(ip, port)

            # Advanced protocol probing
            enum_info['protocol_probing'] = self._ssh_protocol_probing(ip, port)

        except Exception as e:
            enum_info['error'] = str(e)

        return enum_info

    def _ssh_timing_analysis(self, ip: str, port: int) -> Dict[str, Any]:
        """SSH timing analysis for username enumeration"""
        timing_info = {
            'baseline_time': 0,
            'potential_username_enumeration': False,
            'timing_variations': {}
        }

        try:
            # Establish baseline
            baseline_times = []
            for i in range(3):
                start_time = time.time()
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    sock.connect((ip, port))
                    banner = sock.recv(1024)
                    response_time = (time.time() - start_time) * 1000
                    baseline_times.append(response_time)
                    sock.close()
                except Exception:
                    pass
                time.sleep(1)

            if baseline_times:
                timing_info['baseline_time'] = sum(baseline_times) / len(baseline_times)

        except Exception as e:
            timing_info['error'] = str(e)

        return timing_info

    def _ssh_connection_stress_test(self, ip: str, port: int) -> Dict[str, Any]:
        """Test SSH server under connection stress"""
        stress_info = {
            'max_concurrent_connections': 0,
            'connection_limit_reached': False,
            'server_stability_under_load': True
        }

        try:
            connections = []

            # Test concurrent connections
            for i in range(10):  # Limit to 10 to avoid DoS
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((ip, port))
                    connections.append(sock)
                    stress_info['max_concurrent_connections'] = i + 1
                except Exception:
                    stress_info['connection_limit_reached'] = True
                    break

            # Clean up connections
            for sock in connections:
                try:
                    sock.close()
                except:
                    pass

        except Exception as e:
            stress_info['error'] = str(e)

        return stress_info

    def _ssh_protocol_probing(self, ip: str, port: int) -> Dict[str, Any]:
        """Advanced SSH protocol probing"""
        probing_info = {
            'protocol_versions_supported': [],
            'unusual_responses': []
        }

        try:
            # Test different protocol versions
            protocol_tests = ['SSH-1.99-Test', 'SSH-2.0-Test', 'SSH-1.0-Test']

            for protocol in protocol_tests:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    sock.connect((ip, port))

                    # Read server banner first
                    server_banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()

                    # Send our protocol version
                    sock.send(f"{protocol}\r\n".encode())

                    # Read response
                    response = sock.recv(1024).decode('utf-8', errors='ignore').strip()

                    if response and 'SSH-' in response:
                        probing_info['protocol_versions_supported'].append({
                            'sent': protocol,
                            'received': response
                        })

                    sock.close()
                except Exception:
                    pass

                time.sleep(0.5)

        except Exception as e:
            probing_info['error'] = str(e)

        return probing_info

    def _security_assessment_nmap(self, service_info: Dict[str, Any], enum_info: Dict[str, Any],
                                  nmap_data: Dict[str, Any]) -> Dict[str, Any]:
        """Security assessment based on nmap NSE results"""
        vulnerabilities = []
        recommendations = []

        # Process nmap script findings
        self._process_nmap_script_findings_ssh(nmap_data, vulnerabilities)

        # Add findings from aggressive enumeration
        self._process_aggressive_ssh_findings(enum_info, vulnerabilities)

        # Generate aggressive recommendations
        recommendations = self._generate_nmap_recommendations_ssh(vulnerabilities, service_info, nmap_data)

        return {
            'vulnerabilities': vulnerabilities,
            'recommendations': recommendations
        }

    def _process_nmap_script_findings_ssh(self, nmap_data: Dict[str, Any], vulnerabilities: List[Dict]):
        """Process nmap NSE script findings for SSH"""
        scripts = nmap_data.get('scripts', {})

        # Check for vulnerable SSH algorithms
        if 'ssh2-enum-algos' in scripts:
            algos_result = scripts['ssh2-enum-algos']
            if any(weak_algo in algos_result.lower() for weak_algo in ['cbc', 'md5', 'sha1', 'des']):
                vulnerabilities.append({
                    'id': 'SSH-WEAK-ALGORITHMS',
                    'severity': 'Medium',
                    'title': 'Weak SSH Algorithms Detected',
                    'description': f'Weak cryptographic algorithms found: {algos_result}',
                    'recommendation': 'Disable weak algorithms and use only strong ciphers',
                    'source': 'nmap_nse',
                    'detection_method': 'ssh2-enum-algos_script'
                })

        # Check authentication methods
        if 'ssh-auth-methods' in scripts:
            auth_result = scripts['ssh-auth-methods']
            if 'password' in auth_result.lower():
                vulnerabilities.append({
                    'id': 'SSH-PASSWORD-AUTH',
                    'severity': 'Low',
                    'title': 'SSH Password Authentication Enabled',
                    'description': f'Password authentication is enabled: {auth_result}',
                    'recommendation': 'Disable password authentication and use key-based authentication only',
                    'source': 'nmap_nse',
                    'detection_method': 'ssh-auth-methods_script'
                })

    def _process_aggressive_ssh_findings(self, enum_info: Dict[str, Any], vulnerabilities: List[Dict]):
        """Process aggressive SSH enumeration findings"""
        timing_analysis = enum_info.get('timing_analysis', {})
        if timing_analysis.get('potential_username_enumeration', False):
            vulnerabilities.append({
                'id': 'SSH-USER-ENUM-TIMING',
                'severity': 'Medium',
                'title': 'SSH Username Enumeration via Timing',
                'description': 'Timing analysis suggests username enumeration may be possible',
                'recommendation': 'Configure SSH to provide consistent response times',
                'source': 'manual_verification',
                'detection_method': 'timing_analysis'
            })

    def _generate_nmap_recommendations_ssh(self, vulnerabilities: List[Dict], service_info: Dict[str, Any],
                                           nmap_data: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on nmap NSE findings"""
        recommendations = [
            'Implement strong SSH authentication policies',
            'Monitor SSH logs for brute force attempts',
            'Use SSH key-based authentication exclusively',
            'Implement rate limiting for SSH connections',
            'Configure SSH fail2ban protection'
        ]

        # Add specific recommendations based on findings
        vuln_types = [v.get('id', '') for v in vulnerabilities]
        if any('WEAK-ALGORITHMS' in v_id for v_id in vuln_types):
            recommendations.append('Update SSH configuration to use only strong cryptographic algorithms')

        if any('PASSWORD-AUTH' in v_id for v_id in vuln_types):
            recommendations.append('Disable SSH password authentication and enforce key-based authentication')

        return list(set(recommendations))