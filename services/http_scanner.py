
import socket
import time
import subprocess
import re
import json
import requests
from datetime import datetime
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin
from .base_scanner import BaseScanner


class HTTPScanner(BaseScanner):


    def __init__(self, timeout: int = 10):
        super().__init__(timeout)

    def get_supported_ports(self) -> List[int]:
        return [80, 8000, 8080]  # Common HTTP ports

    def get_service_name(self) -> str:
        return "HTTP"

    def scan(self, ip: str, port: int, **kwargs) -> Dict[str, Any]:
        """Normal HTTP scan - Safe web application assessment"""
        self.scan_start_time = time.time()
        results = self.create_base_result(ip, port)

        try:
            print(f"🌐 Starting HTTP normal scan for {ip}:{port}")

            # Step 1: Basic connectivity and HTTP response
            self.mark_step_completed(results, 'connectivity')
            connectivity_info = self._check_http_connectivity(ip, port)
            results['connectivity_info'] = connectivity_info

            if not connectivity_info.get('accessible'):
                return self.create_failed_result(ip, port,
                                                 f"HTTP service not accessible: {connectivity_info.get('failure_reason', 'Connection failed')}")

            # Step 2: Basic HTTP headers and server analysis
            self.mark_step_completed(results, 'headers')
            headers_info = self._analyze_http_headers(ip, port)
            results['service_info'].update(headers_info)

            # Step 3: Run normal nmap scan (safe scripts)
            self.mark_step_completed(results, 'nmap_scan')
            nmap_results = self._run_normal_http_scan(ip, port)
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
            security_findings = self._parse_http_security_findings(nmap_results, aggressive=False)
            results['vulnerabilities'] = security_findings.get('vulnerabilities', [])
            results['recommendations'] = security_findings.get('recommendations', [])
            results['advanced_findings'] = security_findings.get('advanced_findings', {})

            # Step 5: Add manual web application analysis
            web_vulnerabilities = self._assess_web_security(ip, port, aggressive=False)
            results['vulnerabilities'].extend(web_vulnerabilities)

            return self.finalize_results(results, success=True)

        except Exception as e:
            print(f"❌ HTTP normal scan error: {e}")
            results['error'] = str(e)
            return self.finalize_results(results, success=False)

    def scan_aggressive(self, ip: str, port: int, **kwargs) -> Dict[str, Any]:
        """Aggressive HTTP scan - Comprehensive web application vulnerability assessment"""
        self.scan_start_time = time.time()
        results = self.create_base_result(ip, port)

        try:
            print(f"🎯 Starting HTTP aggressive scan for {ip}:{port}")

            # Get normal scan results if provided
            normal_results = kwargs.get('normal_scan_results')

            # Step 1: Connectivity (reuse if available)
            self.mark_step_completed(results, 'connectivity')
            if normal_results and normal_results.get('connectivity_info'):
                connectivity_info = normal_results['connectivity_info']
            else:
                connectivity_info = self._check_http_connectivity(ip, port)
            results['connectivity_info'] = connectivity_info

            # Step 2: Enhanced HTTP headers analysis
            self.mark_step_completed(results, 'enhanced_headers')
            if normal_results and normal_results.get('service_info'):
                headers_info = normal_results['service_info']
            else:
                headers_info = self._analyze_http_headers(ip, port)
            results['service_info'].update(headers_info)

            # Step 3: Run aggressive nmap scan (all scripts)
            self.mark_step_completed(results, 'aggressive_nmap_scan')
            nmap_results = self._run_aggressive_http_scan(ip, port)
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
            security_findings = self._parse_http_security_findings(nmap_results, aggressive=True)
            results['vulnerabilities'] = security_findings.get('vulnerabilities', [])
            results['recommendations'] = security_findings.get('recommendations', [])
            results['advanced_findings'] = security_findings.get('advanced_findings', {})

            # Step 5: Enhanced web application security assessment
            web_vulnerabilities = self._assess_web_security(ip, port, aggressive=True)
            results['vulnerabilities'].extend(web_vulnerabilities)

            return self.finalize_results(results, success=True)

        except Exception as e:
            print(f"❌ HTTP aggressive scan error: {e}")
            results['error'] = str(e)
            return self.finalize_results(results, success=False)

    def _check_http_connectivity(self, ip: str, port: int) -> Dict[str, Any]:
        """Check HTTP connectivity and basic response"""
        connectivity_info = {
            'accessible': False,
            'http_response_successful': False,
            'response_time': None,
            'status_code': None,
            'server_header': None
        }

        try:
            start_time = time.time()
            url = f"http://{ip}:{port}/"

            # Make HTTP request with timeout
            response = requests.get(url, timeout=self.timeout, allow_redirects=False)
            response_time = round((time.time() - start_time) * 1000, 2)

            connectivity_info.update({
                'accessible': True,
                'http_response_successful': True,
                'response_time': response_time,
                'status_code': response.status_code,
                'server_header': response.headers.get('Server'),
                'content_type': response.headers.get('Content-Type'),
                'content_length': response.headers.get('Content-Length'),
                'url': url
            })

            # Check for redirects
            if 300 <= response.status_code < 400:
                connectivity_info['redirect_location'] = response.headers.get('Location')

        except requests.exceptions.Timeout:
            connectivity_info['failure_reason'] = 'HTTP request timed out'
        except requests.exceptions.ConnectionError:
            connectivity_info['failure_reason'] = 'HTTP connection failed'
        except Exception as e:
            connectivity_info['failure_reason'] = f'HTTP request failed: {str(e)}'

        return connectivity_info

    def _analyze_http_headers(self, ip: str, port: int) -> Dict[str, Any]:
        """Analyze HTTP headers and server information"""
        headers_info = {}

        try:
            url = f"http://{ip}:{port}/"
            response = requests.get(url, timeout=self.timeout, allow_redirects=False)

            # Basic server information
            headers_info.update({
                'server_type': response.headers.get('Server', 'Unknown'),
                'content_type': response.headers.get('Content-Type'),
                'http_status_code': response.status_code,
                'content_length': response.headers.get('Content-Length'),
                'last_modified': response.headers.get('Last-Modified'),
                'etag': response.headers.get('ETag')
            })

            # Security headers analysis
            security_headers = self._analyze_security_headers(response.headers)
            headers_info['security_headers'] = security_headers

            # Extract server version if possible
            server_header = response.headers.get('Server', '')
            if server_header:
                version_match = re.search(r'([A-Za-z]+)[/\s]*([\d\.]+)', server_header)
                if version_match:
                    headers_info['server_name'] = version_match.group(1)
                    headers_info['server_version'] = version_match.group(2)

            # Check for common web technologies
            headers_info['technologies'] = self._detect_web_technologies(response.headers,
                                                                         response.text if hasattr(response,
                                                                                                  'text') else '')

        except Exception as e:
            headers_info['headers_error'] = str(e)

        return headers_info

    def _run_normal_http_scan(self, ip: str, port: int) -> Dict[str, Any]:
        """Run normal (safe) nmap HTTP scan"""
        try:
            # Normal HTTP scan - safe scripts only
            cmd = [
                'wsl', 'nmap', '-sV', f'-p{port}',
                '--script',
                'http-title,http-sitemap-generator,http-php-version,http-server-header,http-methods,http-robots.txt,http-security-headers,http-headers,http-favicon,http-enum',
                '--script-timeout', '60s',
                '--host-timeout', '300s',
                ip
            ]

            print(f"🌐 Running normal HTTP scan: {' '.join(cmd)}")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=420)

            if result.returncode != 0:
                error_msg = f"Normal HTTP nmap failed with return code {result.returncode}"
                if result.stderr:
                    error_msg += f": {result.stderr}"
                return {'error': error_msg}

            parsed = self._parse_nmap_http_output(result.stdout, aggressive=False)
            parsed['command_used'] = ' '.join(cmd)
            parsed['scan_type'] = 'normal'

            return parsed

        except subprocess.TimeoutExpired:
            return {'error': 'Normal HTTP nmap scan timed out'}
        except Exception as e:
            return {'error': f'Normal HTTP nmap execution failed: {str(e)}'}

    def _run_aggressive_http_scan(self, ip: str, port: int) -> Dict[str, Any]:
        """Run aggressive (comprehensive) nmap HTTP scan"""
        try:
            # Aggressive HTTP scan - all scripts including vulnerability testing
            cmd = [
                'wsl', 'nmap', '-sV', '-A', f'-p{port}',
                '--script','http-*','http-vuln*','http-userdir-enum','http-brute','http-auth-finder','http-auth','http-shellshock','http-dombased-xss','http-wordpress-enum',
                'http-xssed','http-csrf',
                '--script-timeout', '120s',
                '--host-timeout', '600s',
                ip
            ]

            print(f"🎯 Running aggressive HTTP scan: {' '.join(cmd)}")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=720)

            if result.returncode != 0:
                error_msg = f"Aggressive HTTP nmap failed with return code {result.returncode}"
                if result.stderr:
                    error_msg += f": {result.stderr}"
                return {'error': error_msg}

            parsed = self._parse_nmap_http_output(result.stdout, aggressive=True)
            parsed['command_used'] = ' '.join(cmd)
            parsed['scan_type'] = 'aggressive'

            return parsed

        except subprocess.TimeoutExpired:
            return {'error': 'Aggressive HTTP nmap scan timed out'}
        except Exception as e:
            return {'error': f'Aggressive HTTP nmap execution failed: {str(e)}'}

    def _parse_nmap_http_output(self, nmap_output: str, aggressive: bool = False) -> Dict[str, Any]:
        """Parse nmap HTTP output"""
        parsed = {
            'service_info': {},
            'banner': '',
            'web_info': {},
            'scripts': {},
            'raw_output': nmap_output,
            'formatted_for_display': self._format_http_output(nmap_output)
        }

        lines = nmap_output.split('\n')

        for line in lines:
            line_stripped = line.strip()

            # Parse HTTP service line
            if '/tcp' in line and ('http' in line.lower() and 'https' not in line.lower()):
                parsed['service_info']['protocol'] = 'TCP'
                parsed['service_info']['service'] = 'HTTP'
                parsed['banner'] = line_stripped

                # Extract server info
                server_match = re.search(r'(Apache|nginx|IIS|lighttpd)[/\s]*([\d\.]+)?', line)
                if server_match:
                    parsed['service_info']['server_type'] = server_match.group(1)
                    if server_match.group(2):
                        parsed['service_info']['server_version'] = server_match.group(2)

            # Parse HTTP script results
            elif line_stripped.startswith('|_http-') or line_stripped.startswith('| http-'):
                script_name = self._extract_script_name(line_stripped, 'http')
                if script_name:
                    content = self._extract_script_content(line_stripped, script_name)
                    parsed['scripts'][script_name] = content

        return parsed

    def _parse_http_security_findings(self, nmap_data: Dict[str, Any], aggressive: bool = False) -> Dict[str, Any]:
        """Parse HTTP security findings from nmap results"""
        findings = {
            'vulnerabilities': [],
            'recommendations': [],
            'advanced_findings': {}
        }

        if not nmap_data or nmap_data.get('error'):
            return findings

        scripts = nmap_data.get('scripts', {})

        # Web Security Analysis
        web_findings = self._analyze_web_findings(scripts, aggressive)
        findings['vulnerabilities'].extend(web_findings.get('vulnerabilities', []))
        findings['advanced_findings']['web_analysis'] = web_findings.get('web_analysis', {})

        # Server Security Analysis
        server_findings = self._analyze_server_findings(scripts, aggressive)
        findings['vulnerabilities'].extend(server_findings.get('vulnerabilities', []))
        findings['advanced_findings']['server_analysis'] = server_findings.get('server_analysis', {})

        # Generate recommendations
        findings['recommendations'] = self._generate_http_recommendations(findings['vulnerabilities'], aggressive)

        return findings

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
            if 'version' in scripts['http-server-header'].lower():
                web_findings['vulnerabilities'].append({
                    'id': 'HTTP-INFO-001',
                    'severity': 'Low',
                    'title': 'Server Version Disclosure',
                    'description': 'Web server discloses version information',
                    'recommendation': 'Configure server to hide version information',
                    'source': 'nmap_http',
                    'detection_method': 'http-server-header'
                })

        # Methods analysis
        if 'http-methods' in scripts:
            dangerous_methods = self._check_dangerous_http_methods(scripts['http-methods'])
            if dangerous_methods:
                web_findings['vulnerabilities'].append({
                    'id': 'HTTP-METHODS-001',
                    'severity': 'Medium',
                    'title': 'Dangerous HTTP Methods Enabled',
                    'description': f'Dangerous HTTP methods enabled: {", ".join(dangerous_methods)}',
                    'recommendation': 'Disable unnecessary HTTP methods (PUT, DELETE, TRACE, etc.)',
                    'source': 'nmap_http',
                    'detection_method': 'http-methods'
                })

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

            if 'http-xssed' in scripts:
                web_findings['vulnerabilities'].append({
                    'id': 'HTTP-XSS-001',
                    'severity': 'Medium',
                    'title': 'Cross-Site Scripting (XSS) Risk',
                    'description': 'Site appears in XSSed database',
                    'recommendation': 'Implement proper input validation and output encoding',
                    'source': 'nmap_http',
                    'detection_method': 'http-xssed'
                })

        return web_findings

    def _analyze_server_findings(self, scripts: Dict[str, Any], aggressive: bool) -> Dict[str, Any]:
        """Analyze server-related findings"""
        server_findings = {
            'vulnerabilities': [],
            'server_analysis': {}
        }

        # Check for common vulnerabilities
        if 'http-slowloris-check' in scripts:
            if 'VULNERABLE' in scripts['http-slowloris-check'].upper():
                server_findings['vulnerabilities'].append({
                    'id': 'HTTP-DOS-001',
                    'severity': 'Medium',
                    'title': 'Slowloris DoS Vulnerability',
                    'description': 'Server vulnerable to Slowloris denial of service attack',
                    'recommendation': 'Configure server timeout settings and rate limiting',
                    'source': 'nmap_http',
                    'detection_method': 'http-slowloris-check'
                })

        return server_findings

    def _assess_web_security(self, ip: str, port: int, aggressive: bool = False) -> List[Dict[str, Any]]:
        """Assess web application security issues manually"""
        vulnerabilities = []

        try:
            url = f"http://{ip}:{port}/"
            response = requests.get(url, timeout=self.timeout)

            # Check for default pages
            if self._is_default_page(response.text):
                vulnerabilities.append({
                    'id': 'HTTP-DEFAULT-001',
                    'severity': 'Low',
                    'title': 'Default Web Page Detected',
                    'description': 'Server serves default installation page',
                    'recommendation': 'Replace default page with custom content',
                    'source': 'manual_analysis',
                    'detection_method': 'content_analysis'
                })

            # Check for directory listing
            if 'Index of /' in response.text or 'Directory Listing' in response.text:
                vulnerabilities.append({
                    'id': 'HTTP-LISTING-001',
                    'severity': 'Medium',
                    'title': 'Directory Listing Enabled',
                    'description': 'Web server allows directory browsing',
                    'recommendation': 'Disable directory listing in web server configuration',
                    'source': 'manual_analysis',
                    'detection_method': 'content_analysis'
                })

        except Exception as e:
            print(f"Manual web security assessment failed: {e}")

        return vulnerabilities

    def _generate_http_recommendations(self, vulnerabilities: List[Dict], aggressive: bool) -> List[str]:
        """Generate HTTP security recommendations"""
        recommendations = [
            'Implement proper security headers (HSTS, CSP, X-Frame-Options, etc.)',
            'Keep web server software updated to latest stable version',
            'Disable unnecessary HTTP methods and server features',
            'Implement proper input validation and output encoding',
            'Use HTTPS instead of HTTP for sensitive data transmission'
        ]

        if aggressive:
            recommendations.extend([
                'Regular security scanning and penetration testing',
                'Implement Web Application Firewall (WAF)',
                'Use content security policies to prevent XSS attacks',
                'Implement rate limiting and DDoS protection',
                'Monitor web server logs for suspicious activity'
            ])

        return recommendations

    # Helper methods
    def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze HTTP security headers"""
        security_headers = {
            'strict-transport-security': headers.get('Strict-Transport-Security'),
            'content-security-policy': headers.get('Content-Security-Policy'),
            'x-frame-options': headers.get('X-Frame-Options'),
            'x-content-type-options': headers.get('X-Content-Type-Options'),
            'x-xss-protection': headers.get('X-XSS-Protection'),
            'referrer-policy': headers.get('Referrer-Policy')
        }

        analysis = {
            'headers_present': [],
            'missing_headers': [],
            'header_values': security_headers
        }

        for header, value in security_headers.items():
            if value:
                analysis['headers_present'].append(header)
            else:
                analysis['missing_headers'].append(header)

        return analysis

    def _detect_web_technologies(self, headers: Dict[str, str], content: str) -> List[str]:
        """Detect web technologies from headers and content"""
        technologies = []

        # Check headers for technology indicators
        server = headers.get('Server', '').lower()
        x_powered_by = headers.get('X-Powered-By', '').lower()

        if 'apache' in server:
            technologies.append('Apache')
        if 'nginx' in server:
            technologies.append('Nginx')
        if 'iis' in server:
            technologies.append('IIS')
        if 'php' in x_powered_by:
            technologies.append('PHP')
        if 'asp.net' in x_powered_by:
            technologies.append('ASP.NET')

        # Check content for framework indicators (limited to avoid performance issues)
        content_lower = content.lower()[:5000] if content else ''  # Only check first 5KB

        if 'wordpress' in content_lower:
            technologies.append('WordPress')
        if 'drupal' in content_lower:
            technologies.append('Drupal')
        if 'joomla' in content_lower:
            technologies.append('Joomla')

        return technologies

    def _is_default_page(self, content: str) -> bool:
        """Check if response contains default installation page"""
        default_indicators = [
            'apache2 default page',
            'nginx default page',
            'iis7 default',
            'welcome to nginx',
            'apache2 ubuntu default page',
            'test page for the apache',
            'default web site page'
        ]

        content_lower = content.lower()
        return any(indicator in content_lower for indicator in default_indicators)

    def _check_dangerous_http_methods(self, methods_output: str) -> List[str]:
        """Check for dangerous HTTP methods"""
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']
        found_dangerous = []

        methods_upper = methods_output.upper()
        for method in dangerous_methods:
            if method in methods_upper:
                found_dangerous.append(method)

        return found_dangerous

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

    def _format_http_output(self, nmap_output: str) -> str:
        """Format HTTP nmap output for display"""
        lines = nmap_output.split('\n')
        important_lines = []

        for line in lines:
            line_lower = line.lower()
            if any(keyword in line_lower for keyword in [
                'port', 'state', 'service', 'http-', 'server', 'title',
                'methods', 'headers', 'vulnerable', 'security', 'directory'
            ]):
                important_lines.append(line)

        return '\n'.join(important_lines) if important_lines else nmap_output

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