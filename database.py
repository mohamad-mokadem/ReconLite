import mysql.connector
from flask import jsonify
from mysql.connector import Error
import json
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any


class DatabaseManager:
    def __init__(self):
        self.connection = None
        self.connected = False
        self.connect()

    def connect(self):
        """Connect to MySQL database"""
        try:
            self.connection = mysql.connector.connect(
                host='localhost',
                port=3306,
                database='reconlite_db',
                user='root',
                password='',  # Usually empty for XAMPP
                charset='utf8mb4',
                collation='utf8mb4_unicode_ci'
            )

            if self.connection.is_connected():
                self.connected = True
                print("✅ Connected to MySQL database")
            else:
                self.connected = False
                print("❌ MySQL connection failed - not connected")

        except Error as e:
            self.connected = False
            print(f"❌ Error connecting to MySQL: {e}")
            print("💡 Make sure XAMPP MySQL is running and database 'reconlite_db' exists")

    def execute_query(self, query: str, params: tuple = None) -> Optional[List]:
        """Execute a query and return results"""
        # Check connection first
        if not self.connected or not self.connection:
            print("❌ Database not connected - cannot execute query")
            return None

        # Check if connection is still alive
        try:
            if not self.connection.is_connected():
                print("❌ Database connection lost - attempting to reconnect")
                self.connect()
                if not self.connected:
                    return None
        except Error:
            print("❌ Database connection check failed - attempting to reconnect")
            self.connect()
            if not self.connected:
                return None

        try:
            cursor = self.connection.cursor(dictionary=True)
            cursor.execute(query, params or ())

            if query.strip().upper().startswith('SELECT'):
                results = cursor.fetchall()
                cursor.close()
                return results
            else:
                self.connection.commit()
                cursor.close()
                return None

        except Error as e:
            print(f"❌ Database error: {e}")
            print(f"❌ Query: {query}")
            print(f"❌ Params: {params}")
            return None

    # Session Management Methods
    def create_session(self, session_data: Dict[str, Any]) -> str:
        """Create a new session"""
        if not self.connected:
            print("❌ Cannot create session - database not connected")
            return None

        session_id = str(uuid.uuid4())

        query = """
        INSERT INTO sessions (id, name, type, target, status, created_at, notes)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """

        params = (
            session_id,
            session_data.get('name'),
            session_data.get('type'),
            session_data.get('target'),
            session_data.get('status', 'in_progress'),
            datetime.now(),
            session_data.get('notes', '')
        )

        try:
            # For INSERT queries, we need to check if the operation succeeded differently
            if not self.connected or not self.connection:
                print("❌ Database not connected - cannot create session")
                return None

            cursor = self.connection.cursor(dictionary=True)
            cursor.execute(query, params)
            self.connection.commit()

            # Check if the insert was successful by checking affected rows
            if cursor.rowcount > 0:
                cursor.close()
                print(f"✅ Session created successfully with ID: {session_id}")
                return session_id
            else:
                cursor.close()
                print(f"❌ Failed to create session - no rows affected")
                return None

        except Error as e:
            print(f"❌ Database error creating session: {e}")
            print(f"❌ Query: {query}")
            print(f"❌ Params: {params}")
            return None

    def get_sessions(self, limit: int = 50) -> List[Dict]:
        """Get all sessions with proper error handling and debugging"""
        if not self.connected:
            print("❌ Cannot get sessions - database not connected")
            return []

        try:
            query = """
            SELECT s.*, 
                   COALESCE(COUNT(DISTINCT ds.id), 0) as service_count,
                   COALESCE(COUNT(DISTINCT v.id), 0) as vulnerability_count
            FROM sessions s
            LEFT JOIN discovered_services ds ON s.id = ds.session_id
            LEFT JOIN vulnerabilities v ON s.id = v.session_id
            GROUP BY s.id, s.name, s.type, s.target, s.status, s.created_at, s.completed_at, s.notes, s.scan_duration, s.total_ports, s.open_ports, s.vulnerabilities_found
            ORDER BY s.created_at DESC
            LIMIT %s
            """

            results = self.execute_query(query, (limit,))

            if results is None:
                print("❌ No results returned from sessions query")
                return []

            print(f"✅ Found {len(results)} sessions in database")

            # Debug: Print first session if available
            if results:
                print(f"📊 Sample session: {results[0]}")

            return results

        except Exception as e:
            print(f"❌ Error in get_sessions: {e}")
            return []

    def get_session_details(self, session_id: str) -> Optional[Dict]:
        """Enhanced session details with exploit URLs"""
        if not self.connected:
            print("❌ Cannot get session details - database not connected")
            return None

        try:
            print(f"[DEBUG] 🔍 DB: Getting enhanced session details for {session_id}")

            # Get session info
            session_query = "SELECT * FROM sessions WHERE id = %s"
            session_result = self.execute_query(session_query, (session_id,))

            if not session_result or len(session_result) == 0:
                print(f"[DEBUG] ❌ DB: No session found with ID {session_id}")
                return None

            session_data = session_result[0]
            print(f"[DEBUG] ✅ DB: Session found - {session_data.get('name', 'Unknown')}")

            # Get services
            services_query = "SELECT * FROM discovered_services WHERE session_id = %s ORDER BY port"
            services = self.execute_query(services_query, (session_id,)) or []
            session_data['services'] = services
            print(f"[DEBUG] 📊 DB: Found {len(services)} services")

            # Get DNS records
            dns_query = "SELECT * FROM dns_records WHERE session_id = %s"
            dns_records = self.execute_query(dns_query, (session_id,)) or []
            session_data['dns_records'] = dns_records

            # Get subdomains
            subdomains_query = "SELECT * FROM subdomains WHERE session_id = %s"
            subdomains = self.execute_query(subdomains_query, (session_id,)) or []
            session_data['subdomains'] = subdomains

            # Get vulnerabilities
            vulns_query = "SELECT * FROM vulnerabilities WHERE session_id = %s ORDER BY severity DESC"
            vulnerabilities = self.execute_query(vulns_query, (session_id,)) or []
            session_data['vulnerabilities'] = vulnerabilities

            # Enhanced: Get CVE vulnerabilities with exploit URLs
            cve_query = """
            SELECT cv.*, 
                   GROUP_CONCAT(cr.reference_url SEPARATOR '||') as exploit_urls,
                   GROUP_CONCAT(cr.reference_type SEPARATOR '||') as url_types
            FROM cve_vulnerabilities cv
            LEFT JOIN cve_references cr ON cv.id = cr.cve_vulnerability_id
            WHERE cv.session_id = %s
            GROUP BY cv.id
            ORDER BY cv.cvss_score DESC
            """
            cve_vulnerabilities = self.execute_query(cve_query, (session_id,)) or []

            # Process CVE vulnerabilities to include exploit URLs
            processed_cve_vulns = []
            for cve in cve_vulnerabilities:
                cve_dict = dict(cve)

                # Parse exploit URLs
                if cve_dict.get('exploit_urls'):
                    urls = cve_dict['exploit_urls'].split('||')
                    types = cve_dict.get('url_types', '').split('||')

                    cve_dict['exploit_references'] = []
                    for i, url in enumerate(urls):
                        if url:
                            url_type = types[i] if i < len(types) else 'other'
                            cve_dict['exploit_references'].append({
                                'url': url,
                                'type': url_type,
                                'title': self._get_url_title(url, url_type),
                                'verified': True
                            })
                else:
                    cve_dict['exploit_references'] = []

                # Clean up
                if 'exploit_urls' in cve_dict:
                    del cve_dict['exploit_urls']
                if 'url_types' in cve_dict:
                    del cve_dict['url_types']

                processed_cve_vulns.append(cve_dict)

            session_data['cve_vulnerabilities'] = processed_cve_vulns
            print(f"[DEBUG] 📊 DB: Found {len(processed_cve_vulns)} CVE vulnerabilities with URLs")

            # Get detected software
            software_query = "SELECT * FROM detected_software WHERE session_id = %s ORDER BY confidence DESC"
            detected_software = self.execute_query(software_query, (session_id,)) or []
            session_data['detected_software'] = detected_software

            # Get whois data
            whois_query = "SELECT * FROM whois_data WHERE session_id = %s"
            whois_data = self.execute_query(whois_query, (session_id,)) or []
            session_data['whois_data'] = whois_data

            return session_data

        except Exception as e:
            print(f"[DEBUG] ❌ DB: Error getting enhanced session details: {e}")
            return None

    def save_discovered_service(self, session_id: str, service_data: Dict[str, Any]):
        """Save a discovered service"""
        if not self.connected:
            print("❌ Cannot save service - database not connected")
            return False

        query = """
        INSERT INTO discovered_services 
        (session_id, ip_address, port, protocol, service_name, service_version, banner, state)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """

        params = (
            session_id,
            service_data.get('ip'),
            service_data.get('port'),
            service_data.get('protocol', 'tcp'),
            service_data.get('service'),
            service_data.get('version'),
            service_data.get('banner'),
            service_data.get('state', 'open')
        )

        try:
            if not self.connected or not self.connection:
                return False

            cursor = self.connection.cursor(dictionary=True)
            cursor.execute(query, params)
            self.connection.commit()
            success = cursor.rowcount > 0
            cursor.close()
            return success

        except Error as e:
            print(f"❌ Database error saving service: {e}")
            return False

    def complete_session(self, session_id: str, summary_data: Dict[str, Any]):
        """Enhanced session completion with exploit statistics"""
        if not self.connected:
            print("❌ Cannot complete session - database not connected")
            return False

        # Calculate enhanced statistics
        cve_count = summary_data.get('cve_vulnerabilities_found', 0)
        software_count = summary_data.get('software_detected', 0)
        highest_cvss = summary_data.get('highest_cvss_score', 0.0)

        # Count exploit URLs
        exploit_urls_count = 0
        try:
            url_count_query = """
            SELECT COUNT(*) as url_count 
            FROM cve_references cr
            JOIN cve_vulnerabilities cv ON cr.cve_vulnerability_id = cv.id
            WHERE cv.session_id = %s
            """
            result = self.execute_query(url_count_query, (session_id,))
            if result and len(result) > 0:
                exploit_urls_count = result[0]['url_count']
        except Exception as e:
            print(f"⚠️ Could not count exploit URLs: {e}")

        query = """
        UPDATE sessions 
        SET status = 'completed', 
            completed_at = %s,
            scan_duration = %s,
            total_ports = %s,
            open_ports = %s,
            vulnerabilities_found = %s,
            cve_vulnerabilities_found = %s,
            software_detected = %s,
            highest_cvss_score = %s
        WHERE id = %s
        """

        params = (
            datetime.now(),
            summary_data.get('duration', 0),
            summary_data.get('total_ports', 0),
            summary_data.get('open_ports', 0),
            summary_data.get('vulnerabilities', 0),
            cve_count,
            software_count,
            highest_cvss,
            session_id
        )

        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            self.connection.commit()
            success = cursor.rowcount > 0
            cursor.close()

            if success:
                print(f"✅ Enhanced session completed: {session_id}")
                print(
                    f"📊 Stats: {summary_data.get('vulnerabilities', 0)} vulns, {cve_count} CVEs, {exploit_urls_count} URLs")

            return success

        except Error as e:
            print(f"❌ Database error completing enhanced session: {e}")
            return False

    def delete_session(self, session_id: str) -> bool:
        """Delete a session and all related data"""
        if not self.connected:
            print("❌ Cannot delete session - database not connected")
            return False

        query = "DELETE FROM sessions WHERE id = %s"

        try:
            if not self.connected or not self.connection:
                return False

            cursor = self.connection.cursor(dictionary=True)
            cursor.execute(query, (session_id,))
            self.connection.commit()
            success = cursor.rowcount > 0
            cursor.close()
            return success

        except Error as e:
            print(f"❌ Database error deleting session: {e}")
            return False

    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get statistics for dashboard with better error handling"""
        stats = {
            'total_sessions': 0,
            'passive_sessions': 0,
            'active_sessions': 0,
            'total_services': 0
        }

        if not self.connected:
            print("❌ Cannot get dashboard stats - database not connected")
            return stats

        try:
            # Total sessions
            total_query = "SELECT COUNT(*) as total FROM sessions"
            result = self.execute_query(total_query)
            if result and len(result) > 0:
                stats['total_sessions'] = result[0]['total']
                print(f"📊 Total sessions: {stats['total_sessions']}")

            # Sessions by type
            type_query = """
            SELECT type, COUNT(*) as count 
            FROM sessions 
            GROUP BY type
            """
            type_results = self.execute_query(type_query) or []

            for row in type_results:
                if row['type'] == 'passive':
                    stats['passive_sessions'] = row['count']
                elif row['type'] == 'active':
                    stats['active_sessions'] = row['count']

            print(f"📊 Passive sessions: {stats['passive_sessions']}, Active sessions: {stats['active_sessions']}")

            # Total services found
            services_query = "SELECT COUNT(*) as total FROM discovered_services"
            result = self.execute_query(services_query)
            if result and len(result) > 0:
                stats['total_services'] = result[0]['total']
                print(f"📊 Total services: {stats['total_services']}")

            return stats

        except Exception as e:
            print(f"❌ Error getting dashboard stats: {e}")
            return stats

    def close(self):
        """Close database connection"""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            self.connected = False
            print("✅ Database connection closed")

    def save_cve_vulnerability(self, session_id: str, cve_vuln: Dict[str, Any]) -> bool:
        """Enhanced CVE vulnerability saving with exploit URLs and references"""
        if not self.connected:
            return False

        query = """
        INSERT INTO cve_vulnerabilities 
        (session_id, cve_id, severity, cvss_score, cvss_vector, title, description, 
         recommendation, published_date, source, risk_score, remediation_priority,
         affected_software, software_version, detection_method)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        # Parse published date
        published_date = None
        if cve_vuln.get('published_date'):
            try:
                from datetime import datetime
                if isinstance(cve_vuln['published_date'], str):
                    published_date = datetime.fromisoformat(cve_vuln['published_date'].replace('Z', ''))
                else:
                    published_date = cve_vuln['published_date']
            except:
                pass

        # Enhanced parameters with exploit data
        params = (
            session_id,
            cve_vuln.get('cve_id', cve_vuln.get('id', '')),
            cve_vuln.get('severity', 'Unknown'),
            cve_vuln.get('cvss_score', 0.0),
            cve_vuln.get('cvss_vector', ''),
            cve_vuln.get('title', ''),
            cve_vuln.get('description', ''),
            cve_vuln.get('recommendation', ''),
            published_date,
            cve_vuln.get('source', 'Vulners'),
            cve_vuln.get('risk_score', 0.0),
            cve_vuln.get('remediation_priority', 'Medium'),
            cve_vuln.get('affected_software', ''),
            cve_vuln.get('software_version', ''),
            cve_vuln.get('detection_method', 'banner_analysis')
        )

        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            self.connection.commit()
            cve_id = cursor.lastrowid
            success = cursor.rowcount > 0
            cursor.close()

            if success and cve_id:
                print(f"✅ Enhanced CVE vulnerability saved: {cve_vuln.get('cve_id', 'Unknown')}")

                # Save exploit URLs using existing cve_references table
                self._save_exploit_urls_to_references(cve_id, cve_vuln)

            return success
        except Exception as e:
            print(f"❌ Error saving enhanced CVE vulnerability: {e}")
            return False


    def save_detected_software(self, session_id: str, software: Dict[str, Any]) -> bool:
        """Save detected software to database"""
        if not self.connected:
            return False

        query = """
        INSERT INTO detected_software 
        (session_id, software_name, version, cpe, confidence, detection_method, raw_match)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """

        params = (
            session_id,
            software.get('name', ''),
            software.get('version', ''),
            software.get('cpe', ''),
            software.get('confidence', 'medium'),
            software.get('detection_method', 'banner_pattern'),
            software.get('raw_match', '')
        )

        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            self.connection.commit()
            success = cursor.rowcount > 0
            cursor.close()
            return success
        except Exception as e:
            print(f"❌ Error saving detected software: {e}")
            return False

    def save_vulnerability(self, session_id: str, vuln: Dict[str, Any]) -> bool:
        """Save vulnerability to database"""
        if not self.connected:
            print("❌ Cannot save vulnerability - database not connected")
            return False

        query = """
        INSERT INTO vulnerabilities 
        (session_id, vuln_id, severity, title, description, recommendation)
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

        try:
            if not self.connected or not self.connection:
                return False

            cursor = self.connection.cursor(dictionary=True)
            cursor.execute(query, params)
            self.connection.commit()
            success = cursor.rowcount > 0
            cursor.close()

            if success:
                print(f"✅ Vulnerability saved: {vuln.get('id', 'Unknown')}")
            else:
                print(f"❌ Failed to save vulnerability: {vuln.get('id', 'Unknown')}")

            return success

        except Error as e:
            print(f"❌ Database error saving vulnerability: {e}")
            print(f"❌ Query: {query}")
            print(f"❌ Params: {params}")
            return False




    def save_shodan_host_intelligence(self, session_id: str, ip_address: str, shodan_data: Dict[str, Any]) -> bool:
        """Save Shodan host intelligence to database"""
        if not self.connected:
            return False

        query = """
        INSERT INTO shodan_host_intelligence 
        (session_id, ip_address, organization, isp, country, city, asn, 
         last_update, total_ports, hostnames, domains)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
        organization = VALUES(organization),
        isp = VALUES(isp),
        country = VALUES(country),
        city = VALUES(city),
        asn = VALUES(asn),
        last_update = VALUES(last_update),
        total_ports = VALUES(total_ports),
        hostnames = VALUES(hostnames),
        domains = VALUES(domains)
        """

        try:
            import json

            params = (
                session_id,
                ip_address,
                shodan_data.get('org', ''),
                shodan_data.get('isp', ''),
                shodan_data.get('country_name', ''),
                shodan_data.get('city', ''),
                shodan_data.get('asn', ''),
                shodan_data.get('last_update'),
                len(shodan_data.get('data', [])),
                json.dumps(shodan_data.get('hostnames', [])),
                json.dumps(shodan_data.get('domains', []))
            )

            cursor = self.connection.cursor()
            cursor.execute(query, params)
            self.connection.commit()
            success = cursor.rowcount > 0
            cursor.close()

            if success:
                print(f"✅ Saved Shodan host intelligence for {ip_address}")
            return success

        except Exception as e:
            print(f"❌ Error saving Shodan host intelligence: {e}")
            return False


    def save_shodan_port_data(self, session_id: str, ip_address: str, port_data: Dict[str, Any]) -> bool:
        """Save Shodan port-specific data to database"""
        if not self.connected:
            return False

        query = """
        INSERT INTO shodan_port_data 
        (session_id, ip_address, port, shodan_product, shodan_version, shodan_banner,
         shodan_timestamp, banner_hash, ssl_info, http_info, cpe_list, vulnerabilities)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
        shodan_product = VALUES(shodan_product),
        shodan_version = VALUES(shodan_version),
        shodan_banner = VALUES(shodan_banner),
        shodan_timestamp = VALUES(shodan_timestamp),
        banner_hash = VALUES(banner_hash),
        ssl_info = VALUES(ssl_info),
        http_info = VALUES(http_info),
        cpe_list = VALUES(cpe_list),
        vulnerabilities = VALUES(vulnerabilities)
        """

        try:
            import json
            from datetime import datetime

            # Parse timestamp
            timestamp = None
            if port_data.get('timestamp'):
                try:
                    timestamp = datetime.fromisoformat(port_data['timestamp'].replace('Z', ''))
                except:
                    pass

            params = (
                session_id,
                ip_address,
                port_data.get('port'),
                port_data.get('product', ''),
                port_data.get('version', ''),
                port_data.get('banner', ''),
                timestamp,
                port_data.get('hash', ''),
                json.dumps(port_data.get('ssl', {})),
                json.dumps(port_data.get('http', {})),
                json.dumps(port_data.get('cpe', [])),
                json.dumps(list(port_data.get('vulns', [])))
            )

            cursor = self.connection.cursor()
            cursor.execute(query, params)
            self.connection.commit()
            success = cursor.rowcount > 0
            cursor.close()

            if success:
                print(f"✅ Saved Shodan port data for {ip_address}:{port_data.get('port')}")
            return success

        except Exception as e:
            print(f"❌ Error saving Shodan port data: {e}")
            return False


    def save_shodan_other_ports(self, session_id: str, ip_address: str, other_ports: List[Dict[str, Any]]) -> bool:
        """Save other ports discovered by Shodan"""
        if not self.connected or not other_ports:
            return False

        # Clear existing other ports for this session/IP
        delete_query = "DELETE FROM shodan_other_ports WHERE session_id = %s AND ip_address = %s"

        insert_query = """
        INSERT INTO shodan_other_ports 
        (session_id, ip_address, port, product, version, last_seen, confidence_level)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """

        try:
            from datetime import datetime

            cursor = self.connection.cursor()

            # Clear existing
            cursor.execute(delete_query, (session_id, ip_address))

            # Insert new data
            for port_info in other_ports[:20]:  # Limit to 20 ports
                timestamp = None
                if port_info.get('last_seen'):
                    try:
                        timestamp = datetime.fromisoformat(port_info['last_seen'].replace('Z', ''))
                    except:
                        pass

                params = (
                    session_id,
                    ip_address,
                    port_info.get('port'),
                    port_info.get('product', ''),
                    port_info.get('version', ''),
                    timestamp,
                    'medium'  # Default confidence
                )
                cursor.execute(insert_query, params)

            self.connection.commit()
            cursor.close()
            print(f"✅ Saved {len(other_ports)} Shodan other ports for {ip_address}")
            return True

        except Exception as e:
            print(f"❌ Error saving Shodan other ports: {e}")
            return False

    def get_shodan_intelligence_for_session(self, session_id: str) -> Dict[str, Any]:
        """Retrieve all Shodan intelligence for a session"""
        if not self.connected:
            return {}

        try:
            # Get host intelligence
            host_query = """
            SELECT * FROM shodan_host_intelligence 
            WHERE session_id = %s
            """
            host_data = self.execute_query(host_query, (session_id,)) or []

            # Get port data
            port_query = """
            SELECT * FROM shodan_port_data 
            WHERE session_id = %s
            """
            port_data = self.execute_query(port_query, (session_id,)) or []

            # Get other ports
            other_ports_query = """
            SELECT * FROM shodan_other_ports 
            WHERE session_id = %s
            ORDER BY port
            """
            other_ports_data = self.execute_query(other_ports_query, (session_id,)) or []

            return {
                'host_intelligence': host_data,
                'port_data': port_data,
                'other_ports': other_ports_data,
                'available': len(host_data) > 0 or len(port_data) > 0
            }

        except Exception as e:
            print(f"❌ Error retrieving Shodan intelligence: {e}")
            return {}


    def update_session_shodan_metadata(self, session_id: str, credits_used: int = 0) -> bool:
        """Update session with Shodan usage metadata"""
        if not self.connected:
            return False

        query = """
        UPDATE sessions 
        SET shodan_intelligence_used = TRUE,
            shodan_query_credits_used = %s,
            shodan_last_updated = NOW()
        WHERE id = %s
        """

        try:
            cursor = self.connection.cursor()
            cursor.execute(query, (credits_used, session_id))
            self.connection.commit()
            success = cursor.rowcount > 0
            cursor.close()
            return success

        except Exception as e:
            print(f"❌ Error updating session Shodan metadata: {e}")
            return False


    def get_session_details_with_shodan(self, session_id: str) -> Optional[Dict]:
        """Get session details including Shodan intelligence"""
        try:
            # Get basic session details
            session_data = self.get_session_details(session_id)
            if not session_data:
                return None

            # Add Shodan intelligence
            shodan_intel = self.get_shodan_intelligence_for_session(session_id)
            if shodan_intel.get('available'):
                session_data['shodan_intelligence'] = shodan_intel

            return session_data

        except Exception as e:
            print(f"❌ Error getting session details with Shodan: {e}")
            return None


    def get_session_details_complete(self, session_id: str) -> Optional[Dict]:
        """Get COMPLETE session information with all data formatted for UI"""
        if not self.connected:
            print("❌ Cannot get session details - database not connected")
            return None

        try:
            print(f"[DEBUG] 🔍 DB: Getting COMPLETE session details for {session_id}")

            # Get session info
            session_query = "SELECT * FROM sessions WHERE id = %s"
            session_result = self.execute_query(session_query, (session_id,))

            if not session_result or len(session_result) == 0:
                print(f"[DEBUG] ❌ DB: No session found with ID {session_id}")
                return None

            session_data = session_result[0]
            print(f"[DEBUG] ✅ DB: Session found - {session_data.get('name', 'Unknown')}")

            # Get ALL related data
            # Services
            services_query = "SELECT * FROM discovered_services WHERE session_id = %s ORDER BY port"
            services = self.execute_query(services_query, (session_id,)) or []
            session_data['services'] = services

            # DNS records
            dns_query = "SELECT * FROM dns_records WHERE session_id = %s ORDER BY record_type"
            dns_records = self.execute_query(dns_query, (session_id,)) or []
            session_data['dns_records'] = dns_records

            # Subdomains
            subdomains_query = "SELECT * FROM subdomains WHERE session_id = %s ORDER BY subdomain"
            subdomains = self.execute_query(subdomains_query, (session_id,)) or []
            session_data['subdomains'] = subdomains

            # Whois data
            whois_query = "SELECT * FROM whois_data WHERE session_id = %s"
            whois_data = self.execute_query(whois_query, (session_id,)) or []
            session_data['whois_data'] = whois_data

            # Vulnerabilities
            vulns_query = "SELECT * FROM vulnerabilities WHERE session_id = %s ORDER BY severity DESC"
            vulnerabilities = self.execute_query(vulns_query, (session_id,)) or []
            session_data['vulnerabilities'] = vulnerabilities

            # CVE vulnerabilities
            cve_query = "SELECT * FROM cve_vulnerabilities WHERE session_id = %s ORDER BY cvss_score DESC"
            cve_vulnerabilities = self.execute_query(cve_query, (session_id,)) or []
            session_data['cve_vulnerabilities'] = cve_vulnerabilities

            # Detected software
            software_query = "SELECT * FROM detected_software WHERE session_id = %s ORDER BY confidence DESC"
            detected_software = self.execute_query(software_query, (session_id,)) or []
            session_data['detected_software'] = detected_software

            # Shodan intelligence (if tables exist)
            try:
                shodan_host_query = "SELECT * FROM shodan_host_intelligence WHERE session_id = %s"
                shodan_host = self.execute_query(shodan_host_query, (session_id,)) or []

                shodan_port_query = "SELECT * FROM shodan_port_data WHERE session_id = %s"
                shodan_port = self.execute_query(shodan_port_query, (session_id,)) or []

                shodan_other_query = "SELECT * FROM shodan_other_ports WHERE session_id = %s ORDER BY port"
                shodan_other = self.execute_query(shodan_other_query, (session_id,)) or []

                if shodan_host or shodan_port or shodan_other:
                    session_data['shodan_intelligence'] = {
                        'available': True,
                        'host_data': shodan_host,
                        'port_data': shodan_port,
                        'other_ports': shodan_other
                    }
            except Exception as shodan_error:
                print(f"[DEBUG] ⚠️ DB: Shodan tables might not exist: {shodan_error}")
                session_data['shodan_intelligence'] = {'available': False}

            print(f"[DEBUG] ✅ DB: Complete session data loaded successfully")
            print(f"[DEBUG] 📊 DB: {len(services)} services, {len(dns_records)} DNS, {len(subdomains)} subdomains")
            print(f"[DEBUG] 📊 DB: {len(vulnerabilities)} vulns, {len(cve_vulnerabilities)} CVEs")

            return session_data

        except Exception as e:
            print(f"[DEBUG] ❌ DB: Error getting complete session details: {e}")
            import traceback
            traceback.print_exc()
            return None

    def _save_exploit_urls_to_references(self, cve_vulnerability_id: int, cve_vuln: Dict[str, Any]):
        """Save exploit URLs to existing cve_references table"""
        try:
            references = []

            # Add Vulners URL if available
            if cve_vuln.get('href'):
                references.append({
                    'url': cve_vuln['href'],
                    'type': 'vendor'  # Using existing enum
                })

            # Add source URL if available
            if cve_vuln.get('source_href'):
                references.append({
                    'url': cve_vuln['source_href'],
                    'type': 'advisory'  # Using existing enum
                })

            # Add CVE URL
            if cve_vuln.get('cve_id') and cve_vuln['cve_id'].startswith('CVE-'):
                references.append({
                    'url': f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_vuln['cve_id']}",
                    'type': 'advisory'
                })

            # Add Exploit-DB URL if available
            if cve_vuln.get('has_exploits') and cve_vuln.get('exploit_count', 0) > 0:
                # Try to extract EDB ID from title or generate search URL
                edb_url = self._generate_exploit_db_url(cve_vuln)
                if edb_url:
                    references.append({
                        'url': edb_url,
                        'type': 'exploit'
                    })

            # Save all references using existing table structure
            for ref in references:
                self._save_to_cve_references(cve_vulnerability_id, ref)

        except Exception as e:
            print(f"❌ Error saving exploit URLs: {e}")

    def _save_to_cve_references(self, cve_vulnerability_id: int, reference: Dict[str, Any]):
        """Save to existing cve_references table"""
        try:
            query = """
            INSERT INTO cve_references (cve_vulnerability_id, reference_url, reference_type)
            VALUES (%s, %s, %s)
            """

            params = (
                cve_vulnerability_id,
                reference['url'],
                reference['type']
            )

            cursor = self.connection.cursor()
            cursor.execute(query, params)
            self.connection.commit()
            cursor.close()

            print(f"✅ Exploit URL saved: {reference['url']}")

        except Exception as e:
            print(f"❌ Error saving reference: {e}")

    def _generate_exploit_db_url(self, cve_vuln: Dict[str, Any]) -> str:
        """Generate Exploit-DB URL from CVE data"""
        # Try to extract EDB ID from title
        title = cve_vuln.get('title', '')
        import re

        edb_match = re.search(r'EDB-ID:\s*(\d+)', title, re.IGNORECASE)
        if edb_match:
            return f"https://www.exploit-db.com/exploits/{edb_match.group(1)}"

        # Fallback to search URL
        if cve_vuln.get('cve_id'):
            return f"https://www.exploit-db.com/search?cve={cve_vuln['cve_id']}"

        # General exploit search
        if cve_vuln.get('affected_software'):
            search_term = cve_vuln['affected_software'].replace(' ', '+')
            return f"https://www.exploit-db.com/search?q={search_term}"

        return "https://www.exploit-db.com/"

    def _get_url_title(self, url: str, url_type: str) -> str:
        """Generate user-friendly title for exploit URLs"""
        if 'exploit-db.com' in url:
            return 'View on Exploit-DB'
        elif 'vulners.com' in url:
            return 'View on Vulners'
        elif 'cve.mitre.org' in url:
            return 'CVE Details'
        elif 'nvd.nist.gov' in url:
            return 'NVD Database'
        elif url_type == 'vendor':
            return 'Vendor Advisory'
        elif url_type == 'exploit':
            return 'Exploit Reference'
        else:
            return 'Reference Link'





# Global database instance
db = DatabaseManager()