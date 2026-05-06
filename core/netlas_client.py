import requests
import json
from typing import List, Dict, Any

# Netlas API base URL - this was missing!
NETLAS_BASE_URL = "https://app.netlas.io/api"


class NetlasClient:
    """Netlas API client for port and service discovery - Fixed version"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = NETLAS_BASE_URL
        self.headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json"
        }
        self.debug = True

    def search_target(self, target: str, target_type: str) -> List[Dict[str, Any]]:
        """Search for ports and services on target"""

        if self.debug:
            print(f"🔍 Netlas: Searching for {target} (type: {target_type})")

        try:
            # Build query based on target type (your working version)
            if target_type == 'domain':
                query = f"domain:{target} OR host:{target}"
            else:
                query = f"ip:{target}"

            if self.debug:
                print(f"🔍 Netlas: Query: {query}")

            # Make API request (your working version)
            response = requests.get(
                f"{self.base_url}/responses",
                headers=self.headers,
                params={
                    "q": query,
                    "start": 0,
                    "size": 20
                },
                timeout=10
            )

            if self.debug:
                print(f"🔍 Netlas: API response status: {response.status_code}")

            if response.status_code == 200:
                results = self._parse_results(response.json())
                if self.debug:
                    print(f"✅ Netlas: Found {len(results)} results")
                return results
            else:
                print(f"❌ Netlas API error: {response.status_code}")
                print(f"   Response: {response.text}")
                return []

        except Exception as e:
            print(f"❌ Netlas search error: {str(e)}")
            return []

    def _parse_results(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Enhanced Netlas result parsing with robust data extraction (your working version)"""

        if self.debug:
            # Print raw data for debugging (your version)
            print("🔍 Netlas: Raw API response:")
            print(json.dumps(data.get('items', []), indent=2))

        results = []
        seen = set()

        items = data.get("items") or data.get("data") or []
        print(f"[DEBUG] Netlas raw results count: {len(items)}")

        for item in items:
            try:
                # 'item' could be a dict or have nested 'data' (your working version)
                record = item.get('data', item) if isinstance(item, dict) else item

                # Extract IP or host (your working version)
                ip = record.get("ip") or record.get("host")
                port = record.get("port")

                # Skip if missing essential info (your working version)
                if not ip or port is None:
                    if self.debug:
                        print(f"[DEBUG] Skipping entry missing IP or port: {record}")
                    continue

                # Normalize port as int safely (your working version)
                try:
                    port = int(port)
                except Exception:
                    if self.debug:
                        print(f"[DEBUG] Skipping entry with invalid port: {port}")
                    continue

                key = f"{ip}:{port}"
                if key in seen:
                    continue
                seen.add(key)

                # Extract service info, handle if it's a dict or string (your working version)
                service_data = record.get("service", {})
                if isinstance(service_data, dict):
                    service_name = service_data.get("name", "unknown") or "unknown"
                    service_version = service_data.get("version", "") or ""
                else:
                    service_name = service_data if service_data else "unknown"
                    service_version = ""

                # HTTP info (some entries might not have 'http' key) (your working version)
                http_data = record.get("http", {})
                if not isinstance(http_data, dict):
                    http_data = {}

                # Location info (your working version)
                location_data = record.get("location", {})
                if not isinstance(location_data, dict):
                    location_data = {}

                # Append to results (your working version)
                results.append({
                    "ip": ip,
                    "port": port,
                    "protocol": record.get("protocol", "tcp") or "tcp",
                    "service": service_name,
                    "version": service_version,
                    "banner": record.get("banner", "") or "",
                    "http_title": http_data.get("title", "") or "",
                    "http_server": http_data.get("server", "") or "",
                    "http_status": http_data.get("status_code", "") or "",
                    "asn": location_data.get("asn", "") or "",
                    "country": location_data.get("country", "") or "",
                    "org": location_data.get("organization", "") or "",
                    "source": "Netlas",  # Fixed: was record.get("source", "")
                    "timestamp": record.get("timestamp", "") or ""
                })

            except Exception as e:
                if self.debug:
                    print(f"⚠️ Error parsing Netlas item: {e}")
                continue

        print(f"[DEBUG] Parsed {len(results)} Netlas results")
        return results

    def test_api(self) -> Dict[str, Any]:
        """Test Netlas API with a simple query instead of user endpoint"""
        result = {
            'connected': False,
            'error': None,
            'test_query_result': None
        }

        try:
            if self.debug:
                print("🔍 Netlas: Testing API with simple query...")

            # Test with a simple query instead of user endpoint
            test_response = requests.get(
                f"{self.base_url}/responses",
                headers=self.headers,
                params={
                    "q": "domain:google.com",
                    "size": 1
                },
                timeout=10
            )

            if test_response.status_code == 200:
                result['connected'] = True
                test_data = test_response.json()
                items = test_data.get('items', [])
                result['test_query_result'] = f"Success - {len(items)} items found"

                if self.debug:
                    print(f"✅ Netlas: API test successful - {len(items)} results")

            elif test_response.status_code == 402:
                result['error'] = "Payment required - check your Netlas credits"
            elif test_response.status_code == 429:
                result['error'] = "Rate limit exceeded"
            else:
                result['error'] = f"API returned {test_response.status_code}: {test_response.text}"

        except Exception as e:
            result['error'] = str(e)

        return result

    def is_available(self) -> bool:
        """Check if Netlas service is available and properly configured"""
        test_result = self.test_api()
        return test_result['connected']

    def set_debug(self, debug: bool):
        """Enable or disable debug output"""
        self.debug = debug