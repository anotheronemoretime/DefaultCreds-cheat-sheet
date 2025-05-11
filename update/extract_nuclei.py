#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import yaml
from pathlib import Path
from typing import Dict, List, Optional
from itertools import product
import argparse
import base64
import json
import urllib.parse

class NucleiCredsExtractor:
    def __init__(self, templates_dir: str = "~/nuclei-templates/http/default-logins/", debug: bool = False):
        self.templates_dir = os.path.expanduser(templates_dir)
        self.credentials = []
        self.debug = debug
        self.templates_without_creds = []

    def _clean_value(self, value: str) -> str:
        """Remove surrounding quotes if present and URL decode."""
        if isinstance(value, str):
            # Remove quotes
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            # URL decode
            try:
                value = urllib.parse.unquote(value)
            except Exception:
                pass
        return value

    def _clean_vendor_name(self, vendor: str) -> str:
        """Clean vendor name by removing unwanted references."""
        if not isinstance(vendor, str):
            return "unknown"
            
        # Convert to lowercase
        vendor = vendor.lower()
        
        # Remove unwanted references
        unwanted_refs = [
            "default login",
            "weak credential discovery",
            " admin",
            "default-login",
            "weak-login",
            "default credentials",
            "default credential"
        ]
        
        for ref in unwanted_refs:
            vendor = vendor.replace(ref, "")
            
        # Remove any double spaces and trim
        vendor = " ".join(vendor.split())
        
        return vendor.strip()

    def extract_credentials(self) -> List[Dict]:
        """Extract credentials from all Nuclei templates in the directory and subdirectories."""
        if not os.path.exists(self.templates_dir):
            raise FileNotFoundError(f"Directory not found: {self.templates_dir}")

        # Recursively find all yaml files
        for template_file in Path(self.templates_dir).rglob("*.yaml"):
            try:
                with open(template_file, 'r', encoding='utf-8') as f:
                    template = yaml.safe_load(f)
                
                # Extract vendor from template metadata
                vendor = self._extract_vendor(template)
                
                # Extract credentials from the template
                creds = self._extract_template_credentials(template)
                
                if creds:
                    for cred in creds:
                        cred_dict = {
                            'vendor': vendor,
                            'username': self._clean_value(cred.get('username', '')),
                            'password': self._clean_value(cred.get('password', ''))
                        }
                        if self.debug:
                            cred_dict['template'] = str(template_file.relative_to(self.templates_dir))
                        self.credentials.append(cred_dict)
                else:
                    self.templates_without_creds.append(str(template_file.relative_to(self.templates_dir)))
            
            except Exception as e:
                print(f"Error processing {template_file}: {str(e)}")

        return self.credentials

    def _extract_vendor(self, template: Dict) -> str:
        """Extract vendor name from template metadata."""
        if not isinstance(template, dict):
            return "unknown"

        vendor = "unknown"
        # Try to get vendor from metadata
        if 'info' in template:
            info = template['info']
            # Try name first
            if 'name' in info:
                vendor = info['name'].split(' - ')[0]
            # Then try metadata
            elif 'metadata' in info and 'vendor' in info['metadata']:
                vendor = info['metadata']['vendor']
            # Then try product name
            elif 'metadata' in info and 'product' in info['metadata']:
                vendor = info['metadata']['product']
            # Finally try tags
            elif 'tags' in info and isinstance(info['tags'], list):
                for tag in info['tags']:
                    if tag != 'default-login':
                        vendor = tag
                        break

        return self._clean_vendor_name(vendor)

    def _get_username_field(self, payloads: Dict) -> List[str]:
        """Get username values from various possible field names."""
        # Try different possible field names for username
        for field in ['username', 'user', 'j_username']:
            if field in payloads:
                return payloads[field]
        return ['']

    def _get_password_field(self, payloads: Dict) -> List[str]:
        """Get password values from various possible field names."""
        # Try different possible field names for password
        for field in ['password', 'pass', 'j_password']:
            if field in payloads:
                return payloads[field]
        return ['']

    def _extract_auth_credentials(self, raw_request: str) -> Optional[Dict]:
        """Extract credentials from base64 encoded Authorization header."""
        for line in raw_request.split('\n'):
            if line.lower().startswith('authorization: basic '):
                try:
                    # Extract the base64 encoded part
                    encoded = line.split(' ', 2)[2].strip()
                    # Decode base64
                    decoded = base64.b64decode(encoded).decode('utf-8')
                    # Split username and password
                    username, password = decoded.split(':', 1)
                    return {
                        'username': username,
                        'password': password
                    }
                except Exception:
                    continue
        return None

    def _extract_body_credentials(self, http_section: Dict) -> Optional[Dict]:
        """Extract credentials from HTTP request body."""
        if 'body' in http_section:
            body = http_section['body']
            if isinstance(body, str):
                # Handle JSON format
                if body.strip().startswith('{') and body.strip().endswith('}'):
                    try:
                        data = json.loads(body)
                        # Common JSON field names for username
                        username_fields = ['user', 'username', 'login', 'identity', 'email', 'account']
                        # Common JSON field names for password
                        password_fields = ['password', 'pass', 'secret', 'pwd', 'key']
                        
                        username = None
                        password = None
                        
                        # Try to find username
                        for field in username_fields:
                            if field in data:
                                username = data[field]
                                break
                                
                        # Try to find password
                        for field in password_fields:
                            if field in data:
                                password = data[field]
                                break
                                
                        if username and password:
                            return {
                                'username': username,
                                'password': password
                            }
                    except Exception:
                        pass
                
                # Handle form data format (user=USERID&password=PASSW0RD)
                elif '=' in body and '&' in body:
                    try:
                        params = dict(param.split('=', 1) for param in body.split('&'))
                        username = params.get('user', params.get('username', ''))
                        password = params.get('password', params.get('pass', ''))
                        if username and password:
                            return {
                                'username': username,
                                'password': password
                            }
                    except Exception:
                        pass
        return None

    def _extract_json_credentials(self, content: str) -> Optional[Dict]:
        """Extract credentials from JSON content."""
        try:
            # Find JSON content between empty lines
            json_content = None
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if line.strip().startswith('{') and line.strip().endswith('}'):
                    json_content = line.strip()
                    break
                elif line.strip().startswith('{'):
                    # Multi-line JSON
                    json_lines = [line.strip()]
                    for next_line in lines[i+1:]:
                        json_lines.append(next_line.strip())
                        if next_line.strip().endswith('}'):
                            json_content = ''.join(json_lines)
                            break
                    if json_content:
                        break

            if json_content:
                data = json.loads(json_content)
                # Common JSON field names for username
                username_fields = ['user', 'username', 'login', 'identity', 'email', 'account']
                # Common JSON field names for password
                password_fields = ['password', 'pass', 'secret', 'pwd', 'key']
                
                username = None
                password = None
                
                # Try to find username
                for field in username_fields:
                    if field in data:
                        username = data[field]
                        break
                        
                # Try to find password
                for field in password_fields:
                    if field in data:
                        password = data[field]
                        break
                        
                if username and password:
                    return {
                        'username': username,
                        'password': password
                    }
        except Exception:
            pass
        return None

    def _extract_form_credentials(self, content: str) -> Optional[Dict]:
        """Extract credentials from form-urlencoded content."""
        try:
            # Find form data after empty line
            form_data = None
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if line.strip() == '' and i + 1 < len(lines):
                    form_data = lines[i + 1].strip()
                    break

            if form_data:
                # Parse form data
                params = dict(param.split('=', 1) for param in form_data.split('&'))
                # Common field names for username
                username_fields = [
                    'user', 'username', 'login', 'identity', 'email', 'account', 'Username',
                    'j_username',  # Jenkins
                    'username',    # Generic
                    'userid',      # Generic
                    'login_id',    # Generic
                    'loginname'    # Generic
                ]
                # Common field names for password
                password_fields = [
                    'password', 'pass', 'secret', 'pwd', 'key', 'Password',
                    'j_password',  # Jenkins
                    'passwd',      # Generic
                    'passcode',    # Generic
                    'passphrase'   # Generic
                ]
                
                username = None
                password = None
                
                # Try to find username
                for field in username_fields:
                    if field in params:
                        username = params[field]
                        break
                        
                # Try to find password
                for field in password_fields:
                    if field in params:
                        password = params[field]
                        break
                        
                if username or password:
                    return {
                        'username': username or '',
                        'password': password or ''
                    }
        except Exception:
            pass
        return None

    def _extract_base64_payload_credentials(self, http_section: Dict) -> List[Dict]:
        """Extract credentials from base64 encoded payloads."""
        creds = []
        if 'payloads' in http_section:
            payloads = http_section['payloads']
            for key, values in payloads.items():
                if isinstance(values, list):
                    for value in values:
                        try:
                            # Try to decode base64
                            decoded = base64.b64decode(value).decode('utf-8')
                            # Check if it's in format username:password
                            if ':' in decoded:
                                username, password = decoded.split(':', 1)
                                creds.append({
                                    'username': username,
                                    'password': password
                                })
                        except Exception:
                            continue
        return creds

    def _extract_template_credentials(self, template: Dict) -> List[Dict]:
        """Extract credentials from template content."""
        creds = []
        
        if not isinstance(template, dict):
            return creds

        # First check variables section
        if 'variables' in template:
            variables = template['variables']
            username = variables.get('username', '')
            password = variables.get('password', '')
            if username or password:
                creds.append({
                    'username': username,
                    'password': password
                })
                return creds

        # Then check http section with payloads
        if 'http' in template:
            for http_section in template['http']:
                if isinstance(http_section, dict):
                    # Check for digest credentials
                    if 'digest-username' in http_section and 'digest-password' in http_section:
                        creds.append({
                            'username': http_section['digest-username'],
                            'password': http_section['digest-password']
                        })
                        return creds

                    # Check for base64 encoded payloads
                    base64_creds = self._extract_base64_payload_credentials(http_section)
                    if base64_creds:
                        creds.extend(base64_creds)
                        return creds

                    # Check for payloads
                    if 'payloads' in http_section:
                        payloads = http_section['payloads']
                        
                        # Get usernames and passwords using field name variations
                        usernames = self._get_username_field(payloads)
                        passwords = self._get_password_field(payloads)
                        
                        # Generate all possible combinations
                        for username, password in product(usernames, passwords):
                            creds.append({
                                'username': username,
                                'password': password
                            })
                        if creds:
                            return creds

            # If no credentials found in standard methods, check raw requests
            for http_section in template['http']:
                if isinstance(http_section, dict) and 'raw' in http_section:
                    for raw_request in http_section['raw']:
                        # Check for Authorization header
                        auth_creds = self._extract_auth_credentials(raw_request)
                        if auth_creds:
                            creds.append(auth_creds)
                            return creds
                        
                        # Check for JSON credentials in raw request
                        json_creds = self._extract_json_credentials(raw_request)
                        if json_creds:
                            creds.append(json_creds)
                            return creds

                        # Check for form-urlencoded credentials in raw request
                        form_creds = self._extract_form_credentials(raw_request)
                        if form_creds:
                            creds.append(form_creds)
                            return creds

        return creds

    def display_credentials(self):
        """Display credentials in stdout."""
        if self.debug:
            print("vendor,username,password,template")
            for cred in self.credentials:
                print(f"{cred['vendor']},{cred['username']},{cred['password']},{cred['template']}")
        else:
            #print("vendor,username,password")
            for cred in self.credentials:
                print(f"{cred['vendor']},{cred['username']},{cred['password']}")

        if self.debug and self.templates_without_creds:
            print("\nTemplates without credentials:")
            print("=" * 80)
            for template in self.templates_without_creds:
                print(f"- {template}")
            print("=" * 80)

def main():
    parser = argparse.ArgumentParser(description='Extract credentials from Nuclei templates')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
    args = parser.parse_args()

    extractor = NucleiCredsExtractor(debug=args.debug)
    extractor.extract_credentials()
    extractor.display_credentials()

if __name__ == "__main__":
    main() 