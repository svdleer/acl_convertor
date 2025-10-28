#!/usr/bin/env python3
"""
Universal ACL Format Converter

Copyright (C) 2025 Silvester van der Leer

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

Credits must be given to the original author: Silvester van der Leer
"""

import re
import sys
import argparse
from typing import List, Tuple, Optional
from datetime import datetime


# Cisco named UDP/TCP ports mapping
CISCO_PORT_NAMES = {
    # UDP ports
    'biff': '512',
    'bootpc': '68',
    'bootps': '67',
    'dnsix': '195',
    'isakmp': '500',
    'mobile-ip': '434',
    'nameserver': '42',
    'netbios-dgm': '138',
    'netbios-ns': '137',
    'netbios-ss': '139',
    'non500-isakmp': '4500',
    'ntp': '123',
    'rip': '520',
    'ripv6': '521',
    'snmp': '161',
    'snmptrap': '162',
    'who': '513',
    'xdmcp': '177',
    # TCP ports
    'bgp': '179',
    'chargen': '19',
    'cmd': '514',
    'daytime': '13',
    'exec': '512',
    'ftp-data': '20',
    'gopher': '70',
    'hostname': '101',
    'ident': '113',
    'irc': '194',
    'klogin': '543',
    'kshell': '544',
    'login': '513',
    'lpd': '515',
    'msrpc': '135',
    'nntp': '119',
    'onep-plain': '15001',
    'onep-tls': '15002',
    'uucp': '540',
    'whois': '43',
    # Shared UDP/TCP ports
    'discard': '9',
    'domain': '53',
    'echo': '7',
    'finger': '79',
    'ftp': '21',
    'pim-auto-rp': '496',
    'pop2': '109',
    'pop3': '110',
    'smtp': '25',
    'sunrpc': '111',
    'syslog': '514',
    'tacacs': '49',
    'talk': '517',
    'telnet': '23',
    'time': '37',
    'www': '80',
    # Additional common ports
    'ssh': '22',
    'http': '80',
    'https': '443',
    'imap': '143',
    'rtsp': '554',
    'tftp': '69'
}

# Reverse mapping: port number to name (for Cisco output)
PORT_NUMBER_TO_NAME = {v: k for k, v in CISCO_PORT_NAMES.items()}


def wildcard_to_subnet_mask(wildcard: str) -> str:
    """Convert Cisco wildcard mask to standard subnet mask."""
    if wildcard == "any":
        return "any"
    
    try:
        octets = wildcard.split('.')
        if len(octets) != 4:
            return wildcard
        
        first_octet = int(octets[0])
        # If it starts with 255, it's already a subnet mask, not a wildcard
        if first_octet >= 128:
            return wildcard
        
        subnet_octets = []
        for octet in octets:
            wild_int = int(octet)
            subnet_int = 255 - wild_int
            subnet_octets.append(str(subnet_int))
        
        return '.'.join(subnet_octets)
    except (ValueError, IndexError):
        return wildcard


def subnet_to_wildcard(subnet: str) -> str:
    """Convert standard subnet mask to Cisco wildcard mask."""
    if subnet == "any":
        return "any"
    try:
        octets = subnet.split('.')
        if len(octets) != 4:
            return subnet
        wildcard_octets = []
        for octet in octets:
            val = int(octet)
            wildcard_octets.append(str(255 - val))
        return '.'.join(wildcard_octets)
    except (ValueError, IndexError):
        return subnet


def convert_protocol_name(protocol: str) -> str:
    """Convert protocol names for Casa CMTS format."""
    protocol_map = {
        # Protocol field conversions
        'ip': 'all',
        'www': 'http',
        
        # Port field conversions (eq statements to numeric ports)
        'eq bootps': '67',
        'eq bootpc': '68', 
        'eq tftp': '69',
        'eq www': '80',
        'eq http': '80',
        'eq time': '37',
        'eq ssh': '22',
        'eq telnet': '23',
        'eq snmp': '161',
        'eq ftp': '21',
        'eq smtp': '25',
        'eq pop2': '109',
        'eq pop3': '110',
        'eq imap': '143',
        'eq finger': '79',
        'eq sunrpc': '111',
        'eq ntp': '123',
        'eq domain': '53',
        'eq rtelnet': '107',
        'eq rtsp': '554',
        'eq telnets': '992',
        'eq edis': '2904',  # EDIS default port
        'eq ipdr': '4737',  # IPDR default port
        'eq ngod': '8080',  # NGOD default port
        
        # Range conversions
        'gt 1023': 'range 1024 65535',
        'range 1023 to 65535': 'range 1024 65535',
        'range 135 to 139': 'range 135 139',
        'range 135 to netbios-ss': 'range 135 139',
    }
    
    return protocol_map.get(protocol, protocol)


def get_casa_supported_protocols():
    """Return the list of Casa CMTS supported protocol names."""
    return {
        'all', 'bootpc', 'bootps', 'edis', 'finger', 'ftp', 'http', 
        'icmp', 'igmp', 'imap', 'ipdr', 'ngod', 'ntp', 'pop2', 'pop3', 
        'rtelnet', 'rtsp', 'smtp', 'snmp', 'ssh', 'sunrpc', 'tcp', 
        'telnet', 'telnets', 'tftp', 'time', 'udp'
    }


def remove_match_count(line: str) -> str:
    """Remove match count information from ACL line."""
    return re.sub(r'\s*\(\d+\s+matches?\)', '', line)


def convert_remark_format(line: str) -> str:
    """Convert remark format from 'remark:' to 'remark "..."'."""
    if 'remark:' in line:
        parts = line.split('remark:', 1)
        if len(parts) == 2:
            line_num = parts[0].strip()
            remark_text = parts[1].strip()
            return f'{line_num} remark "{remark_text}"'
    
    return line


def parse_acl_line(line: str) -> Tuple[Optional[int], str]:
    """Parse an ACL line and extract line number and content."""
    line = line.strip()
    if not line:
        return None, ""
    
    # Check for E6000 format: configure access-list <name> <seq> <content>
    e6000_match = re.match(r'^configure\s+access-list\s+\S+\s+(\d+)\s+(.+)', line)
    if e6000_match:
        return int(e6000_match.group(1)), e6000_match.group(2)
    
    # Check for E6000 initial line: configure access-list 100 name <name>
    if re.match(r'^configure\s+access-list\s+\d+\s+name\s+', line):
        return None, ""  # Skip this line
    
    # Check for standard format with line number
    match = re.match(r'^(\d+)\s+(.+)', line)
    if match:
        return int(match.group(1)), match.group(2)
    else:
        return None, line


def is_multicast_ip(ip: str) -> bool:
    """Check if an IP address is in the multicast range (224.0.0.0-239.255.255.255)."""
    if not re.match(r'\d+\.\d+\.\d+\.\d+', ip):
        return False
    try:
        first_octet = int(ip.split('.')[0])
        return 224 <= first_octet <= 239
    except (ValueError, IndexError):
        return False


def convert_to_casa_format(tokens: List[str]) -> str:
    """
    Convert ACL tokens to Casa CMTS format.
    
    Handles two formats:
    Format 1 (Standard Cisco): permit/deny proto src srcmask dest destmask eq port
    Format 2 (Custom): permit/deny proto src srcmask eq port dest destmask [srcport]
    
    Casa format: permit/deny proto src srcmask dest destmask [srcport destport]
    """
    if len(tokens) < 2:
        return ' '.join(tokens)
    
    action = tokens[0]  # permit/deny
    protocol = tokens[1]
    
    # Casa CMTS uses 'all' instead of 'ip'
    if protocol == 'ip':
        protocol = 'all'
        tokens[1] = 'all'
    
    # Convert protocol name using Casa CMTS supported protocols
    casa_protocols = get_casa_supported_protocols()
    
    if protocol in casa_protocols and protocol not in ['tcp', 'udp', 'all']:
        result_tokens = []
        i = 0
        icmp_type = None
        icmp_type_value = None
        
        while i < len(tokens):
            # Handle ICMP type conversion - move to front
            if (tokens[i] == 'type' or tokens[i] == 'icmptype') and i + 1 < len(tokens):
                icmp_type = 'type'
                icmp_type_value = tokens[i + 1]
                i += 2
                continue
            
            # Handle range conversion
            elif tokens[i] == 'range' and i + 1 < len(tokens):
                if i + 3 < len(tokens) and tokens[i + 2] == 'to':
                    # "range X to Y" format
                    start_port = tokens[i + 1]
                    end_port = tokens[i + 3]
                    
                    # Convert named ports to numbers
                    port_map = {
                        'netbios-ss': '139', 'netbios-ns': '137', 'netbios-dgm': '138',
                        'www': '80', 'http': '80', 'https': '443', 'ssh': '22',
                        'telnet': '23', 'ftp': '21', 'smtp': '25', 'dns': '53',
                        'tftp': '69', 'snmp': '161', 'bootps': '67', 'bootpc': '68'
                    }
                    
                    if start_port in port_map:
                        start_port = port_map[start_port]
                    if end_port in port_map:
                        end_port = port_map[end_port]
                    
                    result_tokens.extend(['range', start_port, end_port])
                    i += 4
                    continue
                elif i + 2 < len(tokens):
                    # "range X Y" format (already correct)
                    result_tokens.extend([tokens[i], tokens[i + 1], tokens[i + 2]])
                    i += 3
                    continue
            
            # Handle wildcard mask conversion
            elif (i > 1 and re.match(r'\d+\.\d+\.\d+\.\d+', tokens[i]) and
                  tokens[i] != "any"):
                # This is an IP address
                result_tokens.append(tokens[i])
                # Check if next token is a potential wildcard mask
                if (i + 1 < len(tokens) and 
                    re.match(r'\d+\.\d+\.\d+\.\d+', tokens[i + 1])):
                    potential_mask = tokens[i + 1]
                    # Convert wildcard to subnet mask
                    subnet_mask = wildcard_to_subnet_mask(potential_mask)
                    result_tokens.append(subnet_mask)
                    i += 2
                else:
                    i += 1
            else:
                result_tokens.append(tokens[i])
                i += 1
        
        # For ICMP, insert type at the beginning after protocol name
        # Ensure protocol token reflects any change (e.g., ip -> all for multicast)
        if len(result_tokens) > 1:
            result_tokens[0] = action
            result_tokens[1] = protocol

        # For ICMP, insert type at the beginning after protocol name
        if icmp_type and icmp_type_value and protocol == 'icmp':
            final_tokens = []
            for j, token in enumerate(result_tokens):
                if j == 1:  # After 'permit/deny icmp'
                    final_tokens.extend([token, icmp_type, icmp_type_value])
                else:
                    final_tokens.append(token)
            return ' '.join(final_tokens)

        return ' '.join(result_tokens)
    
    # Convert basic protocol names
    if protocol == 'ip':
        protocol = 'all'
    
    # Detect format by looking for 'eq' or 'gt' position
    eq_positions = [i for i, token in enumerate(tokens) if token in ['eq', 'gt']]
    
    if len(eq_positions) == 2 and len(tokens) >= 10:
        return handle_dual_port_format(tokens, action, protocol)
    
    # Check for "host" keyword format: action protocol any host X.X.X.X eq port
    if (len(eq_positions) == 1 and 'host' in tokens and 
        len(tokens) >= 7 and tokens[2] == 'any'):
        
        host_pos = tokens.index('host')
        if host_pos + 1 < len(tokens):
            host_ip = tokens[host_pos + 1]
            port_name = tokens[-1]
            
            # Convert named ports to numbers
            numeric_port = CISCO_PORT_NAMES.get(port_name, port_name)
            return f"{action} {protocol} any {host_ip} 255.255.255.255 {numeric_port} any"
    
    if (len(eq_positions) == 1 and len(tokens) >= 6 and 
        tokens[2] == 'any' and tokens[-2] == 'eq'):
        
        dest_ip = tokens[3]
        dest_mask = wildcard_to_subnet_mask(tokens[4]) if tokens[4] != "any" else "any"
        port_name = tokens[-1]
        
        numeric_port = CISCO_PORT_NAMES.get(port_name, port_name)
        return f"{action} {protocol} any {dest_ip} {dest_mask} {numeric_port} any"
    
    if (len(eq_positions) == 1 and len(tokens) >= 6 and 
        tokens[-3] == 'any' and tokens[-2] == 'eq'):
        
        src_ip = tokens[2]
        src_mask = wildcard_to_subnet_mask(tokens[3]) if tokens[3] != "any" else "any"
        port_name = tokens[-1]
        
        # Handle both formats: 6 tokens (no dest) and 8 tokens (with dest)
        if len(tokens) >= 8:  # action protocol src srcmask dest destmask any eq proto
            dest_ip = tokens[4]
            dest_mask = wildcard_to_subnet_mask(tokens[5]) if tokens[5] != "any" else "any"
        else:  # action protocol src srcmask any eq proto
            dest_ip = "any"
            dest_mask = "any"
        
        numeric_port = CISCO_PORT_NAMES.get(port_name, port_name)
        return f"{action} {protocol} {src_ip} {src_mask} {dest_ip} {numeric_port} any"
    
    if not eq_positions:
        # No 'eq' or 'gt' found - basic format, convert protocol and wildcard masks
        # Check if this line involves multicast IPs
        has_multicast = any(is_multicast_ip(token) for token in tokens if re.match(r'\d+\.\d+\.\d+\.\d+', token))
        
        if protocol == 'ip' and has_multicast:
            tokens[1] = 'all'
            protocol = 'all'
        
        result_tokens = []
        i = 0
        icmp_type = None
        icmp_type_value = None
        
        while i < len(tokens):
            # Handle ICMP type conversion - move to front
            if (tokens[i] == 'type' or tokens[i] == 'icmptype') and i + 1 < len(tokens):
                icmp_type = 'type'
                icmp_type_value = tokens[i + 1]
                i += 2
                continue
            
            # Handle range conversion
            elif tokens[i] == 'range' and i + 1 < len(tokens):
                if i + 3 < len(tokens) and tokens[i + 2] == 'to':
                    # "range X to Y" format
                    start_port = tokens[i + 1]
                    end_port = tokens[i + 3]
                    
                    # Convert named ports to numbers
                    port_map = {
                        'netbios-ss': '139', 'netbios-ns': '137', 'netbios-dgm': '138',
                        'www': '80', 'http': '80', 'https': '443', 'ssh': '22',
                        'telnet': '23', 'ftp': '21', 'smtp': '25', 'dns': '53',
                        'tftp': '69', 'snmp': '161', 'bootps': '67', 'bootpc': '68'
                    }
                    
                    if start_port in port_map:
                        start_port = port_map[start_port]
                    if end_port in port_map:
                        end_port = port_map[end_port]
                    
                    result_tokens.extend(['range', start_port, end_port])
                    i += 4
                    continue
                elif i + 2 < len(tokens):
                    # "range X Y" format (already correct)
                    result_tokens.extend([tokens[i], tokens[i + 1], tokens[i + 2]])
                    i += 3
                    continue
            
            # Handle wildcard mask conversion
            elif (i > 1 and re.match(r'\d+\.\d+\.\d+\.\d+', tokens[i]) and
                  tokens[i] != "any"):
                # This is an IP address
                result_tokens.append(tokens[i])
                # Check if next token is a potential wildcard mask
                if (i + 1 < len(tokens) and 
                    re.match(r'\d+\.\d+\.\d+\.\d+', tokens[i + 1])):
                    potential_mask = tokens[i + 1]
                    # Convert wildcard to subnet mask
                    subnet_mask = wildcard_to_subnet_mask(potential_mask)
                    result_tokens.append(subnet_mask)
                    i += 2
                else:
                    i += 1
            else:
                result_tokens.append(tokens[i])
                i += 1
        
        # For ICMP, insert type at the beginning after protocol name
        if icmp_type and icmp_type_value and protocol == 'icmp':
            final_tokens = []
            for j, token in enumerate(result_tokens):
                if j == 1:  # After 'permit/deny icmp'
                    final_tokens.extend([token, icmp_type, icmp_type_value])
                else:
                    final_tokens.append(token)
            return ' '.join(final_tokens)
        
        return ' '.join(result_tokens)
    
    port_keyword_pos = eq_positions[0]
    
    # Use IP pattern detection to determine format intelligently
    # Standard Cisco format: action proto src [srcmask] dest [destmask] eq/gt port
    # Custom format: action proto src [srcmask] eq port dest [destmask] [srcport]
    
    # Check if there are IP addresses AFTER the eq/gt keyword
    # Standard format has NO IPs after eq/gt (just port name/number)
    # Custom format has IP addresses after eq/gt (dest IP and mask)
    
    has_ip_after_eq = False
    for i in range(port_keyword_pos + 2, len(tokens)):  # Skip eq and port name
        if re.match(r'\d+\.\d+\.\d+\.\d+', tokens[i]):
            has_ip_after_eq = True
            break
    
    # Custom format: eq port is followed by destination IP addresses
    if has_ip_after_eq:
        return handle_custom_format(tokens, action, protocol, casa_protocols)
    
    # Standard Cisco format: eq port is at the end (no IPs after)
    else:
        return handle_standard_cisco_format(tokens, action, protocol, casa_protocols)
    
    # Default: pass through with basic conversions
    if protocol == 'ip':
        tokens[1] = 'all'
    return ' '.join(tokens)


def handle_standard_cisco_format(tokens: List[str], action: str, protocol: str, casa_protocols: set) -> str:
    """Handle standard Cisco format: permit proto src srcmask dest destmask eq port"""
    
    if len(tokens) < 8:  # Need at least: action proto src srcmask dest destmask eq port
        return ' '.join(tokens)
    
    # Parse: action proto src srcmask dest destmask eq/gt port
    src_ip = "any"
    src_mask = "any"
    dest_ip = "any"
    dest_mask = "any"
    port_spec = ""
    i = 2  # Start after action and protocol
    
    # Parse source (IP or "host IP" or "any")
    if i < len(tokens):
        if tokens[i] == "host" and i + 1 < len(tokens):
            src_ip = tokens[i + 1]
            src_mask = "255.255.255.255"
            i += 2
        elif tokens[i] == "any":
            src_ip = "any"
            src_mask = "any"
            i += 1
        elif re.match(r'\d+\.\d+\.\d+\.\d+', tokens[i]):
            src_ip = tokens[i]
            i += 1
            # Check for source mask
            if i < len(tokens) and re.match(r'\d+\.\d+\.\d+\.\d+', tokens[i]):
                src_mask = wildcard_to_subnet_mask(tokens[i])
                i += 1
            else:
                src_mask = "255.255.255.255"  # Default host mask
    
    # Parse destination (IP or "host IP" or "any")
    if i < len(tokens):
        if tokens[i] == "host" and i + 1 < len(tokens):
            dest_ip = tokens[i + 1]
            dest_mask = "255.255.255.255"
            i += 2
        elif tokens[i] == "any":
            dest_ip = "any"
            dest_mask = "any"
            i += 1
        elif re.match(r'\d+\.\d+\.\d+\.\d+', tokens[i]):
            dest_ip = tokens[i]
            i += 1
            # Check for destination mask
            if i < len(tokens) and re.match(r'\d+\.\d+\.\d+\.\d+', tokens[i]):
                dest_mask = wildcard_to_subnet_mask(tokens[i])
                i += 1
            else:
                dest_mask = "255.255.255.255"  # Default host mask
    
    # Parse port specification (after 'eq' or 'gt')
    if i < len(tokens) and tokens[i] in ['eq', 'gt'] and i + 1 < len(tokens):
        port_keyword = tokens[i]   # 'eq' or 'gt'
        port_value = tokens[i + 1]
        
        if port_keyword == 'eq':
            # Convert to named protocol ONLY for well-known Casa CMTS protocols
            casa_named_protocols = {
                ('tcp', '80'): 'http', ('tcp', 'www'): 'http', ('tcp', 'http'): 'http',
                ('tcp', '22'): 'ssh', ('tcp', 'ssh'): 'ssh',
                ('tcp', '23'): 'telnet', ('tcp', 'telnet'): 'telnet',
                ('tcp', '21'): 'ftp', ('tcp', 'ftp'): 'ftp',
                ('tcp', '25'): 'smtp', ('tcp', 'smtp'): 'smtp',
                ('udp', '67'): 'bootps', ('udp', 'bootps'): 'bootps',
                ('udp', '68'): 'bootpc', ('udp', 'bootpc'): 'bootpc',
                ('udp', '69'): 'tftp', ('udp', 'tftp'): 'tftp',
                ('udp', '37'): 'time', ('udp', 'time'): 'time',
                ('udp', '161'): 'snmp', ('udp', 'snmp'): 'snmp',
                ('udp', '123'): 'ntp', ('udp', 'ntp'): 'ntp'
            }
            
            named_protocol = casa_named_protocols.get((protocol, port_value))
            if named_protocol:
                return f"{action} {named_protocol} {src_ip} {src_mask} {dest_ip} {dest_mask}"
            
            numeric_port = CISCO_PORT_NAMES.get(port_value, port_value)
            if src_ip != "any" and dest_ip != "any":
                return f"{action} {protocol} {src_ip} {src_mask} {dest_ip} {dest_mask} {numeric_port} any"
        
        elif port_keyword == 'gt':
            if port_value == '1023':
                port_spec = "range 1023 65535"
            else:
                port_spec = f"range {port_value} 65535"
            
            # Build result with range
            if src_ip != "any" and dest_ip != "any":
                return f"{action} {protocol} {src_ip} {src_mask} {dest_ip} {dest_mask} {port_spec}"
    
    # Default return without port specification
    return f"{action} {protocol} {src_ip} {src_mask} {dest_ip} {dest_mask}"


def handle_dual_port_format(tokens: List[str], action: str, protocol: str) -> str:
    """Handle format: action protocol src srcmask gt/eq port1 dest destmask gt/eq port2"""
    
    src_ip = tokens[2]
    src_mask = wildcard_to_subnet_mask(tokens[3]) if tokens[3] != "any" else "any"
    
    port1_keyword = tokens[4]  # gt or eq
    port1_value = tokens[5]
    
    dest_ip = tokens[6] 
    dest_mask = wildcard_to_subnet_mask(tokens[7]) if tokens[7] != "any" else "any"
    
    port2_keyword = tokens[8]  # gt or eq  
    port2_value = tokens[9]
    
    # Convert ports based on keywords
    if port1_keyword == 'gt':
        if port1_value == '1023':
            src_port_spec = "range 1023 65535"
        else:
            src_port_spec = f"range {port1_value} 65535"
    else:  # eq
        src_port_spec = port1_value
        
    if port2_keyword == 'gt':
        if port2_value == '1023':
            dest_port_spec = "range 1023 65535"
        else:
            dest_port_spec = f"range {port2_value} 65535"
    else:  # eq
        dest_port_spec = port2_value
    
    return f"{action} {protocol} {src_ip} {src_mask} {dest_ip} {dest_mask} {dest_port_spec} {src_port_spec}"


def handle_custom_format(tokens: List[str], action: str, protocol: str, casa_protocols: set) -> str:
    """Handle custom format: permit proto src srcmask eq port dest destmask [srcport]"""
    
    if len(tokens) < 7:
        return ' '.join(tokens)
    
    # Parse: action proto srcip srcmask eq port destip destmask [srcport]
    src_ip = "any"
    src_mask = "any"
    dest_ip = "any"
    dest_mask = "any" 
    src_port = "any"
    dest_port = ""
    i = 2  # Start after action and protocol
    
    # Parse source (IP or "host IP" or "any")
    if i < len(tokens):
        if tokens[i] == "host" and i + 1 < len(tokens):
            src_ip = tokens[i + 1]
            src_mask = "255.255.255.255"
            i += 2
        elif tokens[i] == "any":
            src_ip = "any"
            src_mask = "any"
            i += 1
        elif re.match(r'\d+\.\d+\.\d+\.\d+', tokens[i]):
            src_ip = tokens[i]
            i += 1
            # Check for source mask
            if i < len(tokens) and re.match(r'\d+\.\d+\.\d+\.\d+', tokens[i]):
                src_mask = wildcard_to_subnet_mask(tokens[i])
                i += 1
            else:
                src_mask = "255.255.255.255"  # Default host mask
    
    # Parse destination port (after 'eq')
    if i < len(tokens) and tokens[i] == 'eq' and i + 1 < len(tokens):
        port_name = tokens[i + 1]
        i += 2
        
        # Convert named ports to numbers
        port_map = {
            'www': '80', 'http': '80', 'https': '443', 'ssh': '22',
            'telnet': '23', 'ftp': '21', 'smtp': '25', 'dns': '53',
            'tftp': '69', 'snmp': '161', 'bootps': '67', 'bootpc': '68',
            'time': '37', 'pop2': '109', 'pop3': '110', 'imap': '143',
            'sunrpc': '111', 'rtelnet': '107', 'rtsp': '554',
            'telnets': '992', 'domain': '53', 'finger': '79', 'ntp': '123'
        }
        dest_port = port_map.get(port_name, port_name)
    
    # Parse destination (IP or "host IP" or "any")
    if i < len(tokens):
        if tokens[i] == "host" and i + 1 < len(tokens):
            dest_ip = tokens[i + 1]
            dest_mask = "255.255.255.255"
            i += 2
        elif tokens[i] == "any":
            dest_ip = "any"
            dest_mask = "any"
            i += 1
        elif re.match(r'\d+\.\d+\.\d+\.\d+', tokens[i]):
            dest_ip = tokens[i]
            i += 1
            # Check for destination mask
            if i < len(tokens) and re.match(r'\d+\.\d+\.\d+\.\d+', tokens[i]):
                dest_mask = wildcard_to_subnet_mask(tokens[i])
                i += 1
            else:
                dest_mask = "255.255.255.255"  # Default host mask
    
    # Parse source port (last position)
    if i < len(tokens):
        src_port = tokens[i]
    
    # Check if we should convert to named protocol 
    dest_port_was_named = not (tokens[5].isdigit() if len(tokens) > 5 else True)
    
    if (dest_port.isdigit() and src_port == "any" and 
        src_ip != "any" and dest_ip != "any" and not dest_port_was_named):
        
        protocol_port_map = {
            ('tcp', '80'): 'http', ('tcp', '22'): 'ssh', ('tcp', '23'): 'telnet',
            ('tcp', '21'): 'ftp', ('tcp', '25'): 'smtp', ('tcp', '992'): 'telnets',
            ('udp', '67'): 'bootps', ('udp', '68'): 'bootpc', ('udp', '69'): 'tftp',
            ('udp', '37'): 'time', ('udp', '161'): 'snmp', ('udp', '123'): 'ntp',
            ('tcp', '143'): 'imap', ('tcp', '109'): 'pop2', ('tcp', '110'): 'pop3',
            ('tcp', '79'): 'finger', ('tcp', '111'): 'sunrpc', ('tcp', '554'): 'rtsp'
        }
        
        named_protocol = protocol_port_map.get((protocol, dest_port))
        if named_protocol:
            return f"{action} {named_protocol} {src_ip} {src_mask} {dest_ip} {dest_mask}"
    
    # Build result with ports
    has_specific_src = (src_ip != "any")
    has_specific_dest = (dest_ip != "any")
    
    if has_specific_src and has_specific_dest and (src_port != "any" or dest_port != "any"):
        return f"{action} {protocol} {src_ip} {src_mask} {dest_ip} {dest_mask} {src_port} {dest_port}"
    
    return f"{action} {protocol} {src_ip} {src_mask} {dest_ip} {dest_mask}"


def convert_acl_line(line: str, remove_line_numbers: bool = False, 
                    start_line_num: int = 10, line_increment: int = 10) -> str:
    """Convert a single ACL line to Casa CMTS format."""
    original_line = line.strip()
    
    # Handle comment lines (starting with !) - pass through as-is
    if original_line.startswith('!'):
        return original_line
    
    # Remove match counts first
    line = remove_match_count(line)
    
    # Convert remark format
    line = convert_remark_format(line)
    
    # Parse line number and content
    line_num, content = parse_acl_line(line)
    
    if not content:
        return ""
    
    # Split content into tokens, but preserve inline comments
    inline_comment = ""
    if '!' in content:
        parts = content.split('!', 1)
        content = parts[0].strip()
        if len(parts) > 1:
            inline_comment = f" ! {parts[1].strip()}"
    
    tokens = content.split()
    if not tokens:
        return ""
    
    # Handle different ACL statement types
    if tokens[0] == 'remark':
        # Remark statements - ensure proper quoting
        if len(tokens) > 1:
            remark_text = ' '.join(tokens[1:])
            if not (remark_text.startswith('"') and remark_text.endswith('"')):
                cleaned_text = remark_text.strip('\'"')
                remark_text = f'"{cleaned_text}"'
            content = f'remark {remark_text}'
        else:
            content = 'remark ""'
    
    elif tokens[0] in ['permit', 'deny']:
        # Handle "deny any IP mask" format first
        if (len(tokens) >= 4 and tokens[1] == 'any' and 
            re.match(r'\d+\.\d+\.\d+\.\d+', tokens[2]) and 
            re.match(r'\d+\.\d+\.\d+\.\d+', tokens[3])):
            
            dest_ip = tokens[2]
            dest_mask = wildcard_to_subnet_mask(tokens[3])
            content = f'{tokens[0]} all any any {dest_ip} {dest_mask}'
        
        # Handle special DHCP case
        elif (len(tokens) >= 7 and tokens[1] == 'udp' and tokens[2] == 'any' and 
              tokens[3] == 'eq' and tokens[4] == 'bootpc' and 
              tokens[5] == 'any' and tokens[6] == 'eq' and 
              len(tokens) > 7 and tokens[7] == 'bootps'):
            content = f'{tokens[0]} bootps any any'
        # Handle basic deny/permit proto any any eq port format
        elif (len(tokens) >= 6 and tokens[2] == 'any' and tokens[3] == 'any' and 
              tokens[4] == 'eq' and len(tokens) > 5):
            protocol = tokens[1]
            port_name = tokens[5]
            
            # Convert to named protocol if possible
            protocol_port_map = {
                ('udp', 'snmp'): 'snmp', ('udp', '161'): 'snmp',
                ('tcp', 'www'): 'http', ('tcp', 'http'): 'http', ('tcp', '80'): 'http',
                ('tcp', 'ssh'): 'ssh', ('tcp', '22'): 'ssh',
                ('tcp', 'telnet'): 'telnet', ('tcp', '23'): 'telnet',
                ('tcp', 'ftp'): 'ftp', ('tcp', '21'): 'ftp',
                ('tcp', 'smtp'): 'smtp', ('tcp', '25'): 'smtp',
                ('udp', 'bootps'): 'bootps', ('udp', '67'): 'bootps',
                ('udp', 'bootpc'): 'bootpc', ('udp', '68'): 'bootpc',
                ('udp', 'tftp'): 'tftp', ('udp', '69'): 'tftp',
                ('udp', 'time'): 'time', ('udp', '37'): 'time'
            }
            
            named_protocol = protocol_port_map.get((protocol, port_name))
            if named_protocol:
                content = f'{tokens[0]} {named_protocol} any any'
            else:
                # Convert named ports to numbers
                numeric_port = CISCO_PORT_NAMES.get(port_name, port_name)
                content = f'{tokens[0]} {protocol} any any {numeric_port} any'
        else:
            # Convert to Casa CMTS format
            content = convert_to_casa_format(tokens)
    
    # Add back inline comment if it existed
    content += inline_comment
    
    # Handle line numbering
    if remove_line_numbers:
        return content
    else:
        if line_num is not None:
            return f"{line_num} {content}"
        else:
            return content


def convert_acl_file(input_text: str, remove_line_numbers: bool = False,
                    renumber_lines: bool = False, start_line: int = 10,
                    line_increment: int = 10, version: str = None) -> str:
    """Convert an entire ACL configuration to Casa CMTS format."""
    lines = input_text.strip().split('\n')
    converted_lines = []
    current_line_num = start_line
    
    # Add date header remark at the beginning
    today = version if version else datetime.now().strftime('%Y%m%d')
    date_remark = f'remark "cable-inlist version {today}"'
    if not remove_line_numbers:
        date_remark = f"{current_line_num} {date_remark}"
        current_line_num += line_increment
    converted_lines.append(date_remark)
    
    for line in lines:
        if not line.strip():
            continue
            
        converted = convert_acl_line(line, remove_line_numbers, start_line, line_increment)
        
        if converted:
            if renumber_lines and not remove_line_numbers:
                _, content = parse_acl_line(converted)
                if content:
                    converted = f"{current_line_num} {content}"
                    current_line_num += line_increment
            
            converted_lines.append(converted)
    
    # Combine consecutive remark lines
    converted_lines = combine_consecutive_remarks(converted_lines)
    
    return '\n'.join(converted_lines)


def combine_consecutive_remarks(lines: List[str]) -> List[str]:
    """Keep remark lines separate (combining disabled)."""
    return lines


def convert_to_cisco_format(lines: List[str], remove_line_numbers: bool = False, 
                            renumber_lines: bool = False, start_line: int = 10, 
                            line_increment: int = 10, version: str = None) -> str:
    """Convert ACL to standard Cisco format."""
    converted_lines = []
    current_line_num = start_line
    
    # Add date header remark at the beginning
    today = version if version else datetime.now().strftime('%Y%m%d')
    date_remark = f'remark "cable-inlist version {today}"'
    if not remove_line_numbers:
        date_remark = f"{current_line_num} {date_remark}"
        current_line_num += line_increment
    converted_lines.append(date_remark)
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        # Remove match counts
        line = remove_match_count(line)
        
        # Parse the line
        line_num, content = parse_acl_line(line)
        
        if not content:
            continue
        
        # Convert to Cisco format (basically clean up and standardize)
        tokens = content.split()
        
        if not tokens:
            continue
        
        # Handle remark format: normalize and wrap remark text in double quotes
        if tokens[0] == 'remark' or (len(tokens) > 1 and tokens[0].endswith(':') and 'remark' in tokens[0]):
            # Extract remark text after 'remark:' or following the 'remark' token
            if 'remark:' in content:
                parts = content.split('remark:', 1)
                remark_text = parts[1].strip() if len(parts) > 1 else ''
            else:
                # Join tokens after the 'remark' token
                remark_text = ' '.join(tokens[1:]).strip()

            # Strip surrounding quotes if present and then re-wrap with double quotes
            if remark_text.startswith('"') and remark_text.endswith('"'):
                remark_text = remark_text[1:-1]
            remark_text = remark_text.strip()
            content = f'remark "{remark_text}"'
        else:
            # Process non-remark lines for Cisco compatibility
            result_tokens = []
            i = 0
            
            # Get protocol for range handling (tokens[1] after permit/deny)
            protocol = tokens[1] if len(tokens) > 1 else None
            
            while i < len(tokens):
                token = tokens[i]
                
                # Handle range with 'to': range X to Y
                if token == 'range' and i + 3 < len(tokens) and tokens[i + 2] == 'to':
                    start_port = tokens[i + 1]
                    end_port = tokens[i + 3]
                    # For UDP: convert start port name to number
                    # For TCP: keep start port name
                    if protocol == 'udp' and start_port in CISCO_PORT_NAMES:
                        start_port = CISCO_PORT_NAMES[start_port]
                    # End port can remain as name
                    result_tokens.extend([token, start_port, end_port])
                    i += 4
                    continue
                
                # Handle range without 'to': range X Y
                if token == 'range' and i + 2 < len(tokens):
                    start_port = tokens[i + 1]
                    end_port = tokens[i + 2]
                    # For UDP: convert start port name to number
                    # For TCP: keep start port name
                    if protocol == 'udp' and start_port in CISCO_PORT_NAMES:
                        start_port = CISCO_PORT_NAMES[start_port]
                    # End port can remain as name
                    result_tokens.extend([token, start_port, end_port])
                    i += 3
                    continue
                
                if token == 'eq' and i + 1 < len(tokens):
                    next_token = tokens[i + 1]
                    if next_token == 'ssh':
                        result_tokens.extend([token, '22'])
                        i += 2
                        continue
                
                if token == 'icmptype' and i + 1 < len(tokens):
                    icmp_type_to_name = {
                        '0': 'echo-reply',
                        '3': 'unreachable',
                        '8': 'echo',
                        '11': 'time-exceeded'
                    }
                    next_token = tokens[i + 1]
                    if next_token in icmp_type_to_name:
                        result_tokens.append(icmp_type_to_name[next_token])
                        i += 2
                        continue
                    else:
                        # Keep icmptype with number if not in map
                        result_tokens.extend([token, next_token])
                        i += 2
                        continue
                
                if (i > 0 and re.match(r'\d+\.\d+\.\d+\.\d+', token) and 
                    i + 1 < len(tokens) and tokens[i + 1] == '255.255.255.255'):
                    result_tokens.extend(['host', token])
                    i += 2
                    continue
                
                if (i > 0 and re.match(r'\d+\.\d+\.\d+\.\d+', token) and 
                    i + 1 < len(tokens) and re.match(r'\d+\.\d+\.\d+\.\d+', tokens[i + 1]) and
                    tokens[i + 1] != '255.255.255.255'):
                    # Check if next token is a subnet mask
                    next_token = tokens[i + 1]
                    octets = next_token.split('.')
                    if len(octets) == 4:
                        try:
                            first_octet = int(octets[0])
                            
                            # Special handling for multicast subnet mask 240.0.0.0 (RFC 3171: 224.0.0.0/4)
                            if next_token == '240.0.0.0':
                                # Convert to wildcard: 255 - 240 = 15
                                wildcard = '15.255.255.255'
                                result_tokens.extend([token, wildcard])
                                i += 2
                                continue
                            
                            # Only convert if it starts with 255 (actual subnet mask)
                            # Wildcard masks start with 0-31 typically
                            if first_octet == 255:
                                # This is a subnet mask - convert to wildcard
                                wildcard_octets = [str(255 - int(o)) for o in octets]
                                wildcard = '.'.join(wildcard_octets)
                                result_tokens.extend([token, wildcard])
                                i += 2
                                continue
                        except ValueError:
                            pass
                
                result_tokens.append(token)
                i += 1
            
            # Convert 'all' back to 'ip'
            if len(result_tokens) > 1 and result_tokens[1] == 'all':
                result_tokens[1] = 'ip'
            
            if (len(result_tokens) >= 3 and result_tokens[0] in ['deny', 'permit'] and 
                result_tokens[1] == 'any' and re.match(r'\d+\.\d+\.\d+\.\d+', result_tokens[2])):
                # Insert 'ip any' after action
                result_tokens = [result_tokens[0], 'ip', 'any'] + result_tokens[2:]
            
            if (len(result_tokens) > 4 and result_tokens[-1] == 'any' and result_tokens[-2] == 'any'):
                result_tokens = result_tokens[:-2]
            
            content = ' '.join(result_tokens)
        
        if renumber_lines and not remove_line_numbers:
            content = f"{current_line_num} {content}"
            current_line_num += line_increment
        elif not remove_line_numbers and line_num:
            content = f"{line_num} {content}"
        
        converted_lines.append(content)
    
    return '\n'.join(converted_lines)


def convert_to_e6000_format(lines: List[str], remove_line_numbers: bool = False, 
                            renumber_lines: bool = False, start_line: int = 10, 
                            line_increment: int = 10, version: str = None) -> str:
    """Convert ACL to E6000 format with configure statements and sequence numbers."""
    converted_lines = []
    current_line_num = start_line
    sequence_num = start_line
    
    # Generate ACL name with today's date
    today = version if version else datetime.now().strftime('%Y%m%d')
    acl_name = f"cable-inlist-{today}"
    
    # Add initial configure statement
    converted_lines.append(f"configure access-list 100 name {acl_name}")
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        # Remove match counts
        line = remove_match_count(line)
        
        # Parse the line
        line_num, content = parse_acl_line(line)
        
        if not content:
            continue
        
        # Convert to E6000 format
        tokens = content.split()
        
        if not tokens:
            continue
        
        # Handle remark format: wrap in quotes
        if tokens[0] == 'remark' or (len(tokens) > 1 and tokens[0].endswith(':') and 'remark' in tokens[0]):
            # Extract remark text
            if 'remark:' in content:
                parts = content.split('remark:', 1)
                remark_text = parts[1].strip() if len(parts) > 1 else ''
            else:
                remark_text = ' '.join(tokens[1:]).strip()
            
            # Strip surrounding quotes if present and re-wrap
            if remark_text.startswith('"') and remark_text.endswith('"'):
                remark_text = remark_text[1:-1]
            remark_text = remark_text.strip()
            content = f'remark "{remark_text}"'
        else:
            # Process non-remark lines
            result_tokens = []
            i = 0
            
            while i < len(tokens):
                token = tokens[i]
                
                # Remove 'to' from range statements
                if token == 'range' and i + 3 < len(tokens) and tokens[i + 2] == 'to':
                    result_tokens.extend([token, tokens[i + 1], tokens[i + 3]])
                    i += 4
                    continue
                
                # E6000 supports ssh as a named port, so don't convert it
                
                # Convert icmptype numbers to names
                if token == 'icmptype' and i + 1 < len(tokens):
                    icmp_type_to_name = {
                        '0': 'echo-reply',
                        '3': 'unreachable',
                        '8': 'echo',
                        '11': 'time-exceeded'
                    }
                    next_token = tokens[i + 1]
                    if next_token in icmp_type_to_name:
                        result_tokens.append(icmp_type_to_name[next_token])
                        i += 2
                        continue
                    else:
                        result_tokens.extend([token, next_token])
                        i += 2
                        continue
                
                result_tokens.append(token)
                i += 1
            
            # Convert 'all' back to 'ip'
            if len(result_tokens) > 1 and result_tokens[1] == 'all':
                result_tokens[1] = 'ip'
            
            content = ' '.join(result_tokens)
        
        # Prefix each line with configure statement and optionally sequence number
        if remove_line_numbers:
            line_content = f"configure access-list {acl_name} {content}"
        else:
            line_content = f"configure access-list {acl_name} {sequence_num} {content}"
            sequence_num += line_increment
        converted_lines.append(line_content)
    
    return '\n'.join(converted_lines)


def main():
    parser = argparse.ArgumentParser(
        description="Universal ACL Format Converter - Convert between Casa CMTS, Cisco IOS, and E6000 ACL formats",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s input.txt --casa              # Convert to Casa CMTS format
  %(prog)s input.txt --cisco             # Convert to standard Cisco format
  %(prog)s input.txt output.txt --casa   # Convert and save to output file
  %(prog)s --stdin --casa                # Read from stdin
  %(prog)s input.txt --remove-lines --casa     # Remove line numbers
  %(prog)s input.txt --renumber --start 170 --increment 10 --casa  # Renumber lines
        """
    )
    
    parser.add_argument('input_file', nargs='?', help='Input ACL file')
    parser.add_argument('output_file', nargs='?', help='Output file (optional)')
    parser.add_argument('--stdin', action='store_true', help='Read from stdin')
    parser.add_argument('--casa', action='store_true', 
                       help='Convert to Casa CMTS format (default)')
    parser.add_argument('--cisco', action='store_true',
                       help='Convert to standard Cisco ACL format')
    parser.add_argument('--e6000', action='store_true',
                       help='Convert to E6000 format with configure statements')
    parser.add_argument('--remove-lines', action='store_true', 
                       help='Remove line numbers from output')
    parser.add_argument('--renumber', action='store_true',
                       help='Renumber lines sequentially')
    parser.add_argument('--start', type=int, default=10,
                       help='Starting line number for renumbering (default: 10)')
    parser.add_argument('--increment', type=int, default=10,
                       help='Line number increment (default: 10)')
    parser.add_argument('--version', type=str, default=None,
                       help='Override version date (format: YYYYMMDD, default: today)')
    
    args = parser.parse_args()
    
    # Default to Casa format if none is specified
    if not args.casa and not args.cisco and not args.e6000:
        args.casa = True
    
    # Validate that only one format is specified
    format_count = sum([args.casa, args.cisco, args.e6000])
    if format_count > 1:
        parser.error("Cannot specify multiple output formats (--casa, --cisco, --e6000)")
    
    # Validate arguments
    if not args.stdin and not args.input_file:
        parser.error("Must specify input file or --stdin")
    
    # Read input
    try:
        if args.stdin:
            input_text = sys.stdin.read()
        else:
            with open(args.input_file, 'r') as f:
                input_text = f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{args.input_file}' not found", file=sys.stderr)
        return 1
    except IOError as e:
        print(f"Error reading input: {e}", file=sys.stderr)
        return 1
    
    # Convert ACL
    try:
        if args.cisco:
            # Convert to standard Cisco format
            lines = input_text.strip().split('\n')
            converted = convert_to_cisco_format(
                lines,
                remove_line_numbers=args.remove_lines,
                renumber_lines=args.renumber,
                start_line=args.start,
                line_increment=args.increment,
                version=args.version
            )
        elif args.e6000:
            # Convert to E6000 format
            lines = input_text.strip().split('\n')
            converted = convert_to_e6000_format(
                lines,
                remove_line_numbers=args.remove_lines,
                renumber_lines=args.renumber,
                start_line=args.start,
                line_increment=args.increment,
                version=args.version
            )
        else:
            # Convert to Casa CMTS format (default)
            converted = convert_acl_file(
                input_text,
                remove_line_numbers=args.remove_lines,
                renumber_lines=args.renumber,
                start_line=args.start,
                line_increment=args.increment,
                version=args.version
            )
    except Exception as e:
        print(f"Error converting ACL: {e}", file=sys.stderr)
        return 1
    
    # Write output
    try:
        if args.output_file:
            with open(args.output_file, 'w') as f:
                f.write(converted + '\n')
            print(f"Converted ACL written to '{args.output_file}'")
        else:
            print(converted)
    except IOError as e:
        print(f"Error writing output: {e}", file=sys.stderr)
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())