# Universal ACL Format Converter

A powerful Python tool for converting Access Control Lists (ACLs) between different network equipment formats.

**Author:** Silvester van der Leer  
**License:** GPL v3 (see LICENSE file)

## Supported Formats

- **Casa CMTS** - Cable modem termination system format
- **Cisco IOS** - Standard Cisco router/switch ACL format  
- **E6000** - Casa Systems E6000 CMTS format

## Features

✅ **Universal Conversion** - Convert between any supported format  
✅ **Auto-Detection** - Automatically detects input format  
✅ **60+ Named Ports** - Full support for Cisco/E6000 TCP/UDP port names  
✅ **Multicast Support** - Proper handling of multicast IP addresses  
✅ **Mask Conversion** - Bidirectional wildcard/subnet mask conversion  
✅ **ICMP Types** - Converts between ICMP type numbers and names  
✅ **Sequence Numbers** - E6000 sequence number support  
✅ **Line Numbering** - Add, remove, or renumber ACL lines  
✅ **Match Count Removal** - Automatically strips Cisco match counts  

## Installation

```bash
git clone https://github.com/svdleer/acl_convertor.git
cd acl_convertor
```

No external dependencies required - uses Python 3 standard library only.

## Usage

### Basic Conversion

```bash
# Convert to Casa CMTS format
python3 acl_converter.py input.acl --casa

# Convert to Cisco IOS format
python3 acl_converter.py input.acl --cisco

# Convert to E6000 format
python3 acl_converter.py input.acl --e6000
```

### Advanced Options

```bash
# Read from stdin
cat input.acl | python3 acl_converter.py --stdin --cisco

# Save to output file
python3 acl_converter.py input.acl output.acl --casa

# Remove line numbers
python3 acl_converter.py input.acl --cisco --remove-lines

# Renumber lines
python3 acl_converter.py input.acl --casa --renumber --start 100 --increment 10

# E6000 with custom sequence numbers
python3 acl_converter.py input.acl --e6000 --start 50 --increment 5
```

## Format Examples

### Casa CMTS Format
```
10 remark "Sample ACL"
20 permit all any 224.0.0.22 0.0.0.0 any any
30 permit bootps any any
40 deny all any 224.0.0.0 31.255.255.255 any any
```

### Cisco IOS Format
```
10 remark "Sample ACL"
20 permit ip any host 224.0.0.22
30 permit udp any eq bootpc any eq bootps
40 deny ip any 224.0.0.0 7.255.255.255
```

### E6000 Format
```
configure access-list 100 name cable-inlist-20251022
configure access-list cable-inlist-20251022 10 remark "Sample ACL"
configure access-list cable-inlist-20251022 20 permit ip any host 224.0.0.22
configure access-list cable-inlist-20251022 30 permit udp any eq bootpc any eq bootps
```

## Named Ports

The converter supports 60+ Cisco and E6000 named ports:

**TCP Ports:** bgp, ftp, ssh, telnet, www, smtp, https, msrpc, nntp, and more  
**UDP Ports:** bootps, bootpc, tftp, ntp, snmp, netbios-ns, syslog, rip, and more

*Note:* Cisco IOS doesn't recognize `ssh` - it's automatically converted to port 22.

## Multicast Handling

- **Casa CMTS:** Uses `all` protocol for multicast
- **Cisco/E6000:** Uses `ip` protocol for multicast
- Automatic multicast IP detection (224.0.0.0-239.255.255.255)

## License

This program is free software licensed under GPL v3. You may use, modify, and distribute it freely, provided that:
- Credits are given to the original author: **Silvester van der Leer**
- Any modifications remain under GPL v3
- See LICENSE file for full terms

## Contributing

Contributions are welcome! Please maintain code quality and add tests for new features.

## Support

For issues or questions, please open an issue on GitHub.

---
**© 2025 Silvester van der Leer**
