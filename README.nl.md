# Universele ACL Formaat Converter

Een krachtige Python tool voor het converteren van Access Control Lists (ACL's) tussen verschillende netwerkapparatuur formaten.

**Auteur:** Silvester van der Leer  
**Licentie:** GPL v3 (zie LICENSE bestand)

## Ondersteunde Formaten

- **Casa CMTS** - Cable modem termination system formaat
- **Cisco IOS** - Standaard Cisco router/switch ACL formaat  
- **E6000** - Casa Systems E6000 CMTS formaat

## Mogelijkheden

✅ **Universele Conversie** - Converteer tussen alle ondersteunde formaten  
✅ **Automatische Detectie** - Detecteert automatisch het invoerformaat  
✅ **60+ Named Ports** - Volledige ondersteuning voor Cisco/E6000 TCP/UDP poortnamen  
✅ **Multicast Ondersteuning** - Correcte verwerking van multicast IP-adressen  
✅ **Masker Conversie** - Bidirectionele wildcard/subnet masker conversie  
✅ **ICMP Types** - Converteert tussen ICMP type nummers en namen  
✅ **Volgnummers** - E6000 sequence number ondersteuning  
✅ **Lijnnummering** - Toevoegen, verwijderen of hernummeren van ACL regels  
✅ **Match Count Verwijdering** - Verwijdert automatisch Cisco match counts  

## Installatie

```bash
git clone https://github.com/svdleer/acl_convertor.git
cd acl_convertor
```

Geen externe afhankelijkheden vereist - gebruikt alleen Python 3 standaard bibliotheek.

## Gebruik

### Basis Conversie

```bash
# Converteer naar Casa CMTS formaat
python3 acl_converter.py input.acl --casa

# Converteer naar Cisco IOS formaat
python3 acl_converter.py input.acl --cisco

# Converteer naar E6000 formaat
python3 acl_converter.py input.acl --e6000
```

### Geavanceerde Opties

```bash
# Lees van stdin
cat input.acl | python3 acl_converter.py --stdin --cisco

# Opslaan naar uitvoerbestand
python3 acl_converter.py input.acl output.acl --casa

# Verwijder lijnnummers
python3 acl_converter.py input.acl --cisco --remove-lines

# Hernummer regels
python3 acl_converter.py input.acl --casa --renumber --start 100 --increment 10

# E6000 met aangepaste volgnummers
python3 acl_converter.py input.acl --e6000 --start 50 --increment 5
```

## Formaat Voorbeelden

### Casa CMTS Formaat
```
10 remark "Voorbeeld ACL"
20 permit all any 224.0.0.22 0.0.0.0 any any
30 permit bootps any any
40 deny all any 224.0.0.0 31.255.255.255 any any
```

### Cisco IOS Formaat
```
10 remark "Voorbeeld ACL"
20 permit ip any host 224.0.0.22
30 permit udp any eq bootpc any eq bootps
40 deny ip any 224.0.0.0 7.255.255.255
```

### E6000 Formaat
```
configure access-list 100 name cable-inlist-20251022
configure access-list cable-inlist-20251022 10 remark "Voorbeeld ACL"
configure access-list cable-inlist-20251022 20 permit ip any host 224.0.0.22
configure access-list cable-inlist-20251022 30 permit udp any eq bootpc any eq bootps
```

## Named Ports

De converter ondersteunt 60+ Cisco en E6000 named ports:

**TCP Poorten:** bgp, ftp, ssh, telnet, www, smtp, https, msrpc, nntp, en meer  
**UDP Poorten:** bootps, bootpc, tftp, ntp, snmp, netbios-ns, syslog, rip, en meer

*Let op:* Cisco IOS herkent `ssh` niet - het wordt automatisch geconverteerd naar poort 22.

## Multicast Verwerking

- **Casa CMTS:** Gebruikt `all` protocol voor multicast
- **Cisco/E6000:** Gebruikt `ip` protocol voor multicast
- Automatische multicast IP detectie (224.0.0.0-239.255.255.255)

## Licentie

Dit programma is vrije software gelicenseerd onder GPL v3. U mag het vrij gebruiken, wijzigen en distribueren, mits:
- Credits worden gegeven aan de oorspronkelijke auteur: **Silvester van der Leer**
- Eventuele wijzigingen onder GPL v3 blijven
- Zie LICENSE bestand voor volledige voorwaarden

## Bijdragen

Bijdragen zijn welkom! Houd de codekwaliteit aan en voeg tests toe voor nieuwe functies.

## Ondersteuning

Voor problemen of vragen, open een issue op GitHub.

---
**© 2025 Silvester van der Leer**
