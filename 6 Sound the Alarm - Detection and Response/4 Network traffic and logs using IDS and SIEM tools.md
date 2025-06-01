## Logs
### Log
a record of events that occur within an organization's systems.

### Log analysis
The process of examining logs to identify events of interest
  
### Log Types:
- Network: Proxies, firewalls, etc
- System: OS
- Application: Specific programs
- Security: Security tools like IDS / IPS
- Authentication logs: Login attempts

### Log formats
- Syslog (protocol, service, log format)
- JSON (use "{}")
- XML (use tag and "<>")
- CSV (use comma)
- CEF (Common Event Format)

## Intrusion detection systems (IDS)
### Signature Analysis
A detection method used to find events of interest

### Detection tool and techniques
- HIDS: Host-based IDS, installed on a host / endpoint.
- NIDS: Network-based IDS, installed on network tech, monitors all traffic going through.

### Techniques

- Signature analysis: Low false positives, easy to evade.
- Anomaly-based analysis: Can detect new threats, has false positives.

## Components of a NIDS rule
1. Action
   - Determines the action to take if the rule criteria is met
   - Alert, pass, or reject
2. Header: Src / dst IP address / ports / protocols
   - Source and destination IP addresses
   - Source and destination ports
   - Protocols and traffic direction
![](/files/6-4-1.png)
1. Rule options: Additional options, e.g. filtering out noisy service
    ![](/files/6-4-2.png)

## Suricata
### Suricata format type
- EVE JSON - Extensible Event Format JavaScript Object Notation

### Log types
- Alert Logs: signatures
- Network telemetry: network flow
![](/files/6-4-3.png)
>this one shows the detection of malware

## Security information event management (SIEM) tools
### Common Software
- **Splunk**
- **Chronicle** or **Google Security Operations (Google SecOps)**

### Search Processing Language (SPL)
Splunk's query language

### YARA-L (used in Google SecOps)
A computer language used to create rules for searching through ingested log data

Types of search:
1. UDM search
   - **Chronicle** uses UDM to search through normalized data.