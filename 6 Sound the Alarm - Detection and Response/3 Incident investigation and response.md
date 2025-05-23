## The detection and analysis phase of the lifecycle
Challenges in the detection and analysis phase
- Impossible to detect everything
- High volumes of alerts (false positive)

### Indicators

- Indicators of Compromise: Observable evidence that suggests potential security incident.
- Indicators of Attack: Series of events that suggest real time incident.

> Essentially, IoCs help to identify the who and what of an attack after it's taken place, while IoAs focus on finding the why and how of an ongoing or unknown attack. For example, observing a process that makes a network connection is an example of an IoA. The filename of the process and the IP address that the process contacted are examples of the related IoCs.

## Pyramid of pain

Higher on the IoC pyramid = harder for an attacker to work around any blocks.

TTP = Tactics, techniques, and procedures.

![](/files/pyramidofpain.png)

## Analyze indicators of compromise with investigative tools
- VirusTotal - free service to analyze suspicious files, domains, URLs and IP addresses.
- Jotti malware scan (scan files)
- Urlscan.io (scans and analyzes URLs)
- MalwareBazaar (free malware samples)

## Documentation

3 benefits:

1. Transparency (chain of custody)
2. Standardization (incident response plan)
3. Clarity

## Triage
**Triage** the prioritzing of incidents according to their level of importance or urgency
1. Receive and assess. (IDS)
2. Assign priority (functional impact, information impact, recoverability)
3. Collect and analyze (gather info from different sources to make informed decision)

## Containment
**Containment**: The act of limiting and preventing additional damage caused by an incident

**Eradication**: The complete removal of the incident elements from all affected systems
- e.g. perform vulnerability test, apply patches

**Recovery**: The process of returning affected systems back to normal operations

## Post-incident activity phase
- **Post-incident activity phase**: The process of reviewing an incident to identify areas for improvement during incident handling
- **Final report**: Documentation that provides a comprehensive review of an incident
