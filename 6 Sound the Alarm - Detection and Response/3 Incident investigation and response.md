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

1. Receive and assess
2. Assign priority
3. Collect and analyze
