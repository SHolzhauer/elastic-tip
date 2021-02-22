# Elastic Threat Intelligence Platform (elastic-tip)
Elastic TIP is a python tool which automates the process of aggregating Threat Intelligence and ingesting
the intelligence into a common format into Elasticsearch with the main goal of being used by the Security
solution.

The intelligence ingested by elastic-tip is meant to be used by the [threat matching](https://github.com/elastic/kibana/pull/78955)
detection rule type.

## Recommended usage
I build this tool to work together with the "threat matching" detection capability of the Elastic stack.
For this the recommended usage is to periodically run the tool with the modules you want and setup a threat matching
rule to match against the `elatic-tip` index.

## CLI
```bash
python3 tip/elastic_tip_cli.py help

Elastic Threat Intelligence Platform
                            ----------------------
                                 community project
==================================================

python tip/elastic_tip_cli.py [command] [options]

Commands:
    help           Print this help output
    run            Run the platform and ingest IOC's into ElasticSearch
    init           Initilize for the first time and load the full IOC lists into ElasticSearch
    verify         Verify the ElasticSearch index and connection

==================================================
Author   Stijn Holzhauer
Website  https://github.com/SHolzhauer/elastic-tip
```

#### Run
The run command can be used to run elastic-tip to gather and ingest threat intelligence into Elasticsearch index

```bash
python tip/elastic_tip_cli.py run -e localhost -m * --tls
```

**Help**
```bash
Elastic Threat Intelligence Platform
                            ----------------------
                                 community project
==================================================

python tip/elastic_tip_cli.py run [options]

    The run command is used to run the Elastic Threat Intelligence Platform and load
    the Threat Intelligence, in the form of Indicators Of Compromise (IOC) into
    your ElasticSearch cluster to be used by the build in Detection-Engine

Options
    -h, --help                Print help output
    -e, --es-hosts <value>    Comma seperated list of Elasticsearch hosts to use
    -u, --user <value>        Username to use for Authentication to ES
    -p, --passwd <value>      Password to use for Authentication to ES
    --modules-list            List module names and the reference link
    -m, --modules <values>    Modules to enable (* for all):
                                  URLhaus
                                  MalwareBazaar
                                  FeodoTracker
                                  SSLBlacklist
                                  EmergingThreats-Blocklist
                                  ESET-MalwareIOC
    -T, --tls                 Use TLS/SSL when connecting to Elasticsearch
    -c, --ca-cert <value>     Use the cert specified by path
    --no-verify               Don't verify the TLS/SSL certificate

==================================================
Author   Stijn Holzhauer
Website  https://github.com/SHolzhauer/elastic-tip
```

## Feeds
Elastic-TIP supports multiple threat intelligence feeds, it currently supports:

_for the exact feed url's look at the `event.reference` field_

| Module name | name | url | note |
|-------------|------|-----|------|
| URLhaus | Abuse.ch URLhaus | https://urlhaus.abuse.ch/ | |
| MalwareBazaar | Abuse.ch MalwareBazaar | https://bazaar.abuse.ch/ | |
| FeodoTracker | Abuse.ch FeodoTracker | https://feodotracker.abuse.ch/ | |
| SSLBlacklist | Abuse.ch SSLBlacklist | https://sslbl.abuse.ch/ | |
| EmergingThreats-Blocklist | Emerging Threats | https://rules.emergingthreats.net/ | This is just the firewall blocklist |
| ESET-MalwareIOC | ESET malwareIOC repo | https://github.com/eset/malware-ioc | |
| AbuseIPdb | AbuseIPdb | https://www.abuseipdb.com/ | Only 10.000 results, API key is required. |
| Spamhaus-Drop | Spamhaus droplist | https://www.spamhaus.org/drop/ | |
| Spamhaus-ExtendedDrop | Spamhaus extended droplist | https://www.spamhaus.org/drop/ | |
| Spamhaus-IPv6Drop | Spamhaus IPv6 droplist | https://www.spamhaus.org/drop/ | |
| Botvrij-filenames | Botvrij files | https://botvrij.eu/data/ioclist.filename.raw | |
| Botvrij-domains | Botvrij Domain names | https://botvrij.eu/data/ioclist.domain.raw | |
| Botvrij-destinations | Botvrij destinations | https://botvrij.eu/data/ioclist.ip-dst.raw | |
| Spamhaus-urls | Botvrij url list | https://botvrij.eu/data/ioclist.url.raw | |