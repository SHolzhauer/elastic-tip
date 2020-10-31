# Elastic Threat Intelligence Platform (elastic-tip)
Elastic TIP is a python tool which automates the process of aggregating Threat Intelligence and ingesting
the intelligence into a common format into Elasticsearch with the main goal of being used by the Security
solution.

The intelligence ingested by elastic-tip is meant to be used by the [threat matching](https://github.com/elastic/kibana/pull/78955)
detection rule type.

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
 