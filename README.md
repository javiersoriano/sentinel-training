# Welcome to Azure Sentinel Labs

<p align="center">
<img src="./Images/sentinel-labs-logo.png?raw=true">
</p>

## Introduction
These labs help you get ramped up with Azure Sentinel and provide hands-on practical experience for product features, capabilities, and scenarios. 

The lab deploys an Azure Sentinel workspace and ingests pre-recorded data to simulate scenarios that showcase various Azure Sentinel features. The cost of the deployed resources is very small due to the size of the data ~10 MBs and the fact that Azure Sentinel offers a 30-day free trial.

## Prerequisites

To deploy Azure Sentinel Labs, **you must have a Microsoft Azure subscription**. If you do not have an existing Azure subscription, you can sign up for a free trial [here](https://azure.microsoft.com/en-us/free/).

## Last release notes

* Version 0.1 - Azure Sentinel Labs **Beta** 

## Modules

[**Module 1 – Setting up the environment**](./Modules/Module-1-Setting-up-the-environment.md)
- [Deploy Azure Sentinel Labs ARM template](./Modules/Module-1-Setting-up-the-environment.md#exercise-1-deploy-azure-sentinel-labs-arm-template)
- [Configure Azure Sentinel Playbook](./Modules/Module-1-Setting-up-the-environment.md#exercise-2-configure-azure-sentinel-playbook)
 
[**Module 2 – Data Connectors**](./Modules/Module-2-Data-Connectors.md)
- [Enable Azure Activity data connector](./Modules/Module-2-Data-Connectors.md#exercise-1-enable-azure-activity-data-connector)
- [Enable Azure Defender data connector](./Modules/Module-2-Data-Connectors.md#exercise-2-enable-azure-defender-data-connector)
- [Enable Threat Intelligence TAXII data connector](./Modules/Module-2-Data-Connectors.md#exercise-3-enable-threat-intelligence-taxii-data-connector)

[**Module 3 – Analytics Rules**](./Modules/Module-3-Analytics-Rules.md)
- [Analytics Rules overview](./Modules/Module-3-Analytics-Rules.md#exercise-1-analytics-rules-overview)
- [Enable Microsoft incident creation rule](./Modules/Module-3-Analytics-Rules.md#exercise-1-enable-microsoft-incident-creation-rule)
- [Review Fusion Rule (Advanced Multistage Attack Detection)](./Modules/Module-3-Analytics-Rules.md#review-fusion-rule-advanced-multistage-attack-detection)

[**Module 4 – Incident Management**](./Modules/Module-4-Incident-Management.md)
- [Review Azure Sentinel incident tools and capabilities](./Modules/Module-4-Incident-Management.md#exercise-1-review-azure-sentinel-incident-tools-and-capabilities)
- [Handling Incident "Sign-ins from IPs that attempt sign-ins to disabled accounts"](./Modules/Module-4-Incident-Management.md#exercise-2-handling-incident-sign-ins-from-ips-that-attempt-sign-ins-to-disabled-accounts)
 
[**Module 5 – Hunting**](./Modules/Module-5-Hunting.md)
- [Acknowldge incident](./Modules/Module-5-Hunting.md#exercise-1-acknowldge-incident)
- [Hunting for more evidence](./Modules/Module-5-Hunting.md#exercise-2-hunting-for-more-evidence)
- [Add IOC to Threat Intelligence](./Modules/Module-5-Hunting.md#exercise-3-add-ioc-to-threat-intelligence)
- [Hand over incident](./Modules/Module-5-Hunting.md#exercise-4-hand-over-incident)
 
[**Module 6 – Watchlists**](./Modules/Module-6-Watchlists.md)
- [Create a Watchlist](./Modules/Module-6-Watchlists.md#exercise-1-create-a-watchlist)
- [Whitelist IP addresses in the analytics rule](./Modules/Module-6-Watchlists.md#exercise-2-whitelist-ip-addresses-in-the-analytics-rule)