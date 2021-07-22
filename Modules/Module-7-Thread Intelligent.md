# Module 6 - Thread Intelligent Thread Intelligent 

#### 🎓 Level: 300 (Intermediate)
#### ⌛ Estimated time to complete this lab: 20 minutes

This module will show you how to use Azure Sentinel Thread Intelligence features and all the integration points in the product.
During this model we will use the TI data we ingested on a previews model of this training and will discover how to visualize the data and use it as part of the detection and investigation.


#### Prerequisites
This module assumes that you have completed [Module 1](Module-1-Setting-up-the-environment.md), and also you [Module 2]( Module-2-Data-Connectors.md) and enable the TAXII TI connector.
 

### Exercise 1: Review Thread Intelligence data and the Threat intelligence manage page
As we reviewed in previous model, we have several ways to ingest TI data into Azure sentinel.
You can use one of many available integrated threat intelligence platform (TIP) products, you can connect to TAXII servers to take advantage of any STIX-compatible threat intelligence source, and you can also make use of any custom solutions that can communicate directly with the Microsoft Graph Security tiIndicators API.
The ingested data store in a dedicated table name **ThreatIntelligenceIndicator** and visible on the Threat Intelligence page on the left navigation.

##Task 1: Review the TI data into Azure Sentinel Logs interface.
1.On the left navigation press **Logs**, this will redirect us to the Log analytics query interface. On the query interface we can see on the left side the tables with the relevant fields.
2. To be able to see the ThreatIntelligenceIndicator schema, run the above query 
 ```powershell
 ThreatIntelligenceIndicator
| getschema
   ```


##Task 2:Review and manage TI IOC's in Azure Sentinel Threat intelligence manage page


### Exercise 1: TI detection (blackbox + TI matching)