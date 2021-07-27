# Module 7 - Threat Intelligence

#### 🎓 Level: 300 (Intermediate)
#### ⌛ Estimated time to complete this lab: 20 minutes

This module will show you how to use Azure Sentinel Threat Intelligence (TI) features and all the integration points in the product.
During this module we will use TI data we ingested in [Module 2](Module-2-Data-Connectors.md) of this training, and will discover how to visualize the data and use it as part of the detection and investigation.


#### Prerequisites
This module assumes that you have completed [Module 1](Module-1-Setting-up-the-environment.md), and also [Module 2](Module-2-Data-Connectors.md) that enables the Threat Intelligence TAXII connector.
 

### Exercise 1: Threat Intelligence data connectors

For detailed prerequisites and instructions for this connector, you can visit our official doc on this matter [Connect your threat intelligence platform to Azure Sentinel](https://docs.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-tip).

#### Task 1 : Threat Intelligence Platforms (TIP) connector 

This connector is currently in public preview and is based on Third-party Threat Intelligence platform (TIP) solutions like PaloAlto MineMeld, ThreatConnect and others.

1. On the left navigation open the connector page and search **Threat Intelligence Platforms (Preview)**
2. On the bottom right pane press **Open connector page**
3. Review the connector Prerequisites and notice that to enable this connector, the user need to be **Global Admin** or **Security Administrator** in the current Azure AD tenant
4. Read the configuration section and notice that as part of this connector onboarding, the user needs to create an Azure AD app registration and grant one of the permissions above
	
#### Task 2 : Threat intelligence TAXII connector

For detailed prerequisites and instructions for this connector, you can visit our official doc on this matter [Connect Azure Sentinel to STIX/TAXII threat intelligence feeds](https://docs.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-taxii)

In [Module 2](Module-2-Data-Connectors.md) we already enabled the TAXII connector in our lab environment, please refer to this module for more information.


### Exercise 2: Explore the Threat Intelligence menu

As we discussed in the previous exercise, we have several ways to ingest TI data into Azure Sentinel. You can use one of the many available integrated Threat Intelligence Platform (TIP) products or you can connect to TAXII servers to take advantage of any STIX-compatible threat intelligence source. There is an additional option whic allows you to bring any custom TI feed using the Microsoft Graph Security tiIndicators API.

The ingested Indicators of Compromise coming from these TI feeds, is stored in a dedicated table called **ThreatIntelligenceIndicator** and visible on the Threat Intelligence menu on the left navigation.

#### Task 1: Review the TI data into Azure Sentinel Logs interface.

1. On the left navigation click on **Logs**, this will redirect you to the Log Analytics query interface. On the query interface we can see on the left side the tables with the relevant fields.
2. Azure Sentinel built-in tables have a pred-efined schema, to be able to see the **ThreatIntelligenceIndicator** schema, run the following query: 

 ```powershell
 ThreatIntelligenceIndicator
| getschema
   ```

![schema](../Images/TI-schema.png)

3.	Let's explore and delve into the TI table. Run the following query which takes 10 records from the table:

 ```powershell
ThreatIntelligenceIndicator
| take 10
   ```

To understand if a specific IOC is active, we need to have closer look at the following columns>

- **ExpirationDateTime [UTC]**
- **Acitve** 

On our example, we can see that the IOC is an IP that is active with future Expiration date. This means that our matching detection rule will take this IOC into consideration when correlating with data sources. 

![Acitve](../Images/TI-active.png)


#### Task 2: Review and manage TI IOC's in Azure Sentinel Threat intelligence menu.

After we ingested our TI data into the ThreatIntelligenceIndicator table,
our mession is to review how our SOC can leverage and manage the TI menu to allow us to search, tag and manage the life cycle of IOC.

 
1. On the Azure sentinel left menu press on the Threat intelligence (Preview)
This menu id a visual representation of the ThreatIntelligenceIndicator table.

![Acitve](../Images/m7-Tiblade.png)


2. Select one IOC from the main pane and notice that the right  pane changed accordingly and present the metadata of the selected IOC.

![Acitve](../Images/m7-Tiblade1.png)
	
3. On the top area of the main blade, we can filter the list of the IOC's based on a specific parameters.
In our case we only ingested one type of IOC (IP), but the **Type** filter allow us to filter based on diffrent types.
If we ingested IOC's from multiple TI data source, the **source** filter can allow us to slice it.

![Acitve](../Images/m7-ITbladeFilter)

	
#### Task 3: add new TI IOC manually in Azure Sentinel Threat intelligence menu
	
	
Part of the SOC analytics job is from time to time to add an IOC in a manuel way to our TI index.
This allows other data sources and detection's to correlate and detect interaction with this IOC.

1. On the **Threat intelligence (Preview)** top menu, press on **add new**, this will open the **new Indicator** menu
2. In the drop down select url and add the above url http://phishing.com
3. Add Tags that will help us to add metadata on this IOC, on our example we want to tag this file IOC with Our relevant incident id that this IOC was part of its observation.
On the add tag pop-up write **incident 4326** and **press Ok**.
	 
![Acitve](../Images/m7-tibladeaddtag.png)

4. On the **Thread types** select **malicious activity**
	
5. Add an **description** and set the **confidence level** to 80, set up the **Valid from** date to today and the **Valid until** to two week from now.
6. Press **Apply**

![Acitve](../Images/m7-fullnewIOC.png)


7. Notice to the newly created IOC on the TI menu.
8. please be aware that every new IOC we added in the TI menu added automatically to the ThreatIntelligenceIndicator table,
You can validate it by opening the **Logs** menu and run the above query.

```powershell
ThreatIntelligenceIndicator
| search "http://phishing.com"
```

9. As we want to view the description column, we need to modify the column order for the menu by select the **column** button on the top bar 
![Acitve](../Images/m7-tibladecolumnorder.png)


10. Once the **Choose columns** opened in the right side, select the **Description**  and drag and drop it by pressing on the 3 dots.
11. Press **Apply**

![Acitve](../Images/m7-TIlogs.png)


After couple of days we got a new information from our internal TI team that this new IOC is not relevant anymore and we need to delete it.

11. Select the newly created manual IOC and press delete

![Acitve](../Images/m7-deleteTI.png)




### Exercise 3: Analytics Rules based on Threat Intelligence data

#### Task 1: Review and enable TI mapping analytics rules

#### Task 2: Review and enable Threat Intelligence Matching Analytics rule


### Exercise 5: Threat Intelligence Workbook
