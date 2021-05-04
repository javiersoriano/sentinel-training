# LAB 01 - Setup

#### 🎓 Level: 100 (Beginner)
#### ⌛ Estimated time to complete this lab: 15 minutes

## Objectives

This exercise guides you through the deployment of the Azure Sentinel environment that will be used in all subsequent modules.

## Prerequisites

To get started with Azure Sentinel, you must have a Microsoft Azure subscription. If you do not have a subscription, you can sign up for a free account.

Permissions to create a resource group in your Azure subscription. 

## Exercise 1: Deploy Azure Sentinel training ARM template

1. Click on the button below. Make sure that you open it in a new tab so you keep these instructions open.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjaviersoriano%2Fsentinel-training%2Fmain%2Fazuredeploy.json)

2. Fill out the defferent fields:
    - **Subscription**: choose the Azure subscription where you would like to deploy the Azure Sentinel lab
    - **Resource Group**: select an existing resource group or create a new resource group (recommended) that will host the lab resources
    - **Region**: from the drop down, select the Azure region where the lab will be located
    - **Workspace Name**: provide a name for the Azure Sentinel workspace. Please note that the workspace name should include 4-63 letters, digits or '-'. The '-' shouldn't be the first or the last symbol
    - **User Name**: Username used to authenticate the playbook with your Azure Sentinel environment. This can be the current username you're logged in with. For example: user1@contoso.com.

3. Click **Review + create** and then **Create** in the next screen. The deployment will start and should take around **10 minutes** to complete.

4. Once finished, go to the resource group name and you should see the following resources: Log Analytics workspace, SecurityInsights solution, *Get-GeoFromIpAndTagIncident* playbook, *Investigation Insights* workbook. 



## Exercise 2: Configure


