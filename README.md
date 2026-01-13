# PermissionHelper

## What is PermissionsHelper!?
  The file PermissionHelper.ps1 is a large PowerShell script specifically designed to extract, process, and convert Azure DevOps permissions and related metadata for an organization. It acts as a helper tool for Azure DevOps administrators who need to audit, analyze, or export permission settings and organizational data.
  
  ### High-Level Overview
  This script automates the process of gathering Azure DevOps permissions, groups, projects, repositories, users, queries, service endpoints, dashboards, plans, iterations, and areas, and converts them into readable formats for analysis.
  
  ### Key Functions and Their Roles
   - Authentication
     - Get-EntraToken / Get-GraphToken
     - Obtain access tokens using the Az PowerShell module for authenticating against Azure DevOps REST APIs and Microsoft Graph API.
   - REST API Calls
     - GET-AzureDevOpsRestAPI
     - Wrapper for calling Azure DevOps REST APIs with error handling, throttling, and logging.
   - Data Extraction Functions
     - These functions use the REST API to extract different types of Azure DevOps data and write them to local JSON files:
  
  ### Conversion & Enrichment
  - Convert-Permissions: Reads the raw permissions file, then enriches and replaces technical IDs/tokens/descriptors (e.g., GUIDs) with human-readable names by cross-referencing the other extracted files (groups, projects, repos, etc.).
    - The output is a more readable permissions file for auditing or reporting.
  
  ### Utility & Logging
  - Update-ConsoleLine: Updates a specific line in the console output (for progress reporting).
  - Update-Log: Appends detailed log entries to an error log file.
  
  ### What Does It Actually Do?
  - Authenticates to Azure DevOps and Graph APIs using the Az module.
  - Extracts all relevant security and organizational data from Azure DevOps using REST APIs (permissions, projects, groups, users, etc.).
  - Writes raw data to local JSON files in the .\data\ folder.
  - Processes and enriches the permissions data, translating technical identifiers and tokens into human-readable names (group names, project names, etc.).
  - Outputs a readable permissions file for use in audits, reporting, or migration scenarios.
  - Handles errors and logs all major actions and issues for troubleshooting.
  ### Typical Use Case
  An Azure DevOps administrator runs this script to:
  - Audit who has access to what resources.
  - Extract permissions for analysis outside of Azure DevOps.
  - Prepare for compliance, security reviews, or migrations.
  ### Summary
  PermissionHelper.ps1 is a comprehensive Azure DevOps permissions audit and export tool. It automates the collection and conversion of permissions and related organizational data into a readable format for analysis and reporting.

## Requirements:
- PCA access in org 
  - I've made an effort to handle issues where you do not have permissions to see something, but I cannot say for sure that I have caught all possible permissions issues you might hit. if you are not a PCA, you are getting a best effort.
- Sufficient System Memory to hold sections of information as they are pulled can be a Gb.
- Sufficient disk space to copy information locally, for large orgs this can be multiple Gbs.
- The script is designed to keep you under the Throttle limits, but Basic + Test Plan may help if you see a lot of issues.

## How to Use:
- Run the script if you do not have AZ CLI it will install it.
- Login at the prompt (usually top left corner of main screen), it may pop up under other windows.
- Choose your subscription.
- Script will get a token, and begin starting separate threads to pull info.
- Once the token is aquired you will be able to use it until expired without the previous steps.
- Some Orgs may have enough data in some areas that this can take an extended amount of time.  You can periodically check the size of the Json file permissions and identities to make sure they are growing.  For moderately sized orgs this may take 10-15 minutes, Very large Orgs may take an hour or more.
- The Application will update you on the status of the Job to pull information for each area: 

```  
    GetPermissionsJob         : Running
    GetProjectsJob            : Completed
    GetGroupsJob              : Completed
    GetUsersJob               : Running
    GetReposJob               : Running
    GetProcessesJob           : Completed
    GetClassificationNodesJob : Completed
    GetQueriesJob             : Running
    GetAnalyticsViewsJob      : Running
    GetServiceEndpointsJob    : Completed
    GetDashboardsJob          : Not Started
    GetPlansJob               : Not Started
    GetClassificationNodesJob : Not Started
    Execution time            : 00:02:30
```

- Once all the Data is pulled locally to the ./data folder as JSON Files, we will process the file to make the Tokens human readable.

```
    Performing Post Processing to give friendly tokens and descriptors...
    Processed 5000 lines so far...
```

- When the Processing is complete the script will Create a folder and move the data files to it

```
   Consolidating Data files for archival (it may take up to a minute to begin moving Permissions.json)... 
   VERBOSE: Performing the operation "Move File" on target "Item: C:\Example.json Destination: C:\[orgname][timestamp]\Example.Json".
```

- Then the Script will Archive the data files 

```
    Archiving files to C:\[orgname][timestamp]\[orgname][timestamp].zip ... 
    [████               Compressing C:\Example.json                                ]
```
- Then the script cleans up after itself by removing the uncompressed files

```
    Archiving files to C:\[orgname][timestamp]\[orgname][timestamp].zip ... 
    <span style="color: yellow;">VERBOSE: Performing the operation "Remove File" on target "Item: C:\[orgname][timestamp]\Example.Json".
```

- When done the script will output a final update and complete

```
   Permissions file     : C:\[orgname][timestamp]\Example.json
   Data files           : C:\[orgname][timestamp]\[orgname][timestamp].zip
   Total Execution time : 00:05:00
   PS C:\>
```

- Errors, Warnings and other information including tarpits and blocking are saved to the error.log file.
  - The permissions_readable.json will be in both the folder and in the zip file for convinience.


## Understanding the Output: ACE/ACL Structures

The output files contain Azure DevOps permissions encoded in **Access Control Entry (ACE)** and **Access Control List (ACL)** structures. These use bitfield-based permission encoding that requires understanding to interpret effectively.

For a comprehensive guide on:
- **How to query and retrieve ACLs** for any namespace
- **Decoding permission bits** to human-readable names
- **Finding and interpreting deny permissions**
- **Modifying individual permissions** safely
- **Understanding effective permissions** (allow AND NOT deny)

See: **[AZURE_DEVOPS_ACE_ACL_GUIDE.md](AZURE_DEVOPS_ACE_ACL_GUIDE.md)**

This guide provides namespace-agnostic examples using both REST API and Azure DevOps CLI for working with permissions programmatically.

## To Dos:

### Need Investigations:
- Resolve Service Accounts and Service Principals Ids.
  - We may need to go to GraphAPI for this.
- Service Endpoints APis seem not to give all results.
  - May need to add a lookup in the convert-permissions like we did for some OOB group SIDs.

### Stretch Goals
- Config to let you control what you are trying to look up more granularly.
- Wire up inheritance chains
- Investigate feasability of per project runs (though we may still have to pull full Identities, groups etc for this to work.)
- Configurable or adaptable Thread pool sizes for best experience.
- piggy back on tf.exe to look at converting Workspace ids to names.... this will be inefficient and should likely be opt in/out via config.

### Note
There is no API exposed that can convert the Workspace ID to a Workspace name for TFVC Items.  This is due to the fact that TFVC is Feature Complete and no additional work will be done on this are aof the product.  If you find that you need to gather more information about a TFVC Workspace you can use the ID and name interchangably in the TF.exe commands and you should be able to get details from there.

There is a "group" that is formatted as: "[\<orgname\>]\DirectoryServiceAddMember-\<TenantName\>-Group" You may see permissions for this group if you are an Owner/PCA but there is no API to decode this from the ID to the above name.  If you have 1 Guid that is not converted to a friendly name in your results this is likely the reason.  This group should not be used or even seen in day to day operations, do not modify this groups permissions.