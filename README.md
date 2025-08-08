# PermissionHelper

## What is PermissionsHelper!?
- Pulls info and creates a big JSON of all the permissions in an org.
- Works great for small to mid-sized orgs!
- Very Large Orgs work, but it can take an extended amount of time if you have:
  - A large number of Users/Groups.
  - A large number of Projects. 
  - A large history (we do not clean up ACES so we have to pull, process and discard disabled ones).
  - Many deleted objects (projects, groups, repos etc.) for the same reason as above.

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


## To Dos:

### Need Investigations:
- Resolve Service Accounts and Service Principals Ids.
  - We may need to go to GraphAPI for this.
- Resolve Workspace Tokens.
  - Seems like this is associated with VS Profile.
- Service Endpoints APis seem not to give all results.
  - May need to add a lookup in the convert-permissions like we did for some OOB group SIDs.

### Stretch Goals
- Config to let you control what you are trying to look up more granularly.
- Wire up inheritance chains
- Investigate feasability of per project runs (though we may still have to pull full Identities, groups etc for this to work.)
- Configurable or adaptable Thread pool sizes for best experience.