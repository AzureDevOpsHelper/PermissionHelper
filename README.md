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
- PCA access in org (otherwise you will only be able to see what you have access to).
- Sufficient System Memory to hold sections of information as they are pulled can be a Gb.
- Sufficient disk space to copy information locally, for large orgs this can be multiple Gbs.
- The script is designed to keep you under the Throttle limits, but Basic + Test Plan may help if you see a lot of issues.

## How to Use:
- Run the script if you do not have AZ CLI it will install it.
- Login at the prompt (usually top left corner of main screen), it may pop up under other windows.
- Choose your subscription.
- Script will get a token, and begin starting separate threads to pull info.
- Once the token is aquired you will be able to use it until expired without the previous steps.
- Threads will update the main screen (no mutex so it can be a little messy).
- When complete there will be multiple files in the ./data folder.
- Errors, including tarpits and blocking are saved to the error.log file.

## To Dos:

### Need Investigations:
 1. Resolve Service Accounts and Service Principals Ids.
   - We may need to go to GraphAPI for this.
 2. Resolve Workspace Tokens.
   - Seems like this is associated with VS Profile.

### Need Lookups added for:
 1. Plan 
 2. Process 
 3. CSS 
 4. Iteration 
 6. DashboardsPrivileges

### Stretch Goals
 1. Wire up inheritance chains
 2. Investigate feasability of per project runs (though we may still have to pull full IDentities, groups etc for this to work.)
 3. Configurable or adaptable Thread pool sizes for best experience.