# PermissionHelper
- It would be nice to have a big flat list of all the permissions in an org.
- This works great for small to mid-sized org but can cause OOMs for larger orgs, since we have to take the results that we've pulled and compare and replace the values in the permissions file.
- Looking at using a streaming JSON parser like https://learn.microsoft.com/en-us/dotnet/api/newtonsoft.json.jsontextreader from Newtonsoft.Json

## Requirements:
- PCA access to org (otherwise you will only be able to see what you have access to)
- Sufficient System Memory to hold sections of information as they are pulled can be multiple Gbs
- Sufficient disk space to copy information locally, for large orgs this can be multiple Gbs
- The script is designed to keep you under the Throttle limits, but Basic + Test Plan may help if needed.

## How to Use:
- Run the script if you do not have AZ CLI it will install it.
- login at the prompt (usually top left corner of main screen), it may pop up under other windows.
- choose your subscription.
- script will get a token, and begin starting separate threads to pull info.
- Once the token is aquired you will be able to use it until expired without the previous steps.
- threads will update the main screen (no mutex so it can be a little messy).
- when complete there will be multiple files in the ./data folder.
- Errors, including tarpits and blocking are saved to the error.log file.