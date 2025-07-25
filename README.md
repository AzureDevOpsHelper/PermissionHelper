# PermissionHelper
It would be nice to have a big flat list of all the permissions in an org.

This works great for small to mid-sized org but can cause OOMs for larger orgs, since we have to take the results that we've pulled and compare and replace the values in the permissions file.

Looking at using a streaming JSON parser like https://learn.microsoft.com/en-us/dotnet/api/newtonsoft.json.jsontextreader from Newtonsoft.Json