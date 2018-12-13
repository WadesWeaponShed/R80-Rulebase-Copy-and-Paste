After doing an upgrade to R80.x from previous versions if a policy was 'Traditional VPN' there is no way to change it to 'Simplified VPN' The easiest method is to copy and paste into a new policy package. The issue is currently copy/paste of a policy doesn't work if you have 'Section Titles' This script will let you COPY and PASTE via the API and will take all information with it.

## How to use ##
 - cp scripts over to mgmt station (this script is intended to run directly on the mgmt station)
  - I highly recommend that you do this in it's own folder
 - execute ./Rulebase_Copy
    - Follow the prompts
    - Output will be in a json file POLICY_NAME.json
 - execute ./Rulebase_Paste
     - Follow the prompts
