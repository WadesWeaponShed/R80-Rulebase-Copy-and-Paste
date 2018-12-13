#!/bin/bash -f

####################################################################################
# Adam Forester, SE, Check Point software   			                                 #
####################################################################################

printf  "This script will export a policy to be imported in using a different name\nPress Anykey to continue\n"
read ANYKEY

printf "\nWhat is the IP address or Name of the Domain or SMS you want to check?\n"
read DOMAIN

printf "\nLogging On to API\n"
mgmt_cli -d $DOMAIN -r true login session-timeout 3600 > id.txt

printf "\nListing Access Policy Package Names\n"
mgmt_cli -d $DOMAIN -s id.txt show access-layers limit 500 --format json | jq --raw-output '."access-layers"[] | (.name)'

printf "\nWhat is the Policy Package Name you want to Copy?\n"
read POL_NAME
POL2=$(echo $POL_NAME | tr -d ' ')
rm $POL2.json

printf "\nDetermining Rulesbase Size\n"
total=$(mgmt_cli -s id.txt -d $DOMAIN show access-rulebase name "$POL_NAME" --format json |jq '.total')
printf "There are $total rules in the rulebase\n"

printf "\nExport Started\n"
mgmt_cli -d $DOMAIN -s id.txt show access-rulebase name "$POL_NAME" limit 1500 details-level full --format json >> "$POL2".json


printf "\nPolicy ready to import using $POL2.json"

printf "\nLogging out of API"
mgmt_cli -r true logout -s id.txt
