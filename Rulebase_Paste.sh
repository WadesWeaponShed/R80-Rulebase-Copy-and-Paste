####################################################################################
# Digest of json created By Nicolas Boissé, SE, Checkpoint software 							 #
# COPY and PAST function added by Adam Forester, SE, Check Point software   			 #
####################################################################################

printf  "This script will allow you to import in a rule base that was exported using Rulebase_Copy.sh\nPress Anykey to continue\n"
read ANYKEY

printf "\nWhat is the IP address or Name of the Domain or SMS you want to check?\n"
read DOMAIN

printf "\nLogging On to API\n"
mgmt_cli -d $DOMAIN -r true login session-name "API Rulebase Copy Past" session-description "API Script to Copy Paste Existing Rulebase" > id.txt

printf "\nListing potential files for import\n"
ls |grep .json

printf "\nWhich Policy do you want to import?\n"
read IMPORT_FILE

printf "\nWhat do you want the new Policy PACKAGE to be called?"
read PACKAGE
LAYERNAME=$(echo $PACKAGE)




		#####################################
		#	Start of Rulebase Importation.	#
		#####################################
        printf "\nimporting access-layer \"$LAYERNAME Network\"..."
        declare -i TOTAL
        declare -i RULENUMBER
        declare -i POSITION
		declare -i INDEX
		declare -i number
		number=1
		TOTAL=$(expr $(cat $IMPORT_FILE | jq '.rulebase[].name' | wc -l) - 1)
        RULENUMBER=0
        POSITION=1

printf "\nCreating policy PACKAGE name $PACKAGE\n"
mgmt_cli -s id.txt -d $DOMAIN add package name "$PACKAGE" --format json


			while [ $RULENUMBER -le $TOTAL ]
			do
			# Is this rule a Section Title?
			ruletype=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" '.rulebase[$RULENUMBER|fromjson] | ."type"'| tr -d '"')
				if [ "$ruletype" == "access-section" ]
				then
					echo "Access-Section detected"
					sectionname="$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" '.rulebase[$RULENUMBER|fromjson] | ."name"'| tr -d '"')"
					declare -i sectionfrom
					declare -i sectionto
					declare -i i
					declare -i j
					echo "------------------------------------------------------------------"
					echo "SECTION $sectionname"
					echo "------------------------------------------------------------------"
					sectionfrom=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" '.rulebase[$RULENUMBER|fromjson] | ."from"'| tr -d '"')
					sectionto=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" '.rulebase[$RULENUMBER|fromjson] | ."to"' | tr -d '"')
					mgmt_cli -s id.txt -d $DOMAIN add access-section layer "$LAYERNAME Network" position bottom name "$sectionname"
					i=$sectionfrom
					j=0

					echo "RULE FROM=$sectionfrom TO=$sectionto"
					while [ $sectionfrom -le $sectionto ]
					do
						echo "============================"
						echo "RULE=#$number $LAYERNAME Network"
						echo "============================"
						# Get rule $RULENUMBER informations:
						SOURCES=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" --arg j "$j" '.rulebase[$RULENUMBER|fromjson]|.rulebase[$j|fromjson]|."source" | @csv' -r | tr -d '"'|sed 's/,/ /g')
						SOURCENEGATE=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" --arg j "$j" '.rulebase[$RULENUMBER|fromjson] |.rulebase[$j|fromjson]| ."source-negate"')
						DESTINATIONS=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" --arg j "$j" '.rulebase[$RULENUMBER|fromjson] |.rulebase[$j|fromjson]| ."destination" | @csv' -r | tr -d '"'|sed 's/,/ /g')
						DESTINATIONNEGATE=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" --arg j "$j" '.rulebase[$RULENUMBER|fromjson] | .rulebase[$j|fromjson]|."destination-negate"')
						SERVICES=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" --arg j "$j" '.rulebase[$RULENUMBER|fromjson] | .rulebase[$j|fromjson]|."service" | @csv' -r | tr -d '"'|sed 's/,/ /g')
						SERVICENEGATE=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" --arg j "$j" '.rulebase[$RULENUMBER|fromjson] |.rulebase[$j|fromjson]| ."service-negate"')
						ACTIONUID=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" --arg j "$j" '.rulebase[$RULENUMBER|fromjson] | .rulebase[$j|fromjson]|."action" '| tr -d '"'|sed 's/,/ /g')
						ACTION=$(cat $IMPORT_FILE | jq --arg ACTIONUID "$ACTIONUID" --arg j "$j" '."objects-dictionary"[]|select (.uid == "'$ACTIONUID'")|."name"'| tr -d '"')
						TRACKUID=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" --arg j "$j" '.rulebase[$RULENUMBER|fromjson]| .rulebase[$j|fromjson]|.track| ."type"' | tr -d '"'|sed 's/,/ /g')
						TRACK=$(cat $IMPORT_FILE | jq --arg TRACKUID "$TRACKUID" --arg j "$j" '."objects-dictionary"[]|select (.uid == "'$TRACKUID'")|."name"')
						NAME=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" --arg j "$j" '.rulebase[$RULENUMBER|fromjson] | .rulebase[$j|fromjson]|."name"' | tr -d '"'|sed 's/,/ /g'| grep -v "null")
						ENABLED=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" --arg j "$j" '.rulebase[$RULENUMBER|fromjson] | .rulebase[$j|fromjson]|."enabled"')

						echo "DEBUG ACTION"
						echo "Action=$ACTION UID=$ACTIONUID"

						# To Do: case with all action
						# look If rule action is an Inline-Layer:
						# In order to get this rule working, the inline layer must be created first. This is handle by "sort -t ',' -k2,2 > layersname.txt at the beginning of the main loop"
						if [ "$ACTION" == "Inner Layer" ]
						then
								echo "Inline layer detected"
								inlinelayer="true"
								inlinelayerUID=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" --arg j "$j" '.rulebase[$RULENUMBER|fromjson]|.rulebase[$j|fromjson]|."inline-layer"'| tr -d '"')
								echo "InlineLayerUID:$inlinelayerUID"
								inlineLAYERNAME=$(cat access-layers.json | jq --arg inlinelayerUID "$inlinelayerUID" '."access-layers"[]|select (.uid == "'$inlinelayerUID'")|."name"'| tr -d '"')
								echo "InlineLauerName:$inlineLAYERNAME"
								echo "InlineLayer name = $inlineLAYERNAME UID= $inlinelayerUID"
								ACTION=$(echo "\"Apply Layer\" inline-layer \"$inlineLAYERNAME\"")
						fi

						#Creating source filter (source.1 name source.2 name ...)
						declare -i x
						x=1
						sourcefilter=""
						for SrcUID in $(echo $SOURCES)
						do
							ObjName=$(cat $IMPORT_FILE | jq --arg SrcUID $SrcUID '."objects-dictionary"[]|select (.uid == "'$SrcUID'")|."name"'|tr -d '"')
							for name in $(echo $ObjName)
							do
								sourcefilter="$sourcefilter $(echo source.$x $name)"
							done
							x=$(expr $x + 1)
						done

						#Creating destination filter (destination.1 name destination.2 name ...)
						x=1
						destinationfilter=""
						for DstUID in $(echo $DESTINATIONS)
						do
							ObjName=$(cat $IMPORT_FILE | jq --arg DstUID $DstUID '."objects-dictionary"[]|select (.uid == "'$DstUID'")|."name"'| tr -d '"')
							for name in $(echo $ObjName)
							do
								destinationfilter="$destinationfilter $(echo destination.$x $name)"
							done
							x=$(expr $x + 1)
						done

						x=1
						servicefilter=""
						for SvcUID in $(echo $SERVICES)
						do
							ObjName=$(cat $IMPORT_FILE | jq --arg SvcUID $SvcUID '."objects-dictionary"[]|select (.uid == "'$SvcUID'")|."name"')
							servicefilter="$servicefilter $(echo "service.$x $ObjName")"
							echo "ObjectName=$ObjName"
							x=$(expr $x + 1)
						done

						echo "#!/bin/bash -f" > mgmtclistring.sh
						#add some debug echo
						echo "mgmt_cli -d $DOMAIN -s id.txt add access-rule layer \"$LAYERNAME Network\" enabled $ENABLED position \"bottom\" name \"$NAME\" action $(echo $ACTION) $(echo $sourcefilter) $(echo $destinationfilter) $(echo $servicefilter) source-negate $SOURCENEGATE destination-negate $DESTINATIONNEGATE service-negate $SOURCENEGATE track $TRACK --ignore-errors true details-level full --format json > \"$LAYERNAME Network-rule-$number\".json"

						#Generating Mgmt_Cli command
						echo "mgmt_cli -d $DOMAIN -s id.txt add access-rule layer \"$LAYERNAME Network\" enabled $ENABLED position \"bottom\" name \"$NAME\" action $(echo $ACTION) $(echo $sourcefilter) $(echo $destinationfilter) $(echo $servicefilter) source-negate $SOURCENEGATE destination-negate $DESTINATIONNEGATE service-negate $SOURCENEGATE track $TRACK --ignore-errors true details-level full --format json > \"$LAYERNAME Network-rule-$number\".json" >> mgmtclistring.sh

						chmod 755 mgmtclistring.sh

						#executing mgmtcli command
						/bin/bash ./mgmtclistring.sh

						rm mgmtclistring.sh

						#Validating Answer
						code=$(cat "$LAYERNAME Network"-rule-$number.json | jq '.code' | tr -d '"')
						case "$code" in
						generic_err_object_field_not_unique )
							echo  "$code in rule $POSITION. Adding an empty rule"
							echo "mgmt_cli -s id.txt -d $DOMAIN add access-rule layer \"$LAYERNAME Network\" position \"bottom\" enabled false name \"$NAME IMPORT ERROR\" action \"accept\" --ignore-errors true --session-id \"$session_id\" details-level full --format json > \"$LAYERNAME Network-rule-$number\".json"

							mgmt_cli -s id.txt -d $DOMAIN add access-rule layer "$LAYERNAME Network" position "bottom" enabled false name "IMPORT ERROR" action $ACTION $(echo $sourcefilter) $(echo $destinationfilter) --ignore-errors true details-level full --format json > "$layer-rule-$number".json
								;;
						err_validation_failed )
								echo "error: $code"
								;;
						esac
						#====================================================================
						i=$(expr $i + 1)
						j=$(expr $j + 1)
						sectionfrom=$(expr $sectionfrom + 1)
						number=$(expr $number + 1)
					done
				else
				# This is a rule. Not a section title
					echo "============================"
					echo "RULE=#$number $LAYERNAME Network"
					echo "============================"
					#Get rule information

					SOURCES=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" '.rulebase[$RULENUMBER|fromjson] | ."source" | @csv' -r | tr -d '"'|sed 's/,/ /g')
					SOURCENEGATE=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" '.rulebase[$RULENUMBER|fromjson] | ."source-negate"')
					DESTINATIONS=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" '.rulebase[$RULENUMBER|fromjson] | ."destination" | @csv' -r | tr -d '"'|sed 's/,/ /g')
					DESTINATIONNEGATE=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" '.rulebase[$RULENUMBER|fromjson] | ."destination-negate"')
					SERVICES=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" '.rulebase[$RULENUMBER|fromjson] | ."service" | @csv' -r | tr -d '"'|sed 's/,/ /g')
					SERVICENEGATE=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" '.rulebase[$RULENUMBER|fromjson] | ."service-negate"')
					ACTIONUID=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" '.rulebase[$RULENUMBER|fromjson] | ."action" '| tr -d '"'|sed 's/,/ /g')
					ACTION=$(cat $IMPORT_FILE | jq --arg ACTIONUID "$ACTIONUID" '."objects-dictionary"[]|select (.uid == "'$ACTIONUID'")|."name"'| tr -d '"')
					TRACKUID=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" '.rulebase[$RULENUMBER|fromjson]| .track| ."type"' | tr -d '"'|sed 's/,/ /g')
					TRACK=$(cat $IMPORT_FILE | jq --arg TRACKUID "$TRACKUID" '."objects-dictionary"[]|select (.uid == "'$TRACKUID'")|."name"')
					NAME=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" '.rulebase[$RULENUMBER|fromjson] | ."name"' | tr -d '"'|sed 's/,/ /g'| grep -v "null")
					ENABLED=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" '.rulebase[$RULENUMBER|fromjson] | ."enabled"')

					echo "DEBUG ACTION"
					echo "Action=$ACTION UID=$ACTIONUID"
					if [ "$ACTION" == "Inner Layer" ]
					then
							echo "Inline layer detected"
							inlinelayer="true"
							inlinelayerUID=$(cat $IMPORT_FILE | jq --arg RULENUMBER "$RULENUMBER" '.rulebase[$RULENUMBER|fromjson]|."inline-layer"'| tr -d '"')
							inlineLAYERNAME=$(cat access-layers.json | jq --arg inlinelayerUID "$inlinelayerUID" '."access-layers"[]|select (.uid == "'$inlinelayerUID'")|."name"'| tr -d '"')
							echo "InlineLayer name = $inlineLAYERNAME UID= $inlinelayerUID"
							ACTION=$(echo "\"Apply Layer\" inline-layer \"$inlineLAYERNAME\"")
					fi

					#Creating source filter (source.1 name source.2 name ...)
					declare -i i
					i=1
					sourcefilter=""
					for SrcUID in $(echo $SOURCES)
					do
						ObjName=$(cat $IMPORT_FILE | jq --arg SrcUID $SrcUID '."objects-dictionary"[]|select (.uid == "'$SrcUID'")|."name"'|tr -d '"')
						for name in $(echo $ObjName)
						do
							sourcefilter="$sourcefilter $(echo source.$i $name)"
						done
						i=$(expr $i + 1)
					done

					#Creating destination filter (destination.1 name destination.2 name ...)
					i=1
					destinationfilter=""
					for DstUID in $(echo $DESTINATIONS)
					do
							ObjName=$(cat $IMPORT_FILE | jq --arg DstUID $DstUID '."objects-dictionary"[]|select (.uid == "'$DstUID'")|."name"'| tr -d '"')
							for name in $(echo $ObjName)
							do
								destinationfilter="$destinationfilter $(echo destination.$i $name)"
							done
							i=$(expr $i + 1)
					done

					i=1
					servicefilter=""
					for SvcUID in $(echo $SERVICES)
					do
							ObjName=$(cat $IMPORT_FILE | jq --arg SvcUID $SvcUID '."objects-dictionary"[]|select (.uid == "'$SvcUID'")|."name"')
						servicefilter="$servicefilter $(echo "service.$i $ObjName")"
							echo "ObjectName=$ObjName"
							i=$(expr $i + 1)
					done

					echo "#!/bin/bash -f" > mgmtclistring.sh
					#add some debug echo
					echo "mgmt_cli -s id.txt -d $DOMAIN add access-rule layer \"$LAYERNAME Network\" enabled $ENABLED position \"bottom\" name \"$NAME\" action $(echo $ACTION) $(echo $sourcefilter) $(echo $destinationfilter) $(echo $servicefilter) source-negate $SOURCENEGATE destination-negate $DESTINATIONNEGATE service-negate $SOURCENEGATE track $TRACK --ignore-errors true --session-id \"$session_id\" details-level full --format json > \"$LAYERNAME Network-rule-$number\".json"

					#Generating Mgmt_Cli command
					echo "mgmt_cli -s id.txt -d $DOMAIN add access-rule layer \"$LAYERNAME Network\" enabled $ENABLED position \"bottom\" name \"$NAME\" action $(echo $ACTION) $(echo $sourcefilter) $(echo $destinationfilter) $(echo $servicefilter) source-negate $SOURCENEGATE destination-negate $DESTINATIONNEGATE service-negate $SOURCENEGATE track $TRACK --ignore-errors true --session-id \"$session_id\" details-level full --format json > \"$LAYERNAME Network-rule-$number\".json" >> mgmtclistring.sh

					#mgmt_cli add access-rule layer "$LAYERNAME Network" enabled $ENABLED position "bottom" name "$NAME" action $ACTION $(echo $sourcefilter) $(echo $destinationfilter) $(echo $servicefilter) source-negate $SOURCENEGATE destination-negate $DESTINATIONNEGATE service-negate $SOURCENEGATE track $TRACK --ignore-errors true details-level full --format json > "$layer-rule-$number".json
					chmod 755 mgmtclistring.sh
					#executing mgmtcli command
					/bin/bash ./mgmtclistring.sh

					rm mgmtclistring.sh

					#Validating Answer
					code=$(cat "$LAYERNAME Network-rule-$number".json | jq '.code' | tr -d '"')
					case "$code" in
					generic_err_object_field_not_unique )
							echo  "$code in rule $POSITION. Adding an empty rule"
							echo "mgmt_cli -s id.txt -d $DOMAIN add access-rule layer \"$LAYERNAME Network\" position \"bottom\" enabled false name \"$NAME IMPORT ERROR\" action \"accept\" --ignore-errors true --session-id \"$session_id\" details-level full --format json > \"$LAYERNAME Network-rule-$number\".json"
							mgmt_cli -s id.txt -d $DOMAIN add access-rule layer "$LAYERNAME Network" position "bottom" enabled false name "IMPORT ERROR" action $ACTION $(echo $sourcefilter) $(echo $destinationfilter) --ignore-errors true --session-id \"$session_id\" details-level full --format json > "$layer-rule-$number".json
							;;
					err_validation_failed )
							echo "error: $code"
							;;
					esac
					number=$(expr $number + 1)

				fi
				RULENUMBER=$(expr $RULENUMBER + 1)
				POSITION=$(expr $POSITION + 1)
			done

printf "\nCleaning Up and Publishing\n"
mgmt_cli -s id.txt -d $DOMAIN delete access-rule layer "$LAYERNAME Network" rule-number 1
rm *-rule-*.json
mgmt_cli -s id.txt -d $DOMAIN publish
mgmt_cli -s id.txt -d $DOMAIN logout
