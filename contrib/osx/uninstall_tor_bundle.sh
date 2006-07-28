#!/bin/sh
#
# not a psueber-pretty uninstall script for the Tor bundle package
#	. this currently leaves ~/.tor, /var/log/tor and empty
#		directories /Library/Tor, /Library/Privoxy (see comment below)
#	. this relies on the fact that the startup items directories (if any)
#		will be named the same as the package name (ie. Tor)
#
#
# version history
#	initial version - 21 may, 2005 - loki der quaeler
#
#
# comments
# loki: because of the way the Tor package installs itself (the root directory
#	is the filesystem root, as opposed to the much nicer way that privoxy
#	installs itself with the privoxy home (/Library/Privoxy) as its
#	install root directory), i thought it more prudent to leave empty
#	directories laying around rather than try to incorrectly intuit from
#	the bom contents what directories should exist and which ones could be
#	deleted (ie, the Tor package has /Library listed in its bom --
#	obviously this is a Bad Thing(tm) to delete).
#       + when the Tor installer is changed, this uninstaller could be modified.
# loki: /bin/ps, when run from a terminal window in osX, restricts information
#	based on the width of the window. an 80 col window will stupidly cause
#	the grep search for the privoxy pid to not find the pid, whereas the grep
#	in a wider window succeeds. consider using killall. in the meantime,
#	advise uninstall runners to drag wide their terminal window.. ugh
#


### this is the location of a file which contains all the actual package names
##	(ie "Tor", "torstartup", ...) the list should be new-line-delimited.
PACKAGE_LIST_SRC=./package_list.txt


### this is the name of the user created in the install process of Tor
TOR_USER=_tor


### these should be constant across all osX installs (so leave them be)
STARTUP_ITEMS_DIR=/Library/StartupItems
PKG_RCPT_BASE_DIR=/Library/Receipts
BOM_INTERMEDIATE_DIR=Contents/Resources
INFO_INTERMEDIATE_DIR=$BOM_INTERMEDIATE_DIR/English.lproj
TEMP_BOM_CONTENTS=/tmp/tor_uninst_scratch


### make sure the script is being run as root, barf if not
if [ "`whoami`" != "root" ]; then
	echo "Must be root to run the uninstall script."
	exit -1
fi


### check to see if tor is currently running, kill it if it is
##	we grep on 'Tor/tor ' because 'tor' is too common (like in 'directory')
##	-- this relies on the fact that tor has been started with command
##	line arguments.. :-/
TOR_PID=`ps -uax | grep 'Tor/tor ' | grep -v grep | awk '{print $2;}'`
if [ ${#TOR_PID} -gt 0 ]; then
	echo ". Killing currently running tor process, pid is $TOR_PID"
	kill -9 $TOR_PID
else
	echo ". tor process appears to already be stopped"
fi


### check to see if privoxy is currently running, kill it if it is
PRIVOXY_PID=`ps -uax | grep privoxy | grep -v grep | awk '{print $2;}'`
if [ ${#PRIVOXY_PID} -gt 0 ]; then
	echo ". Killing currently running privoxy process, pid is $PRIVOXY_PID"
	kill -9 $PRIVOXY_PID
else
	echo ". privoxy process appears to already be stopped"
fi


## grab each package name from the package list file
while read LINE; do
	if [ ${#LINE} -gt 0 ]; then
		PACKAGE_NAME=$LINE.pkg
		PACKAGE_PATH=$PKG_RCPT_BASE_DIR/$PACKAGE_NAME
		echo ". Uninstalling $PACKAGE_NAME"
		if [ ! -d $PACKAGE_PATH ]; then
			echo "  . No receipt exists for this package -- skipping."

			continue
		fi
		

		## get rid of the startup item if it exists
		STARTUP_DIR=$STARTUP_ITEMS_DIR/$LINE
		if [ -d $STARTUP_DIR ]; then
			echo "  . Deleting startup item $STARTUP_DIR"
			rm -rf $STARTUP_DIR
		fi


		## determine the root directory of the the relative paths specified in the bom
		DEFAULT_LOC=`grep DefaultLocation $PACKAGE_PATH/$INFO_INTERMEDIATE_DIR/$LINE.info | awk '{print $2;}'`
		if [ ${#DEFAULT_LOC} -eq 0 ]; then
			echo "!! Could not find default location for $LINE package -- skipping package."

			continue
		fi

		## examine the list of installed items desribed in the bom
		BOM_FILE=$PACKAGE_PATH/$BOM_INTERMEDIATE_DIR/$LINE.bom
		lsbom $BOM_FILE > $TEMP_BOM_CONTENTS
		while read BOM_ITEM; do
			## 3 column items describe just directories, 5 column items describe actual files
			COL_COUNT=$(echo $BOM_ITEM | awk '{print NF;}')
			if [ "$COL_COUNT" -eq 5 ]; then
				FILE_NAME=$DEFAULT_LOC/$(echo $BOM_ITEM | awk '{print $1;}')

				echo "  . Removing $FILE_NAME"
				rm -rf $FILE_NAME
			fi
		done < $TEMP_BOM_CONTENTS

		## remove package receipt
		echo "  . Removing package receipt $PACKAGE_PATH"
		rm -rf $PACKAGE_PATH
	fi
done < $PACKAGE_LIST_SRC


## nuke the user created by the install process.
echo ". Removing created user $TOR_USER"
niutil -destroy . /users/$TOR_USER


## clean up
echo ". Cleaning up"
rm -rf $TEMP_BOM_CONTENTS
rm -rf /Library/Privoxy/ /Library/StartupItems/Privoxy/ /Library/Tor/ /Library/StartupItems/Tor/

echo ". Finished"

