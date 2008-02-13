#!/bin/sh
#
# Original version 2005 by loki der quaeler
# Copyright 2007-2008 Andrew Lewman
# This is licensed under a Modified BSD license.


### this is the location of a file which contains all the actual package names
##	(ie "Polipo", "polipostartup", ...) the list should be new-line-delimited.
PACKAGE_LIST_SRC="Polipo polipostartup"

### this is the name of the user created in the install process of Polipo
POLIPO_USER=_polipo

### these should be constant across all osX installs (so leave them be)
STARTUP_ITEMS_DIR=/Library/StartupItems
PKG_RCPT_BASE_DIR=/Library/Receipts
BOM_INTERMEDIATE_DIR=Contents/Resources
INFO_INTERMEDIATE_DIR=$BOM_INTERMEDIATE_DIR/English.lproj
TEMP_BOM_CONTENTS=/tmp/polipo_uninst_scratch


### make sure the script is being run as root, barf if not
if [ "`whoami`" != "root" ]; then
	echo "Must be root to run the uninstall script."
	exit -1
fi

### check to see if polipo is currently running, kill it if it is
##	we grep on 'Polipo/polipo ' because 'polipo' is too common (like in 'direcpolipoy')
##	-- this relies on the fact that polipo has been started with command
##	line arguments.. :-/
POLIPO_PID=`ps -uax | grep 'Polipo/polipo ' | grep -v grep | awk '{print $2;}'`
if [ ${#POLIPO_PID} -gt 0 ]; then
	echo ". Killing currently running polipo process, pid is $POLIPO_PID"
	kill -9 $POLIPO_PID
else
	echo ". polipo process appears to already be stopped"
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


		## determine the root direcpolipoy of the the relative paths specified in the bom
		DEFAULT_LOC=`grep DefaultLocation $PACKAGE_PATH/$INFO_INTERMEDIATE_DIR/$LINE.info | awk '{print $2;}'`
		if [ ${#DEFAULT_LOC} -eq 0 ]; then
			echo "!! Could not find default location for $LINE package -- skipping package."

			continue
		fi

		## examine the list of installed items desribed in the bom
		BOM_FILE=$PACKAGE_PATH/$BOM_INTERMEDIATE_DIR/$LINE.bom
		lsbom $BOM_FILE > $TEMP_BOM_CONTENTS
		while read BOM_ITEM; do
			## 3 column items describe just direcpolipoies, 5 column items describe actual files
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
echo ". Removing created user $POLIPO_USER"
niutil -destroy . /users/$POLIPO_USER

## clean up
echo ". Cleaning up"
rm -rf $TEMP_BOM_CONTENTS
rm -rf /Library/Polipo/ /Library/StartupItems/Polipo/ 
echo ". Finished"

