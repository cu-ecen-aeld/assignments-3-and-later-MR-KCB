#!/bin/sh

inFile="$1"
inStr="$2"
retVal=1 # Not OK

if [ "$inFile" = "" ] || [ "$inStr" = "" ];
then
  echo "Invalid Input Arguments, please use the command  $0 <inFile> <inStr>"
else
  mkdir -p $(dirname "$inFile")
  if [ $? -ne 0 ]; # check the directory was created without problems
  then
    echo "Error while creating the new directory"
  fi
  echo "$inStr" > "$inFile"
  if [ $? -ne 0 ]; # check the file was create/updated without problems
  then 
    echo "Error while creating the new file"
  else
    retVal=0 # everything is OK lets update the exit value
  fi
fi

exit $retVal

