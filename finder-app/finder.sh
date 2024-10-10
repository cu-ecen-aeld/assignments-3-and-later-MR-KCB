#!/bin/sh 

filesdir="$1"
searchstr="$2"
retVal=1 # error value

if [ "$filesdir" = "" ] || [ "$searchstr" = "" ]; 
then
 echo "Parameter missing please use the next sintax $0 <fileDir> <searchStr>"
elif [ ! -d $filesdir ];
then 
 echo 'filesdir does not represent a directory on the filesystem'
else 
 quantityFiles=$(find $filesdir -type f | wc -l)
 quantityMatchesLines=$(grep -r $searchstr $filesdir | wc -l)
 echo "The number of files are $quantityFiles and the number of matching lines are $quantityMatchesLines"
 retVal=0 # OK
fi


exit $retVal
