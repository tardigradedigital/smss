<?php
// Log rollover scheduler for Synapse Service
// Rotates log queue at 12:00A UTC
// Password for user account 'scheduler'
// 64bitkey

// Set timezone to UTC
date_default_timezone_set('UTC');

// Initialize variable to store log data
$LogData = '';

// Switch to scheduler working directory and set include paths
chdir('C:/inetpub/service/synservice/scheduler/');
ini_set('include_path', '.;../resources/libraries/azure/;../resources/libraries/pear/');

// Load files required for Windows Azure Blob and Queue Storage
require_once 'WindowsAzure/WindowsAzure.php';
use WindowsAzure\Common\ServicesBuilder;
use WindowsAzure\Common\ServiceException;

// Initialize handlers for Queue and Blob Storage
$EntryClient = ServicesBuilder::getInstance()->createQueueService('DefaultEndpointsProtocol=https;AccountName=smss;AccountKey=n+64bitkey+1f==');
$LogClient = ServicesBuilder::getInstance()->createBlobService('DefaultEndpointsProtocol=https;AccountName=smss;AccountKey=n+64bitkey+1f==');

// Retrieve the initial number of log entries
$LogQueueMetadata = $EntryClient->getQueueMetadata('ssologqueue');
$EntryCount = $LogQueueMetadata->getApproximateMessageCount();

// Recursively pull messages from Queue Storage, add them to the log, then delete them from Queue Storage
for($i=0; $i < $EntryCount; ++$i) {
	$MessageBulk = $EntryClient->listMessages('ssologqueue');
	$Messages = $MessageBulk->getQueueMessages();
	$Message = $Messages[0];
	$LogData .= $Message->getMessageText();
	$MessageID = $Message->getMessageID();
	$PopReceipt = $Message->getPopReceipt();
	$EntryClient->deleteMessage('ssologqueue', $MessageID, $PopReceipt);
	$EntryCount = $LogQueueMetadata->getApproximateMessageCount();
}

// Generate previous day's date for unique file name
$LogDate = date('m-d-Y-l', time() - 86400);

// Save the log to disk
file_put_contents("../cache/ssolr-$LogDate.log", $LogData);

// Initialize a file handler for the log file
$LogFile = fopen("../cache/ssolr-$LogDate.log",'r');

// Upload the log file to Blob Storage
$LogClient->createBlockBlob('servicelogs', "ssolog-$LogDate.log", $LogFile);

// Close the file and delete the cache file
fclose($LogFile);
unlink("../cache/ssolr-$LogDate.log");
exit();
?>