<?php
// Synapse Service on Windows Azure
// 2009-2013 Justin Lindsey

error_reporting(0);
ini_set('include_path', '.;synservice/resources/libraries/azure/;synservice/resources/libraries/pear/');
require_once 'WindowsAzure/WindowsAzure.php';
use WindowsAzure\Common\ServicesBuilder;
use WindowsAzure\Common\ServiceException;
use WindowsAzure\Queue\Models\CreateMessageOptions;

class ServiceValidators {
    private $Utilities;
    private $Validators;
    private $VerifySrcs;
    
    public function __construct($Utilities) {
        $this->Utilities = $Utilities;
        $this->Validators = array();
        if(!is_dir("synservice/resources/validators/")) return false;
        if(!$ValidatorsDir = opendir("synservice/resources/validators/")) return false;
        while($ValidatorFile = readdir($ValidatorsDir)) {
            if($ValidatorFile == ".");
            elseif($ValidatorFile == "..");
            elseif(filetype("synservice/resources/validators/".$ValidatorFile) == "dir"); 
            else {
                require_once "synservice/resources/validators/".$ValidatorFile;
                if(is_array($Validator)) $this->Validators[$Validator["ValidatorName"]] = array(
                    "Expression" => $Validator["Expression"],
                    "VerifyAgainst" => ($Validator["VerifyAgainst"]?$Validator["VerifyAgainst"]:false),
                    "AlsoAllow" => ($Validator["AlsoAllow"]?$Validator["AlsoAllow"]:false)
                );
            }
        }
        $this->VerifySrcs = array();
        if(!is_dir("synservice/resources/verifysrcs/")) return false;
        if(!$VerifySrcsDir = opendir("synservice/resources/verifysrcs/")) return false;
        while($VerifySrcFile = readdir($VerifySrcsDir)) {
            if($VerifySrcFile == ".");
            elseif($VerifySrcFile == "..");
            elseif(filetype("synservice/resources/verifysrcs/".$VerifySrcFile) == "dir"); 
            else {
                require_once "synservice/resources/verifysrcs/".$VerifySrcFile;
                if(is_array($VerifySrc)) $this->VerifySrcs[$VerifySrc["SrcName"]] = array(
                    "Query" => $VerifySrc["Query"]
                );
            }
        }
    }

    public function parseArguments($Arguments) {
        $Parsed = array();
        foreach($Arguments as $Argument) {
            $Argument = explode("::",$Argument);
            $Parsed[] = $Argument[1];
        }
        return $Parsed;
    }

    private function validateData($Data, $Type) {
        if(array_key_exists($Type, $this->Validators)) {
            if(preg_match($this->Validators[$Type]["Expression"],$Data)) {
                if($this->Validators[$Type]["VerifyAgainst"]) {
                    if($this->verifyAgainst($Data, $this->Validators[$Type]["VerifyAgainst"])) return true;
                    else return false;
                }
                else return true;
            }
            elseif($this->Validators[$Type]["AlsoAllow"]) {
                foreach($this->Validators[$Type]["AlsoAllow"] as $SubType) {
                    if(preg_match($this->Validators[$SubType]["Expression"],$Data)) {
                        if($this->Validators[$SubType]["VerifyAgainst"]) {
                            if($this->verifyAgainst($Data, $this->Validators[$Type]["VerifyAgainst"])) return true;
                        }
                        else return true;
                    }
                }
                return false;
            }
            else return false;
        }
        elseif(strstr($Type,"*")) {
            if(array_key_exists(substr($Type,0,strlen($Type)-1), $this->Validators)) {
                if($Data == "") return true;
                elseif(preg_match($this->Validators[substr($Type,0,strlen($Type)-1)]["Expression"],$Data)) {
                    if($this->Validators[substr($Type,0,strlen($Type)-1)]["VerifyAgainst"]) {
                        if($this->verifyAgainst($Data, $this->Validators[substr($Type,0,strlen($Type)-1)]["VerifyAgainst"])) return true;
                        else return false;
                    }
                    else return true;
                }
                elseif($this->Validators[substr($Type,0,strlen($Type)-1)]["AlsoAllow"]) {
                    foreach($this->Validators[substr($Type,0,strlen($Type)-1)]["AlsoAllow"] as $SubType) {
                        if(preg_match($this->Validators[$SubType]["Expression"],$Data)) {
                            if($this->Validators[substr($SubType,0,strlen($SubType)-1)]["VerifyAgainst"]) {
                                if($this->verifyAgainst($Data, $this->Validators[substr($SubType,0,strlen($SubType)-1)]["VerifyAgainst"])) return true;
                                else return false;
                            }
                            else return true;
                        }
                    }
                    return false;
                }
                else return false;
            }
        }
        else return false;
    }

    private function verifyAgainst($Data, $VerifySrc) {
        if(is_array($this->VerifySrcs[$VerifySrc])) {
            $VerifyQuery = $this->VerifySrcs[$VerifySrc]["Query"];
            if(!$this->srvSafeGuard(
                "ReadOnlyQuery",
                $VerifyQuery,
                array(
                    $VerifySrc
                )
            )) return false;
            $VerifyQuery = str_replace("[-QUERY_DATA-]", $Data);
            $this->Utilities->dbExecuteQuery($VerifyQuery);
            // Verify funtionality is unfinished; complete database transaction and return true if verified and false if not
        }
        else return false;
    }

    public function verifyArguments($Received, $Required) {
        if(strstr($Required, "||")) $Required = explode("||",$Required);
        else $Required = array($Required);
        $ReceivedCount = count($Received);
        $RequiredCount = count($Required);
        $Parameters = array();
        $MatchCount = 0;
        foreach($Required as $Parameter) {
            $Parameter = explode("::",$Parameter);
            if(substr($Parameter[1],0,1) == "*") {
                $Parameter[1] = substr($Parameter[1],1);
                $OptionalEncountered = true;
                $Parameters[$Parameter[0]] = $Parameter[1]."*";
            }
            else $Parameters[$Parameter[0]] = $Parameter[1];
        }
        foreach($Received as $Argument) {
            $Argument = explode("::",$Argument);
            if(array_key_exists($Argument[0],$Parameters)) {
                $ValidateType = $Parameters[$Argument[0]];
                if($this->validateData($Argument[1],$ValidateType)) $MatchCount++;
            }
            elseif(array_key_exists($Argument[0]."*",$Parameters)) {
                $ValidateType = $Parameters[$Argument[0]];
                if($this->validateData($Argument[1],$ValidateType)) $MatchCount++;
            }
        }
        
        if($OptionalEncountered);
        elseif($ReceivedCount !== $RequiredCount) return false;
        if($MatchCount !== $ReceivedCount) return false;
        elseif($MatchCount == $RequiredCount) return true;
        else return false;
    }
    
    public function srvSafeGuard($SafetyTest, $Data, $Params = false) {
        switch($SafetyTest) {
            case "ReadOnlyQuery":
                $BadCmds = array("ALTER","BACKUP","BEGIN","COMMIT","CREATE","DBCC","DELETE","DESCRIBE","DISABLE","DROP","ENABLE","EXEC","EXECUTE","EXISTS","FLUSH","GO","GRANT","INSERT","KILL","LOAD","REFERENCES","RESTORE","REVERT","REVOKE","ROLLBACK","SEND","SERVERPROPERTY","SESSION_USER","SESSIONPROPERTY","SET","SHOW","SHUTDOWN","TRUNCATE","UNION","UPDATE");
                foreach($BadCmds as $SafeCheck) {
                    if(stripos($Data, $SafeCheck) === false);
                    else {
                        $this->Utilities->mlSendMessage(
                            "serviceadmins@searchermedia.com", 
                            "Service SafeGuard - Potentially compromised file detected",
                            "The Service SafeGuard utility has detected a potentially malicious command in a VerifySrc module.\n\nModule: $Params[0]\nCommand: $SafeCheck",
                            true
                        );
                        exit;
                    }
                }
                return true;
				break;
        }
    }
}

class ServicePermissions {
    public function applicationUse($Application) {
        return true;
    }
}

class ServiceAccounts {
    
}

class ServiceUtilities {
    private $SQLAzureConnection;
    public $CurrentAcct;
    public $CurrentApp;

    public function __construct() {
        $this->dbConnect();
    }

    private function dbConnect() {
        if($this->SQLAzureConnection) return true;
        $SQLAzureDB = "tcp:example.com, 1433";
        $SQLAzureOptions = array(
            "Database" => "Database",
            "UID" => "dbadmin@smssdb",
            "PWD" => "smssRem0t3Db",
            "MultipleActiveResultSets" => false
        );
        $this->SQLAzureConnection = sqlsrv_connect($SQLAzureDB, $SQLAzureOptions);
        return true;
    }

    public function dbDisconnect() {
        if($this->SQLAzureConnection) return sqlsrv_close($this->SQLAzureConnection);
        else return true;
    }

    public function dbExecuteQuery($Query, $Params = false) {
        if($Params) return sqlsrv_query($this->SQLAzureConnection, $Query, $Params);
        else return sqlsrv_query($this->SQLAzureConnection, $Query);
    }

    public function dbFetchRow($Resource) {
        return sqlsrv_fetch_array($Resource, SQLSRV_FETCH_NUMERIC);
    }

    public function dbCountResults($Resource) {
        return sqlsrv_has_rows($Resource);
    }

    public function dbNextResult($Resource) {
        return sqlsrv_next_result($Resource);
    }

    public function dbInitializeUser($Username) {
        $AcctQuery = $this->dbExecuteQuery("SELECT * FROM dbo.Accounts WHERE Username='$Username'");
        $this->CurrentAcct = $this->dbFetchRow($AcctQuery);
        return ($this->dbCountResults($AcctQuery) ? true : false);
    }
    
    public function dbInitializeApp($SerialNumber, $ServiceKey) {
        $AppQuery = $this->dbExecuteQuery("SELECT * FROM dbo.Applications WHERE SerialNumber='$SerialNumber' AND ServiceKey='$ServiceKey'");
        $this->CurrentApp = $this->dbFetchRow($AppQuery);
        return ($this->dbCountResults($AppQuery) ? true : false);
    }
    
    public function accountToUser($Resource = false) {
        if($Resource) {
            $ActionQuery = $this->dbExecuteQuery("SELECT Username FROM dbo.Accounts WHERE AcctNumber='$Resource'");
            $AccountData = $this->dbFetchRow($ActionQuery);
            return ($AccountData ? $AccountData[0] : false);
        }
        else return ($this->CurrentAcct ? $this->CurrentAcct[1] : false);
    }

    public function domainToSerial($Resource = false) {
        if($Resource) {
            $ActionQuery = $this->dbExecuteQuery("SELECT SerialNumber FROM dbo.Applications WHERE DomainName='$Resource'");
            $AppData = $this->dbFetchRow($ActionQuery);
            return ($AppData ? $AppData[0] : false);
        }
        else return ($this->CurrentApp ? $this->CurrentApp[1] : false);
    }

    public function userToAccount($Resource = false) {
        if($Resource) {
            $ActionQuery = $this->dbExecuteQuery("SELECT AcctNumber FROM dbo.Accounts WHERE Username='$Resource'");
            $AccountData = $this->dbFetchRow($ActionQuery);
            return ($AccountData ? $AccountData[0] : false);
        }
        else return ($this->CurrentAcct ? $this->CurrentAcct[0] : false);
    }

    public function serialToDomain($Resource = false) {
        if($Resource) {
            $ActionQuery = $this->dbExecuteQuery("SELECT DomainName FROM dbo.Applications WHERE SerialNumber='$Resource'");
            $AppData = $this->dbFetchRow($ActionQuery);
            return ($AppData ? $AppData[0] : false);
        }
        else return ($this->CurrentApp ? $this->CurrentApp[2] : false);
    }
    
	public function mlSendMessage($Recipient, $Subject, $Message, $UseHTML = true, $From = "no-reply@example.com") {
        if($UseHTML) {
			require_once "synservice/resources/templates/Service.Template.ServiceMail.inc";
			$HTMLMessage = str_replace("[-MAILBODY_DATA-]", $Message, $Template);
		}
		else $HTMLMessage = $Message;
		$MailParameters = array(
        		"api_user" => "azure_smssuser@azure.com",
        		"api_key" => "apikey!",
			"to" => $Recipient,
			"toname" => "Service Administrator",
			"subject" => $Subject,
        		"html" => $HTMLMessage,
        		"text" => $Message,
        		"from" => $From,
        		"fromname" => "Synapse Service"
      		);

		$MailURI = "https://sendgrid.com/api/mail.send.json";
		$MailConnection = curl_init($MailURI);
		curl_setopt($MailConnection, CURLOPT_POST, true);
		curl_setopt($MailConnection, CURLOPT_POSTFIELDS, $MailParameters);
		curl_setopt($MailConnection, CURLOPT_HEADER, false);
		curl_setopt($MailConnection, CURLOPT_SSL_VERIFYPEER, true);
		curl_setopt($MailConnection, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($MailConnection, CURLOPT_CAINFO, 'synservice/certificates/cacert.pem');
		curl_exec($MailConnection);
		curl_close($MailConnection);
        
	}

}

class SynapseService {
    public $Permissions; // Permissions toolkit
    public $Validators; // Data validators toolkit
    public $Accounts; // Synapse ID toolkit
    public $Utilities; // Utilities toolkit
    private $IncomingData; // Raw ServiceRequest data
    private $RequestData; // Raw ServiceRequest data

    public function __construct() {
        $this->Permissions = new ServicePermissions;
        $this->Utilities = new ServiceUtilities;
        $this->Validation = new ServiceValidators($this->Utilities);
        $this->Accounts = new ServiceAccounts;
        $this->IncomingData = unserialize(base64_decode($_POST["ServiceRequest"]));
        $RequestData = explode(".", $this->IncomingData["Host"]["Request"], 4);
        foreach($RequestData as $DataField) $this->RequestData[] = $DataField;
        $Parameters = explode("||", $this->RequestData[3]);
        $this->RequestData[3] = $Parameters[0];
        unset($Parameters[0]);
        $this->RequestData[4] = $Parameters;
        unset($Parameters, $RequestData);
        $this->Utilities->dbInitializeUser($this->IncomingData["User"]["Username"]);
        //if(!$this->Utilities->dbInitializeApp($this->IncomingData["Host"]["SerialNumber"], $this->IncomingData["Host"]["ServiceKey"])) $this->outputJSON("101:01");        
        $this->loadClass();
        exit;
	}

    public function logAccess($Response = false) {
        if(!$_POST['ServiceRequest']) return false;
        $LogTime = date('G:i:s Y', time());
        $LogDate = date('m-d-Y-l', time());
        $LogUser = ($this->IncomingData['User']['Username'] ? $this->IncomingData['User']['Username'] : 'anonymous');
        if($this->IncomingData['User']['IPAddress'] == '127.0.0.1' && $_SERVER['REMOTE_ADDR'] == '0.0.0.0') $AccessIdentifier = 'Developer';
        if($this->IncomingData['User']['IPAddress'] == '127.0.0.1' && $_SERVER['REMOTE_ADDR'] == '1.1.1.1') $AccessIdentifier = 'Cloud';
        else $AccessIdentifier = $_SERVER['REMOTE_ADDR'];
        $LogEntry = "$LogTime [$LogUser@".$AccessIdentifier.'] ['.$this->IncomingData['Host']['ServiceKey'].'] '.(strstr($this->IncomingData['Host']['Request'], '||')?strstr($this->IncomingData['Host']['Request'], '||', true):$this->IncomingData['Host']['Request'])." $Response \r\n";
        $EntryClient = ServicesBuilder::getInstance()->createQueueService('DefaultEndpointsProtocol=https;AccountName=smss;AccountKey=n+64bitkey+1f==');
        if($EntryClient->createMessage('ssologqueue', $LogEntry)) return true;
        else return false;
    }

    public function loadClass() {
        switch($this->RequestData[0]) {
            case "Synapse":
                if(file_exists("synservice/resources/classes/Service.Class.".$this->RequestData[1].".inc")) require_once "synservice/resources/classes/Service.Class.".$this->RequestData[1].".inc";
                else $this->outputJSON("101:04");
                break;
            default:
                $this->outputJSON("101:04");
        }
    }
    
    public function outputJSON($Values) {
        $this->Utilities->dbDisconnect();
        $Values = explode("|||", $Values);
        $ArrayJSON = array("Response" => $Values[0]);
        if(count($Values) > 1) {
            unset($Values[0]);
            foreach($Values as $KeyPair) {
                $KeyPair = explode("::", $KeyPair);
                $Key = $KeyPair[0];
                $Value = $KeyPair[1];
                $ArrayJSON[$Key] = $Value;
            }
        }
        header("Content-type: text/javascript");
        echo "ServerResponse(".json_encode($ArrayJSON).")";
        $this->logAccess($Values[0]);
        exit;
    }
}

if($_SERVER["HTTP_REFERER"]) $Synapse = new SynapseService;
else header("Location: http://example.com/");
exit;
?>