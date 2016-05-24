<?php
	if($this->RequestData[2] == "Version1") {
		if($this->RequestData[3] == "CloseSession") {
			if(!$this->Permissions->applicationUse("Nucleus")) $this->outputJSON("101:07");
			if($this->Utilities->CurrentAcct) {
		        $DbParams = array(
		        	time(),
		        	$this->Utilities->CurrentAcct[0],
		        	$this->IncomingData["User"]["IPAddress"],
		        	$this->IncomingData["User"]["NetworkID"],
		        	$this->IncomingData["Host"]["ServiceKey"],
		        	$this->IncomingData["Host"]["SerialNumber"],
		        	$this->IncomingData["Host"]["IPAddress"],
		        	$this->IncomingData["Host"]["HostName"]
		        );
		        $this->Utilities->dbExecuteQuery("{CALL dbo.CloseSession(?,?,?,?,?,?,?,?)}", $DbParams);
			}
			$this->outputJSON("1:00");
			exit;
		}
		elseif($this->RequestData[3] == "OpenSession") {
			if(!$this->Permissions->applicationUse("Nucleus")) $this->outputJSON("101:07");
			if(!$this->Validation->verifyArguments($this->RequestData[4], "Presession::Presession")) $this->outputJSON("101:06");
			list($Presession) = $this->Validation->parseArguments($this->RequestData[4]);
			$Presession = explode(":", $Presession);
			$Presession[0] = strtolower($Presession[0]);
		    $Response = 0;
			$DbParams = array(
		        $Presession[0],
		        $Presession[1],
		        time(),
		        $this->IncomingData["User"]["IPAddress"],
		        $this->IncomingData["User"]["NetworkID"],
		        $this->IncomingData["Host"]["ServiceKey"],
		        $this->IncomingData["Host"]["SerialNumber"],
		        $this->IncomingData["Host"]["IPAddress"],
		        $this->IncomingData["Host"]["HostName"],
		        array($Response, SQLSRV_PARAM_OUT)
		    );
		    $this->Utilities->dbNextResult($this->Utilities->dbExecuteQuery("{CALL dbo.OpenSession(?,?,?,?,?,?,?,?,?,?)}", $DbParams));
		    if(is_int($Response) && strlen($Response) == 3) $this->outputJSON(substr_replace($Response, ":", 1, 0));
		    elseif(is_int($Response) && strlen($Response) == 5) $this->outputJSON(substr_replace($Response, ":", 3, 0));
		    else $this->outputJSON("1:05");
			exit;
		}
		elseif($this->RequestData[3] == "VerifySession") {
			if(!$this->Permissions->applicationUse("Nucleus")) $this->outputJSON("101:07");
			if(!$this->Validation->verifyArguments($this->RequestData[4], "Username::AlphaNumeric||Password::AlphaNumeric")) $this->outputJSON("101:06");
			list($Username, $Password) = $this->Validation->parseArguments($this->RequestData[4]);
			if($this->Utilities->CurrentAcct) {
		        if($this->Utilities->CurrentAcct[1] !== $Username) $this->outputJSON("1:00");
		        $Response = 0;
		 		$DbParams = array(
			        $this->Utilities->userToAccount($this->IncomingData["User"]["Username"]),
			        $Username,
			        $Password,
			        $this->IncomingData["User"]["IPAddress"],
			        $this->IncomingData["User"]["NetworkID"],
			        time(),
			        $this->IncomingData["Host"]["ServiceKey"],
			        $this->IncomingData["Host"]["SerialNumber"],
			        $this->IncomingData["Host"]["IPAddress"],
			        $this->IncomingData["Host"]["HostName"],
			        array($Response, SQLSRV_PARAM_OUT)
		        );
		        $this->Utilities->dbNextResult($this->Utilities->dbExecuteQuery("{CALL dbo.VerifySession(?,?,?,?,?,?,?,?,?,?,?)}", $DbParams));
		        if(is_int($Response) && strlen($Response) == 3) $this->outputJSON(substr_replace($Response, ":", 1, 0));
		        elseif(is_int($Response) && strlen($Response) == 5) $this->outputJSON(substr_replace($Response, ":", 3, 0));
		        else $this->outputJSON("1:05");
	    	}
			else $this->outputJSON("1:00");
			exit;
		}
		else $this->outputJSON("101:04c");
	}
	else $this->outputJSON("101:05");
?>