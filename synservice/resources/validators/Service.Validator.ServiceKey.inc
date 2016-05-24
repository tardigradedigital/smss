<?php
$Validator = array(
	"ValidatorName" => "ServiceKey",
	"Expression" => "/^[a-zA-Z0-9]{32}$/",
	"VerifyAgainst" => "ServiceKeys",
	"AlsoAllow" => array(
		"ServiceKeyV2"
	)
);
?>