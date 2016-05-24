<?php
$Validator = array(
	"ValidatorName" => "ServiceKeyV2",
	"Expression" => "/^[0-9]{2}-[0-9]{4}-[0-9]{24}$/",
	"VerifyAgainst" => "ServiceKeys",
	"AlsoAllow" => array(
		"ServiceKey"
	)
);
?>