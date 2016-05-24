<?php
$Validator = array(
	"ValidatorName" => "SerialNumber",
	"Expression" => "/[0-9]{12}/",
	"VerifyAgainst" => "SerialNumbers",
	"AlsoAllow" => array(
		"SerialNumberV2"
	)
);
?>