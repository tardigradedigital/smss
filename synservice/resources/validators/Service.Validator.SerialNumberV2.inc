<?php
$Validator = array(
	"ValidatorName" => "SerialNumberV2",
	"Expression" => "/^[0-9]{4}-[0-9]{9}$/",
	"VerifyAgainst" => "SerialNumbers",
	"AlsoAllow" => array(
		"SerialNumber"
	)
);
?>