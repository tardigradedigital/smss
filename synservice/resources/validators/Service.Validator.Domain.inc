<?php
$Validator = array(
	"ValidatorName" => "Domain",
	"Expression" => "/^([a-zA-Z0-9-]+)\.[a-zA-Z]{2,6}$/",
	"VerifyAgainst" => "",
	"AlsoAllow" => array(
		"DomainPort",
		"Subdomain",
		"IPAddress"
	)
);
?>