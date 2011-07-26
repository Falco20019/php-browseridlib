<?php
require_once("lib/jwt.php");
require_once("lib/idassertion.php");

$assertion = $_POST['assertion'];
$audience = $_POST['audience'];

if (!($assertion && $audience)) {
	echo json_encode(array("status"=>"failure", "reason"=>"need assertion and audience"));
	exit;
}

// allow client side XHR to access this WSAPI, see
// https://developer.mozilla.org/en/http_access_control
// for details
// FIXME: should we really allow this? It might encourage the wrong behavior
header('Access-Control-Allow-Origin: *');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
	header('Access-Control-Allow-Methods: POST');
	exit;
}

try {
	$assertionObj = new IDAssertion($assertion);
	$assertionObj->verify(
		$audience,
		function($payload) {
			$result = array(
				"status" => "okay",
				"email" => $payload->email,
				"audience" => $payload->audience,
				"valid-until" => $payload->{"valid-until"},
				"issuer" => $payload->issuer
			);
			echo json_encode($result);
			exit;
		},
		function($errorObj) {
			echo json_encode(array("status"=>"failure", "reason"=>$errorObj));
			exit;
		}
	);
} catch (Exception $e) {
	//console.log($e->getTraceAsString());
	echo json_encode(array("status"=>"failure", "reason"=>$e->getMessage()));
	exit;
}
?>