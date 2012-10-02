<pre>
<?php
// Comment the following line out to test the script!
die();

error_reporting(0);
require_once("../lib/browserid.php");

$name = $_REQUEST["name"];
$keysize = (int)$_REQUEST["keysize"];

echo "Usage: createKeys.php?name=<name>&keysize=<keysize>\r\n";
echo "Allowed keysizes: 64, 128, 256!\r\n";

// Generate keypair:
echo "Generate key pair with keysize $keysize...\r\n";
$pair = RSAKeyPair::generate($keysize);
echo "Keys were generated!\r\n";

// Write secret key to file:
echo "Write Secret Key...\r\n";
$pathSecretKey = Secrets::getPathSecretKey($name);
$handle = fopen($pathSecretKey, "w+");
fwrite($handle, $pair->getSecretKey()->serialize());
fclose($handle);
echo "Secret Key was written to " . $pathSecretKey . "\r\n";

// Write public key to file:
echo "Write Public Key...\r\n";
$pathPublicKey = Secrets::getPathPublicKey($name);
$public = array("public-key"=>json_decode($pair->getPublicKey()->serialize(), true));
$token = new WebToken($public);
$handle = fopen($pathPublicKey, "w+");
fwrite($handle, $token->serialize($pair->getSecretKey()));
fclose($handle);
echo "Public Key was written to " . $pathPublicKey . "\r\n";
?>
</pre>