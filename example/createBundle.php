<pre>
<?php
// Comment the following line out to test the script!
//die();

//error_reporting(0);
require_once("../lib/browserid.php");

$publicKeyIdentity = AbstractPublicKey::deserialize('{"algorithm":"DS","p":"ff600483db6abfc5b45eab78594b3533d550d9f1bf2a992a7a8daa6dc34f8045ad4e6e0c429d334eeeaaefd7e23d4810be00e4cc1492cba325ba81ff2d5a5b305a8d17eb3bf4a06a349d392e00d329744a5179380344e82a18c47933438f891e22aeef812d69c8f75e326cb70ea000c3f776dfdbd604638c2ef717fc26d02e17","q":"e21e04f911d1ed7991008ecaab3bf775984309c3","g":"c52a4a0ff3b7e61fdf1867ce84138369a6154f4afa92966e3c827e25cfa6cf508b90e5de419e1337e07a2e9e2a3cd5dea704d175f8ebf6af397d69e110b96afb17c7a03259329e4829b0d03bbc7896b15b4ade53e130858cc34d96269aa89041f409136c7242a38895c9d5bccad4f389af1d7a4bd1398bd072dffa896233397a","y":"80942e74d41162e7ab30bb4a7a1e0fb0417aad0a1b55b12e0232618502a2552510d631a02a679e60787b12799215b9c35865efb4c86b56584bf85c31f886b25413dc7ef028917e9afbe35726849cfe28a43fba6cdd8e24f4575d5d582317183599c23399e90f10b7e5c0f2bcf7a37e0559dbe492a17a74a49597b0996a2b616d"}');
$secretKeyIdentity = AbstractSecretKey::deserialize('{"algorithm":"DS","p":"ff600483db6abfc5b45eab78594b3533d550d9f1bf2a992a7a8daa6dc34f8045ad4e6e0c429d334eeeaaefd7e23d4810be00e4cc1492cba325ba81ff2d5a5b305a8d17eb3bf4a06a349d392e00d329744a5179380344e82a18c47933438f891e22aeef812d69c8f75e326cb70ea000c3f776dfdbd604638c2ef717fc26d02e17","q":"e21e04f911d1ed7991008ecaab3bf775984309c3","g":"c52a4a0ff3b7e61fdf1867ce84138369a6154f4afa92966e3c827e25cfa6cf508b90e5de419e1337e07a2e9e2a3cd5dea704d175f8ebf6af397d69e110b96afb17c7a03259329e4829b0d03bbc7896b15b4ade53e130858cc34d96269aa89041f409136c7242a38895c9d5bccad4f389af1d7a4bd1398bd072dffa896233397a","x":"a8e62a39c007ab3b7fbaad2e51398c15ec4a720c"}');

$principal = $_REQUEST['principal'];
$audience = $_REQUEST['audience'];

echo "Usage: createBundle.php?principal=<principal>&audience=<audience>\r\n";
echo "Allowed keysizes: 64, 128, 256!\r\n";

$assertion = CertAssertion::createAssertion($audience, $secretKeyIdentity);
echo "Assertion: "; var_dump(WebToken::parse($assertion)->getPayload());
echo "\r\n";

$identityCert = CertAssertion::createIdentityCert($principal, $publicKeyIdentity);
echo "Identity Cert: "; var_dump(WebToken::parse($identityCert)->getPayload());
echo "\r\n";

$bundle = new CertBundle($assertion, array($identityCert));
$assertion = $bundle->bundle();
echo "Bundle: "; var_dump($assertion);
echo "\r\n";

$certAssertion = new CertAssertion($assertion, $audience);
echo "isValid: "; var_dump($certAssertion->isValid());
?>
</pre>