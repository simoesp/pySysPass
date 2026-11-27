<?php
// Author tests/fixtures/php_authenticator_plugindata.json with the upstream
// sysPass Authenticator plugin classes. All values are synthetic test data.
//
//   php scripts/generate-php-authenticator-fixture.php /path/to/sysPass /path/to/php-encryption \
//       /path/to/plugin-Authenticator > tests/fixtures/php_authenticator_plugindata.json
error_reporting(E_ALL & ~E_DEPRECATED);
define('APP_ROOT', $argv[1]);
$defuseRoot = $argv[2];
$pluginRoot = $argv[3];
spl_autoload_register(function ($class) use ($defuseRoot, $pluginRoot) {
    $pluginPrefix = 'SP\\Modules\\Web\\Plugins\\Authenticator\\';
    if (strpos($class, $pluginPrefix) === 0) {
        $path = $pluginRoot . '/src/lib/' . str_replace('\\', '/', substr($class, strlen($pluginPrefix))) . '.php';
    } elseif (strpos($class, 'SP\\') === 0) {
        $path = APP_ROOT . '/lib/' . str_replace('\\', '/', $class) . '.php';
    } elseif (strpos($class, 'Defuse\\Crypto\\') === 0) {
        $path = $defuseRoot . '/src/' . str_replace('\\', '/', substr($class, 14)) . '.php';
    } else {
        return;
    }
    if (is_file($path)) {
        require_once $path;
    }
});
if (!function_exists('logger')) {
    function logger($message, $level = 'DEBUG') {}
}

use SP\Core\Crypt\Crypt;
use SP\Modules\Web\Plugins\Authenticator\Models\AuthenticatorData;

$master = 'authenticator-fixture-master-not-a-secret';
$data = new AuthenticatorData();
$data->setUserId(7);
$data->setIV('JBSWY3DPEHPK3PXP');
$data->setTwofaEnabled(true);
$data->setExpireDays(90);
$data->setDate(1788742791);
$data->setRecoveryCodes(['0123456789abcdef0123', 'fedcba9876543210fedc']);
$data->setLastRecoveryTime(1788742800);

// PluginOperation::create() serializes; EncryptedModel::encrypt() protects it.
$key = Crypt::makeSecuredKey($master);
$encrypted = Crypt::encrypt(serialize($data), $key, $master);
if (unserialize(Crypt::decrypt($encrypted, $key, $master))->getIV() !== 'JBSWY3DPEHPK3PXP') {
    throw new RuntimeException('PHP round trip failed');
}

echo json_encode([
    'source' => [
        'application' => 'sysPass plugin-Authenticator',
        'syspass_commit' => '9d0e169d2163897238877fb65130db47fe1ddcfa',
        'plugin_commit' => 'b3046617b51656999fe7e277a1ec4a4d7e374732',
        'defuse_version' => '2.4.0',
        'authored_by' => 'Native AuthenticatorData, serialize() and EncryptedModel encryption; synthetic user',
    ],
    'master_password' => $master,
    'plugin_data' => ['name' => 'Authenticator', 'itemId' => 7, 'data' => $encrypted, 'key' => $key],
    'expected' => [
        'userId' => 7, 'IV' => 'JBSWY3DPEHPK3PXP', 'twofaEnabled' => true, 'expireDays' => 90,
        'date' => 1788742791, 'recoveryCodes' => ['0123456789abcdef0123', 'fedcba9876543210fedc'],
        'lastRecoveryTime' => 1788742800,
    ],
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
