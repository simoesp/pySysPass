<?php
// Reverse compatibility check: decode values written by pySysPass with the
// upstream sysPass PHP classes, exactly as sysPass reads them.
//
//   php scripts/verify-python-writes.php /path/to/sysPass /path/to/php-encryption [/path/to/plugin-Authenticator] < cases.json
//
// Input:  {"password_salt": "...", "master_password": "...",
//          "accounts": [{"pass": "...", "key": "..."}],
//          "links": [{"hash": "...", "data_base64": "..."}],
//          "hash_checks": [{"key": "...", "hash": "..."}],
//          "authenticator": [{"data": "...", "key": "..."}]}
// Output: {"accounts": ["plaintext", ...], "links": [{account fields}, ...], "hash_checks": [bool, ...]}
// All inputs are synthetic test data, never production secrets.
error_reporting(E_ALL & ~E_DEPRECATED);
define('APP_ROOT', $argv[1]);
$defuseRoot = $argv[2];
$authenticatorRoot = $argv[3] ?? null;
spl_autoload_register(function ($class) use ($defuseRoot, $authenticatorRoot) {
    $pluginPrefix = 'SP\\Modules\\Web\\Plugins\\Authenticator\\';
    if ($authenticatorRoot !== null && strpos($class, $pluginPrefix) === 0) {
        $path = $authenticatorRoot . '/src/lib/' . str_replace('\\', '/', substr($class, strlen($pluginPrefix))) . '.php';
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
// sysPass logs through a global helper; keep verification output clean.
if (!function_exists('logger')) {
    function logger($message, $level = 'DEBUG') {}
}

$input = json_decode(stream_get_contents(STDIN), true, 32, JSON_THROW_ON_ERROR);
$output = ['accounts' => [], 'links' => [], 'hash_checks' => []];

// Config.masterPwd: MasterPassService::checkMasterPassword() path.
foreach ($input['hash_checks'] ?? [] as $check) {
    $output['hash_checks'][] = SP\Core\Crypt\Hash::checkHashKey($check['key'], $check['hash']);
}

// Account.pass/Account.key: AccountService::getPasswordForId() path.
foreach ($input['accounts'] ?? [] as $account) {
    $output['accounts'][] = SP\Core\Crypt\Crypt::decrypt($account['pass'], $account['key'], $input['master_password']);
}

// PublicLink.data: AccountController::viewLinkAction() path.
foreach ($input['links'] ?? [] as $link) {
    $vault = unserialize(base64_decode($link['data_base64'], true), ['allowed_classes' => [SP\Core\Crypt\Vault::class]]);
    if (!$vault instanceof SP\Core\Crypt\Vault) {
        throw new RuntimeException('PublicLink.data is not a sysPass Vault');
    }
    $key = new SP\Services\PublicLink\PublicLinkKey($input['password_salt'], $link['hash']);
    $account = SP\Util\Util::unserialize(SP\DataModel\AccountExtData::class, $vault->getData($key->getKey()));
    if (!$account instanceof SP\DataModel\AccountExtData) {
        throw new RuntimeException('Vault payload is not AccountExtData');
    }
    $output['links'][] = [
        'id' => $account->getId(), 'name' => $account->getName(), 'login' => $account->getLogin(),
        'url' => $account->getUrl(), 'notes' => $account->getNotes(), 'pass' => $account->getPass(),
        'key' => $account->getKey(), 'clientName' => $account->getClientName(),
        'categoryName' => $account->getCategoryName(), 'timeSet' => $vault->getTimeSet(),
    ];
}

// PluginData (Authenticator): PluginDataService::getByItemId() + PluginOperation::get().
foreach ($input['authenticator'] ?? [] as $row) {
    $serialized = SP\Core\Crypt\Crypt::decrypt($row['data'], $row['key'], $input['master_password']);
    $data = SP\Util\Util::unserialize(SP\Modules\Web\Plugins\Authenticator\Models\AuthenticatorData::class, $serialized);
    $output['authenticator'][] = [
        'userId' => $data->getUserId(), 'enabled' => $data->isTwofaEnabled(), 'date' => $data->getDate(),
        'expireDays' => $data->getExpireDays(), 'IV' => $data->getIV(),
        'recoveryCodes' => $data->getRecoveryCodes(), 'lastRecoveryTime' => $data->getLastRecoveryTime(),
        // The plugin's own TOTP check against the stored seed.
        'totpMatches' => isset($row['totp']) ? SP\Modules\Web\Plugins\Authenticator\Util\Google2FA::verify_key($data->getIV(), $row['totp']) : null,
    ];
}

// ItemPreset rows: ItemPresetData::hydrate() and getHash(), as PHP's services use them.
$presetClasses = [
    'account.permission' => SP\DataModel\ItemPreset\AccountPermission::class,
    'account.private' => SP\DataModel\ItemPreset\AccountPrivate::class,
    'session.timeout' => SP\DataModel\ItemPreset\SessionTimeout::class,
    'account.password' => SP\DataModel\ItemPreset\Password::class,
];
foreach ($input['item_presets'] ?? [] as $row) {
    $preset = new SP\DataModel\ItemPresetData();
    $preset->setType($row['type']);
    foreach (['userId' => 'setUserId', 'userGroupId' => 'setUserGroupId', 'userProfileId' => 'setUserProfileId'] as $key => $setter) {
        if ($row[$key] !== null) {
            $preset->$setter($row[$key]);
        }
    }
    $preset->setPriority($row['priority']);
    $preset->setData(base64_decode($row['data_base64'], true));
    $object = $preset->hydrate($presetClasses[$row['type']]);
    $getters = [];
    foreach (get_class_methods($object) as $method) {
        if (preg_match('/^(get|is)[A-Z]/', $method) && (new ReflectionMethod($object, $method))->getNumberOfParameters() === 0) {
            $getters[$method] = $object->$method();
        }
    }
    $output['item_presets'][] = ['hash' => $preset->getHash(), 'values' => $getters];
}

echo json_encode($output, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
