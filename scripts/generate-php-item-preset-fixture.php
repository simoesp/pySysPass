<?php
// Author tests/fixtures/php_item_presets.json with the upstream sysPass
// ItemPreset classes (no database). All values are synthetic.
//
//   php scripts/generate-php-item-preset-fixture.php /path/to/sysPass /path/to/php-encryption \
//       > tests/fixtures/php_item_presets.json
error_reporting(E_ALL & ~E_DEPRECATED);
define('APP_ROOT', $argv[1]);
$defuseRoot = $argv[2];
spl_autoload_register(function ($class) use ($defuseRoot) {
    if (strpos($class, 'SP\\') === 0) {
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
if (!function_exists('__u')) {
    function __u($message) { return $message; }
}
if (!function_exists('logger')) {
    function logger($message, $level = 'DEBUG') {}
}

use SP\DataModel\ItemPreset\AccountPermission;
use SP\DataModel\ItemPreset\AccountPrivate;
use SP\DataModel\ItemPreset\Password;
use SP\DataModel\ItemPreset\SessionTimeout;
use SP\DataModel\ItemPresetData;

$password = new Password();
$password->setLength(14);
$password->setExpireTime(30);
$password->setScore(2);
$password->setRegex('[A-Z].*[0-9]');
$password->setUseNumbers(true);
$password->setUseLetters(true);
$password->setUseSymbols(true);
$password->setUseLower(true);
$password->setUseUpper(true);
$password->setUseImage(false);
$permission = new AccountPermission();
$permission->setUsersView([3, 4]);
$permission->setUsersEdit([5]);
$permission->setUserGroupsView([2]);
$permission->setUserGroupsEdit([6]);
$private = new AccountPrivate();
$private->setPrivateUser(true);
$private->setPrivateGroup(false);

$cases = [
    ['account.permission', $permission, 7, null, null, 5],
    ['account.private', $private, null, 2, null, 0],
    ['session.timeout', new SessionTimeout('192.168.10.0/24', 900), null, null, 3, 1],
    ['account.password', $password, 7, null, null, 0],
];
$out = [];
foreach ($cases as [$type, $object, $userId, $groupId, $profileId, $priority]) {
    $preset = new ItemPresetData();
    $preset->setType($type);
    if ($userId !== null) {
        $preset->setUserId($userId);
    }
    if ($groupId !== null) {
        $preset->setUserGroupId($groupId);
    }
    if ($profileId !== null) {
        $preset->setUserProfileId($profileId);
    }
    $preset->setPriority($priority);
    $out[] = [
        'type' => $type, 'userId' => $userId, 'userGroupId' => $groupId, 'userProfileId' => $profileId,
        'priority' => $priority, 'hash' => $preset->getHash(), 'data_base64' => base64_encode(serialize($object)),
    ];
}

echo json_encode([
    'source' => [
        'application' => 'sysPass',
        'upstream_commit' => '9d0e169d2163897238877fb65130db47fe1ddcfa',
        'authored_by' => 'Native ItemPresetData::getHash() and serialize() of SP\\DataModel\\ItemPreset objects',
    ],
    'presets' => $out,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
