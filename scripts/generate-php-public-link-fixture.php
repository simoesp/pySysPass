<?php
// Run with upstream sysPass and defuse/php-encryption checkouts as arguments.
// All values below are synthetic test data, never production credentials.
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
    require_once $path;
});

$salt = 'public-link-fixture-salt-not-a-production-secret';
$hash = str_repeat('a1', 32);
$account = new SP\DataModel\AccountExtData();
$account->id = '17'; // PDO versions may expose numeric columns as strings.
$account->userId = 2;
$account->userGroupId = 1;
$account->userEditId = 2;
$account->name = 'PHP snapshot — café';
$account->login = 'fixture-user';
$account->pass = 'Synthetic-秘密-Password!';
$account->key = null;
$account->url = 'https://example.invalid/php-snapshot';
$account->notes = 'Stored when the public link was created.';
$account->categoryName = 'Fixture category';
$account->clientName = 'Fixture client';
// getDataForLink selects the names, leaving categoryId/clientId at zero.
$key = new SP\Services\PublicLink\PublicLinkKey($salt, $hash);
$vault = (new SP\Core\Crypt\Vault())->saveData(serialize($account), $key->getKey());
// Verify the fixture using the native reader before exporting it.
$roundTrip = unserialize($vault->getData($key->getKey()), ['allowed_classes' => [SP\DataModel\AccountExtData::class]]);
if ($roundTrip->pass !== $account->pass) {
    throw new RuntimeException('PHP Vault round trip failed');
}
echo json_encode([
    'source' => [
        'application' => 'sysPass',
        'upstream_commit' => '9d0e169d2163897238877fb65130db47fe1ddcfa',
        'defuse_version' => '2.4.0',
        'authored_by' => 'Native PublicLinkKey, AccountExtData and Vault::saveData; synthetic account',
    ],
    'password_salt' => $salt,
    'link' => ['itemId' => 17, 'hash' => $hash, 'typeId' => 1, 'data_base64' => base64_encode($vault->getSerialized())],
    'account' => [
        'id' => $account->id, 'name' => $account->name, 'login' => $account->login,
        'password' => $account->pass, 'url' => $account->url, 'notes' => $account->notes,
        'categoryId' => $account->categoryId, 'clientId' => $account->clientId,
        'categoryName' => $account->categoryName, 'clientName' => $account->clientName,
    ],
], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
