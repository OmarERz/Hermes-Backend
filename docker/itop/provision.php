<?php
// Post-install provisioning of the Hermes iTop (runs inside the itop container as www-data, after the setup).
//   php provision.php                     organization, system person, REST and cron users, webhook (idempotent)
//   php provision.php seed-user on|off    enable (with a fresh token) or disable the loader's administrator token
//   php provision.php rotate-rest-token   give the backend's REST user a new token (the old one stops working)
// Users:
//   hermes-rest  least privilege (C16): REST Services User + "Hermes Backend" profile; what the backend uses
//   hermes-seed  Administrator + REST Services User; only the inventory loader uses it, and only while it loads:
//                `make itop-seed` turns it on, loads, and turns it off again (disabled, token file deleted)
//   hermes-cron  local Administrator for webservices/cron.php; its password lives only in a param file
// iTop 3.2 generates application tokens itself (an encrypted string), so a token cannot be chosen: it is written to a
// file (mode 600) in the data volume and read from there by `make itop-token`. Every object is created when missing
// and brought back to the wanted values when it drifted (webhook URL and token rotation).

if (PHP_SAPI !== 'cli') {
	exit(1);
}
require_once('/var/www/html/approot.inc.php');
require_once(APPROOT.'/application/startup.inc.php');

umask(0077); // token and param files: readable by www-data only

const REST_TOKEN_FILE = APPROOT.'data/hermes-rest-token';
const SEED_TOKEN_FILE = APPROOT.'data/hermes-seed-token';
const CRON_PARAM_FILE = APPROOT.'data/hermes-cron.params';

function Fail(string $sMessage): void
{
	fwrite(STDERR, $sMessage."\n");
	exit(1);
}

function FindOne(string $sClass, array $aKey): ?DBObject
{
	$oSearch = new DBObjectSearch($sClass);
	foreach ($aKey as $sAttCode => $value) {
		$oSearch->AddCondition($sAttCode, $value);
	}
	return (new DBObjectSet($oSearch))->Fetch();
}

// Upsert: create the object when missing, otherwise set the fields that differ from the wanted values.
function Upsert(string $sClass, array $aKey, array $aFields = []): DBObject
{
	$oObj = FindOne($sClass, $aKey);
	if ($oObj === null) {
		$oObj = MetaModel::NewObject($sClass);
		foreach (array_merge($aKey, $aFields) as $sAttCode => $value) {
			$oObj->Set($sAttCode, $value);
		}
		$oObj->DBInsert();
		echo "created $sClass\n";
		return $oObj;
	}
	$aChanged = [];
	foreach ($aFields as $sAttCode => $value) {
		if ((string) $oObj->Get($sAttCode) !== (string) $value) {
			$oObj->Set($sAttCode, $value);
			$aChanged[] = $sAttCode;
		}
	}
	if ($aChanged !== []) {
		$oObj->DBUpdate();
		echo "updated $sClass: ".implode(', ', $aChanged)."\n"; // field names only, never their values
	}
	return $oObj;
}

function ProfileLinks(string $sUserClass, array $aProfileNames): ormLinkSet
{
	$oProfiles = new ormLinkSet($sUserClass, 'profile_list', DBObjectSet::FromScratch('URP_UserProfile'));
	foreach ($aProfileNames as $sName) {
		$oProfile = FindOne('URP_Profiles', ['name' => $sName]);
		if ($oProfile === null) {
			Fail("profile '$sName' not found");
		}
		$oLink = MetaModel::NewObject('URP_UserProfile');
		$oLink->Set('profileid', $oProfile->GetKey());
		$oLink->Set('reason', 'Hermes');
		$oProfiles->AddItem($oLink);
	}
	return $oProfiles;
}

// The clear token only exists in a protected property, right after iTop generated it.
function ClearToken(DBObject $oUser): string
{
	$oProperty = new ReflectionProperty('AbstractApplicationToken', 'sToken');
	$oProperty->setAccessible(true);
	$sToken = (string) $oProperty->getValue($oUser);
	if ($sToken === '') {
		Fail('iTop did not generate a token for '.$oUser->Get('login'));
	}
	return $sToken;
}

function WriteSecretFile(string $sFile, string $sContent): void
{
	if (file_put_contents($sFile, $sContent) === false || !chmod($sFile, 0600)) {
		Fail("cannot write $sFile");
	}
}

// Creates the token user (and its token file) when missing. With $bNewToken, an existing user gets a new token and
// is enabled again: iTop has no public call for that, so the private generator is invoked like the setup does.
function EnsureTokenUser(string $sLogin, array $aProfileNames, int $iPersonId, string $sTokenFile, bool $bNewToken): void
{
	$oUser = FindOne('UserToken', ['login' => $sLogin]);
	if ($oUser === null) {
		$oUser = MetaModel::NewObject('UserToken');
		$oUser->Set('login', $sLogin);
		$oUser->Set('contactid', $iPersonId);
		$oUser->Set('language', 'EN US'); // REST messages in English, whatever the console language is
		$oUser->Set('scope', 'REST/JSON');
		$oUser->Set('profile_list', ProfileLinks('UserToken', $aProfileNames));
		$oUser->DBInsert(); // AfterInsert() generates the token
		WriteSecretFile($sTokenFile, ClearToken($oUser)."\n");
		echo "created REST user $sLogin\n";
		return;
	}
	if (!$bNewToken) {
		echo "REST user $sLogin already exists\n";
		return;
	}
	$oGenerator = new ReflectionMethod('AbstractApplicationToken', 'CreateNewToken');
	$oGenerator->setAccessible(true);
	$oGenerator->invoke($oUser);
	$oUser->Set('status', 'enabled');
	$oUser->DBUpdate();
	WriteSecretFile($sTokenFile, ClearToken($oUser)."\n");
	echo "REST user $sLogin enabled with a new token\n";
}

function DisableTokenUser(string $sLogin, string $sTokenFile): void
{
	$oUser = FindOne('UserToken', ['login' => $sLogin]);
	if ($oUser !== null && $oUser->Get('status') !== 'disabled') {
		$oUser->Set('status', 'disabled');
		$oUser->DBUpdate();
		echo "REST user $sLogin disabled\n";
	}
	if (file_exists($sTokenFile) && !unlink($sTokenFile)) {
		Fail("cannot delete $sTokenFile");
	}
}

// Letters and digits only: the param file format treats '#' as the start of a comment.
function RandomPassword(): string
{
	$sAlphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
	$sPassword = 'Cr0n-'; // upper, lower, digit and symbol, whatever the password policy asks for
	for ($i = 0; $i < 32; $i++) {
		$sPassword .= $sAlphabet[random_int(0, strlen($sAlphabet) - 1)];
	}
	return $sPassword;
}

// The administrator account cron.php logs in with. A missing param file (or a missing user) gets a new password.
function EnsureCronUser(int $iPersonId): void
{
	$oUser = FindOne('UserLocal', ['login' => 'hermes-cron']);
	if ($oUser !== null && is_readable(CRON_PARAM_FILE)) {
		echo "cron user hermes-cron already exists\n";
		return;
	}
	$sPassword = RandomPassword();
	if ($oUser === null) {
		$oUser = MetaModel::NewObject('UserLocal');
		$oUser->Set('login', 'hermes-cron');
		$oUser->Set('contactid', $iPersonId);
		$oUser->Set('language', 'EN US');
		$oUser->Set('profile_list', ProfileLinks('UserLocal', ['Administrator']));
	}
	if (MetaModel::IsValidAttCode('UserLocal', 'expiration')) {
		$oUser->Set('expiration', 'never_expire');
	}
	$oUser->Set('password', $sPassword);
	$oUser->Set('status', 'enabled');
	$oUser->DBWrite();
	WriteSecretFile(CRON_PARAM_FILE, "auth_user=hermes-cron\nauth_pwd=$sPassword\n");
	echo "cron user hermes-cron ready\n";
}

// Webhook for ARQ-02 / C12: when a UserRequest is updated, iTop POSTs the minimal strict-JSON payload
// {"class","id","ref"} to the backend, which re-reads the real state (the webhook is only a doorbell).
// Webhooks are synchronous with a 5 s timeout and are not retried, so the backend also reconciles periodically.
// ITOP_WEBHOOK_URL is configurable; the token (ITOP_WEBHOOK_TOKEN_FILE, else ITOP_WEBHOOK_TOKEN), when set, is sent as
// `Authorization: Bearer`. Running provision again applies a new URL or token to the existing objects.
function WebhookToken(): string
{
	$sFile = getenv('ITOP_WEBHOOK_TOKEN_FILE') ?: '';
	if ($sFile === '') {
		return getenv('ITOP_WEBHOOK_TOKEN') ?: '';
	}
	$sToken = @file_get_contents($sFile);
	if ($sToken === false) {
		Fail("cannot read $sFile");
	}
	return rtrim($sToken, "\r\n");
}

function ConfigureWebhook(): void
{
	$sUrl = getenv('ITOP_WEBHOOK_URL') ?: 'http://host.docker.internal:8000/api/itop/webhook';
	$sBearer = WebhookToken();
	if (preg_match('/[\r\n]/', $sBearer)) {
		Fail('the webhook token must be a single line');
	}

	$oType = FindOne('RemoteApplicationType', ['name' => 'Other / Generic']);
	if ($oType === null) {
		Fail("remote application type 'Other / Generic' not found");
	}
	$oConnection = Upsert('RemoteApplicationConnection', ['name' => 'Hermes backend'], [
		'remoteapplicationtype_id' => $oType->GetKey(),
		'environment' => '3-production', // iTop's code for production
		'url' => $sUrl,
	]);
	$sHeaders = 'Content-Type: application/json';
	if ($sBearer !== '') {
		$sHeaders .= "\nAuthorization: Bearer ".$sBearer;
	}
	// Only class, id and ref: titles and descriptions would break the JSON with their quotes (analysis §5.8)
	$sPayload = '{"class":"$this->finalclass$","id":"$this->id$","ref":"$this->ref$"}';
	$oAction = Upsert('ActionWebhook', ['name' => 'Hermes ticket updated'], [
		'description' => 'Doorbell for the Hermes backend (ARQ-02)',
		'status' => 'enabled', // "In production"
		'remoteapplicationconnection_id' => $oConnection->GetKey(),
		'method' => 'post',
		'path' => '',
		'headers' => $sHeaders,
		'payload' => $sPayload,
	]);
	$oTrigger = FindOne('TriggerOnObjectUpdate', ['description' => 'Hermes: UserRequest updated']);
	if ($oTrigger === null) {
		$oTrigger = MetaModel::NewObject('TriggerOnObjectUpdate');
		$oTrigger->Set('description', 'Hermes: UserRequest updated');
		$oTrigger->Set('target_class', 'UserRequest');
		echo "created trigger on UserRequest update\n";
	}
	$oLinks = $oTrigger->Get('action_list');
	foreach ($oLinks as $oLink) {
		if ((int) $oLink->Get('action_id') === (int) $oAction->GetKey()) {
			return; // already rings the webhook
		}
	}
	$oLink = MetaModel::NewObject('lnkTriggerAction');
	$oLink->Set('action_id', $oAction->GetKey());
	$oLink->Set('order', 1);
	$oLinks->AddItem($oLink);
	$oTrigger->Set('action_list', $oLinks);
	$oTrigger->DBWrite();
	echo "linked the webhook to the UserRequest update trigger\n";
}

CMDBObject::SetTrackInfo('Hermes provisioning');
$oOrg = Upsert('Organization', ['name' => 'Demo-Lab']);
$oPerson = Upsert('Person', ['name' => 'Hermes System', 'first_name' => 'Hermes', 'org_id' => $oOrg->GetKey()],
	['email' => 'hermes@example.test']);
$iPerson = (int) $oPerson->GetKey();

$sCommand = implode(' ', array_slice($argv, 1));
switch ($sCommand) {
	case '':
		EnsureTokenUser('hermes-rest', ['REST Services User', 'Hermes Backend'], $iPerson, REST_TOKEN_FILE, false);
		EnsureCronUser($iPerson);
		ConfigureWebhook();
		break;
	case 'seed-user on':
		EnsureTokenUser('hermes-seed', ['REST Services User', 'Administrator'], $iPerson, SEED_TOKEN_FILE, true);
		break;
	case 'seed-user off':
		DisableTokenUser('hermes-seed', SEED_TOKEN_FILE);
		break;
	case 'rotate-rest-token':
		EnsureTokenUser('hermes-rest', ['REST Services User', 'Hermes Backend'], $iPerson, REST_TOKEN_FILE, true);
		break;
	default:
		Fail('usage: php provision.php [seed-user on|off | rotate-rest-token]');
}
