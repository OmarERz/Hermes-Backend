<?php
// Post-install provisioning of the test instance (runs inside the itop container, after the setup):
// organization, the system person used as caller_id, and two REST users (application tokens):
//   hermes-rest  least privilege (C16): REST Services User + "Hermes Backend" profile; what the backend uses
//   hermes-seed  Administrator + REST Services User; only the seed loader uses it to create the CMDB data
// Idempotent. iTop 3.2 generates application tokens itself (an encrypted string), so a token cannot be chosen:
// it is written to a file (mode 600) in the data volume and read from there by `make itop-token`.

if (PHP_SAPI !== 'cli') {
	exit(1);
}
require_once('/var/www/html/approot.inc.php');
require_once(APPROOT.'/application/startup.inc.php');

function FindOne(string $sClass, array $aKey): ?DBObject
{
	$oSearch = new DBObjectSearch($sClass);
	foreach ($aKey as $sAttCode => $value) {
		$oSearch->AddCondition($sAttCode, $value);
	}
	return (new DBObjectSet($oSearch))->Fetch();
}

function FindOrCreate(string $sClass, array $aKey, array $aFields = []): DBObject
{
	$oObj = FindOne($sClass, $aKey);
	if ($oObj !== null) {
		return $oObj;
	}
	$oObj = MetaModel::NewObject($sClass);
	foreach (array_merge($aKey, $aFields) as $sAttCode => $value) {
		$oObj->Set($sAttCode, $value);
	}
	$oObj->DBInsert();
	echo "created $sClass\n";
	return $oObj;
}

function CreateTokenUser(string $sLogin, array $aProfileNames, int $iPersonId, string $sTokenFile): void
{
	if (FindOne('UserToken', ['login' => $sLogin]) !== null) {
		echo "REST user $sLogin already exists\n";
		return;
	}
	$oUser = MetaModel::NewObject('UserToken');
	$oUser->Set('login', $sLogin);
	$oUser->Set('contactid', $iPersonId);
	$oUser->Set('language', 'EN US');
	$oUser->Set('scope', 'REST/JSON');
	$oProfiles = new ormLinkSet('UserToken', 'profile_list', DBObjectSet::FromScratch('URP_UserProfile'));
	foreach ($aProfileNames as $sName) {
		$oProfile = FindOne('URP_Profiles', ['name' => $sName]);
		if ($oProfile === null) {
			fwrite(STDERR, "profile '$sName' not found\n");
			exit(1);
		}
		$oLink = MetaModel::NewObject('URP_UserProfile');
		$oLink->Set('profileid', $oProfile->GetKey());
		$oLink->Set('reason', 'Hermes test instance');
		$oProfiles->AddItem($oLink);
	}
	$oUser->Set('profile_list', $oProfiles);
	$oUser->DBInsert();
	// AfterInsert() created the token and kept it in a protected property: this is the only moment it is readable
	$oProperty = new ReflectionProperty('AbstractApplicationToken', 'sToken');
	$oProperty->setAccessible(true);
	$sToken = (string) $oProperty->getValue($oUser);
	if ($sToken === '') {
		fwrite(STDERR, "iTop did not generate a token for $sLogin\n");
		exit(1);
	}
	file_put_contents($sTokenFile, $sToken."\n");
	chmod($sTokenFile, 0600);
	echo "created REST user $sLogin\n";
}

CMDBObject::SetTrackInfo('Hermes test instance provisioning');
$oOrg = FindOrCreate('Organization', ['name' => 'Demo-Lab']);
$oPerson = FindOrCreate('Person', ['name' => 'Hermes System', 'first_name' => 'Hermes', 'org_id' => $oOrg->GetKey()],
	['email' => 'hermes@example.test']);

CreateTokenUser('hermes-rest', ['REST Services User', 'Hermes Backend'], $oPerson->GetKey(),
	APPROOT.'data/hermes-rest-token');
CreateTokenUser('hermes-seed', ['REST Services User', 'Administrator'], $oPerson->GetKey(),
	APPROOT.'data/hermes-seed-token');

// Webhook for ARQ-02 / C12: when a UserRequest is updated, iTop POSTs the minimal strict-JSON payload
// {"class","id","ref"} to the backend, which re-reads the real state (the webhook is only a doorbell).
// Webhooks are synchronous with a 5 s timeout and are not retried, so the backend also reconciles periodically.
// ITOP_WEBHOOK_URL is configurable; ITOP_WEBHOOK_TOKEN, when set, is sent as `Authorization: Bearer`.
function ConfigureWebhook(): void
{
	$sUrl = getenv('ITOP_WEBHOOK_URL') ?: 'http://host.docker.internal:8000/api/itop/webhook';
	$sBearer = getenv('ITOP_WEBHOOK_TOKEN') ?: '';

	$oType = FindOne('RemoteApplicationType', ['name' => 'Other / Generic']);
	if ($oType === null) {
		fwrite(STDERR, "remote application type 'Other / Generic' not found\n");
		exit(1);
	}
	$oConnection = FindOrCreate('RemoteApplicationConnection', ['name' => 'Hermes backend'], [
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
	$oAction = FindOrCreate('ActionWebhook', ['name' => 'Hermes ticket updated'], [
		'description' => 'Doorbell for the Hermes backend (ARQ-02)',
		'status' => 'enabled', // "In production"
		'remoteapplicationconnection_id' => $oConnection->GetKey(),
		'method' => 'post',
		'path' => '',
		'headers' => $sHeaders,
		'payload' => $sPayload,
	]);
	if (FindOne('TriggerOnObjectUpdate', ['description' => 'Hermes: UserRequest updated']) !== null) {
		return;
	}
	$oTrigger = MetaModel::NewObject('TriggerOnObjectUpdate');
	$oTrigger->Set('description', 'Hermes: UserRequest updated');
	$oTrigger->Set('target_class', 'UserRequest');
	$oLinks = new ormLinkSet('TriggerOnObjectUpdate', 'action_list', DBObjectSet::FromScratch('lnkTriggerAction'));
	$oLink = MetaModel::NewObject('lnkTriggerAction');
	$oLink->Set('action_id', $oAction->GetKey());
	$oLink->Set('order', 1);
	$oLinks->AddItem($oLink);
	$oTrigger->Set('action_list', $oLinks);
	$oTrigger->DBInsert();
	echo "created trigger on UserRequest update\n";
}

ConfigureWebhook();
