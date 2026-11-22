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
