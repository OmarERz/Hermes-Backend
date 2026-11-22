<?php
// Hermes datamodel extension (D-037): five attributes on FunctionalCI plus the least-privilege backend profile.
// Test instance only: the production iTop owner installs the same module with the iTop setup (ESC-03b).
SetupWebPage::AddModule(
	__FILE__,
	'hermes-ci-attributes/1.0.0',
	array(
		'label' => 'Hermes CI attributes (D-037)',
		'category' => 'business',
		'dependencies' => array(
			'itop-config-mgmt/2.7.0',
			'itop-profiles-itil/1.0.0',
		),
		'mandatory' => false,
		'visible' => true,
		'auto_select' => true,
		'datamodel' => array(),
		'webservice' => array(),
		'data.struct' => array(),
		'data.sample' => array(),
		'doc.manual_setup' => '',
		'doc.more_information' => '',
		'settings' => array(),
	)
);
