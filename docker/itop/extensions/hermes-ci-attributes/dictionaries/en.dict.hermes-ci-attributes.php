<?php
// English labels of the Hermes attributes (D-037) in the iTop console.
Dict::Add('EN US', 'English', 'English', array(
	'Hermes:security' => 'Security (Hermes)',
	'Class:FunctionalCI/Attribute:internet_exposed' => 'Internet exposed',
	'Class:FunctionalCI/Attribute:internet_exposed+' => 'Whether the asset can be reached from the internet. Hermes uses it to prioritize.',
	'Class:FunctionalCI/Attribute:internet_exposed/Value:yes' => 'Yes',
	'Class:FunctionalCI/Attribute:internet_exposed/Value:no' => 'No',
	'Class:FunctionalCI/Attribute:confidentiality' => 'Data confidentiality',
	'Class:FunctionalCI/Attribute:confidentiality+' => 'Classification of the information the asset stores or processes.',
	'Class:FunctionalCI/Attribute:confidentiality/Value:public' => 'Public',
	'Class:FunctionalCI/Attribute:confidentiality/Value:classified' => 'Classified',
	'Class:FunctionalCI/Attribute:confidentiality/Value:highly_classified' => 'Highly classified',
	'Class:FunctionalCI/Attribute:confidentiality/Value:unclassified' => 'Unclassified',
	'Class:FunctionalCI/Attribute:personal_data' => 'Personal data',
	'Class:FunctionalCI/Attribute:personal_data+' => 'Whether the asset stores or processes personal data.',
	'Class:FunctionalCI/Attribute:personal_data/Value:yes' => 'Yes',
	'Class:FunctionalCI/Attribute:personal_data/Value:no' => 'No',
	'Class:FunctionalCI/Attribute:personal_data/Value:unknown' => 'Unknown',
	'Class:FunctionalCI/Attribute:owner_id' => 'Owner',
	'Class:FunctionalCI/Attribute:owner_id+' => 'Person accountable for the asset; Hermes adds them as a contact of its tickets.',
	'Class:FunctionalCI/Attribute:custodian_id' => 'Custodian team',
	'Class:FunctionalCI/Attribute:custodian_id+' => 'Team that runs the asset; it receives the Hermes tickets.',
));
