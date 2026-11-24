<?php
// Spanish labels of the Hermes attributes (D-037) in the iTop console; the codes stay in English (schemas/, REST).
Dict::Add('ES CR', 'Spanish', 'Español, Castellano', array(
	'Hermes:security' => 'Seguridad (Hermes)',
	'Class:FunctionalCI/Attribute:internet_exposed' => 'Expuesto a internet',
	'Class:FunctionalCI/Attribute:internet_exposed+' => 'Si el activo se puede alcanzar desde internet. Hermes lo usa para priorizar.',
	'Class:FunctionalCI/Attribute:internet_exposed/Value:yes' => 'Sí',
	'Class:FunctionalCI/Attribute:internet_exposed/Value:no' => 'No',
	'Class:FunctionalCI/Attribute:confidentiality' => 'Confidencialidad de los datos',
	'Class:FunctionalCI/Attribute:confidentiality+' => 'Clasificación de la información que guarda o procesa el activo.',
	'Class:FunctionalCI/Attribute:confidentiality/Value:public' => 'Pública',
	'Class:FunctionalCI/Attribute:confidentiality/Value:classified' => 'Clasificada',
	'Class:FunctionalCI/Attribute:confidentiality/Value:highly_classified' => 'Altamente clasificada',
	'Class:FunctionalCI/Attribute:confidentiality/Value:unclassified' => 'Sin clasificar',
	'Class:FunctionalCI/Attribute:personal_data' => 'Datos personales',
	'Class:FunctionalCI/Attribute:personal_data+' => 'Si el activo guarda o procesa datos personales.',
	'Class:FunctionalCI/Attribute:personal_data/Value:yes' => 'Sí',
	'Class:FunctionalCI/Attribute:personal_data/Value:no' => 'No',
	'Class:FunctionalCI/Attribute:personal_data/Value:unknown' => 'Desconocido',
	'Class:FunctionalCI/Attribute:owner_id' => 'Dueño',
	'Class:FunctionalCI/Attribute:owner_id+' => 'Persona responsable del activo; Hermes la agrega como contacto de sus tickets.',
	'Class:FunctionalCI/Attribute:custodian_id' => 'Equipo custodio',
	'Class:FunctionalCI/Attribute:custodian_id+' => 'Equipo que opera el activo; recibe los tickets de Hermes.',
));
