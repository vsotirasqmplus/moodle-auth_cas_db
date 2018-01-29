<?php

/**
 * Strings for component 'auth_cas_db', language 'en'
 *
 * @package   auth_cas_db
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

$string['pluginname'] = 'CAS server (SSO) with external database';
$string['auth_cas_db_dbsettings'] = 'External database settings';
$string['auth_cas_dbdescription'] =  'This method uses a CAS server (Central Authentication Service) to authenticate users in a Single Sign On environment (SSO). You can also use an external database to retrieve profile information. If the given username and password are valid according to CAS, Moodle creates a new user entry in its database, taking user attributes from the external database if required.';
$string['auth_cas_dbnodb'] = 'No external database server configured for CAS with DB! Syncing disabled.';
$string['pluginnotenabled'] = 'Plugin not enabled!';
$string['auth_cas_db_field_locked'] = 'You are trying to edit locked fields ({$a}). Please edit these fields in Drupal instead.';
