<?php

/**
 * Version details
 *
 * @package    auth_cas_db
 * @author     Martin Dougiamas
 * @author     Jerome GUTIERREZ
 * @author     Iñaky Arenaza
 * @author     Robert Mason
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

$plugin->version   = 2016012600;        // The current plugin version (Date: YYYYMMDDXX)
$plugin->requires  = 2014111007;        // Requires this Moodle version
$plugin->component = 'auth_cas_db';     // Full name of the plugin (used for diagnostics)
$plugin->dependencies = array(
  'auth_cas' => 2014111000,
  'auth_db' => 2014111000,
);
