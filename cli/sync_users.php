<?php

/**
 * CAS DB user sync script.
 *
 * This script is meant to be called from a cronjob to sync moodle with the 
 * external database.
 *
 * Sample cron entry:
 * # 5 minutes past 4am
 * 5 4 * * * $sudo -u www-data /usr/bin/php /var/www/moodle/auth/cas_db/cli/sync_users.php
 *
 * Notes:
 *   - it is required to use the web server account when executing PHP CLI scripts
 *   - you need to change the "www-data" to match the apache user account
 *   - use "su" if "sudo" not available
 *   - If you have a large number of users, you may want to raise the memory limits
 *     by passing -d momory_limit=256M
 *   - For debugging & better logging, you are encouraged to use in the command line:
 *     -d log_errors=1 -d error_reporting=E_ALL -d display_errors=0 -d html_errors=0
 *
 * Performance notes:
 * We have optimized it as best as we could for PostgreSQL and MySQL, with 27K students
 * we have seen this take 10 minutes.
 *
 * @package    auth
 * @subpackage cas_db
 * @copyright  2007 Jerome Gutierrez - based on code by Martin Langhoff
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

define('CLI_SCRIPT', true);

require(dirname(dirname(dirname(dirname(__FILE__)))).'/config.php');
require_once($CFG->dirroot.'/course/lib.php');

// Ensure errors are well explained
set_debugging(DEBUG_DEVELOPER, true);

if (!is_enabled_auth('cas_db')) {
    error_log('[AUTH CAS DB] '.get_string('pluginnotenabled', 'auth_cas_db'));
    die;
}

$casauth = get_auth_plugin('cas_db');
$casauth->sync_users(true);

