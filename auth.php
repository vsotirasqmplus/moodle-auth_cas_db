<?php

/**
 * @author Martin Dougiamas
 * @author Jerome GUTIERREZ
 * @author Iñaki Arenaza
 * @author Robert Mason
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 *
 * Authentication Plugin: CAS with external database authentication
 *
 * Authentication using CAS (Central Authentication Server) and an external 
 *  database to fetch user profile data instead of LDAP.
 * 
 */

if (!defined('MOODLE_INTERNAL')) {
    die('Direct access to this script is forbidden.');    ///  It must be included from a Moodle page
}

require_once($CFG->dirroot.'/auth/db/auth.php');
require_once($CFG->dirroot.'/auth/cas/CAS/CAS.php');

/**
 * CAS + DB authentication plugin.
 */
class auth_plugin_cas_db extends auth_plugin_db {

    /**
     * Constructor.
     */
    function auth_plugin_cas_db() {
        global $CFG;
        require_once($CFG->libdir.'/adodb/adodb.inc.php');
        
        $this->authtype = 'cas_db';
        $this->roleauth = 'auth_cas_db';
        $this->pluginconfig = 'auth/' . $this->authtype;
        $this->config = get_config($this->pluginconfig);
        if (empty($this->config->extencoding)) {
            $this->config->extencoding = 'utf-8';
        }
    }
    
    /**
     * Indicates if password hashes should be stored in local moodle database.
     * 
     * @return bool False if password hashes should be stored locally.
     */
    function prevent_local_passwords() {
        return true;
    }

    /**
     * Authenticates user against CAS
     * Returns true if the username and password work and false if they are
     * wrong or don't exist.
     *
     * @param string $username The username (with system magic quotes)
     * @param string $password The password (with system magic quotes)
     * @return bool Authentication success or failure.
     */
    function user_login ($username, $password) {
        $this->connectCAS();
        return phpCAS::isAuthenticated() && (trim(core_text::strtolower(phpCAS::getUser())) == $username);
    }

    /**
     * Returns true if this authentication plugin is 'internal'.
     *
     * @return bool
     */
    function is_internal() {
        return false;
    }

    /**
     * Returns true if this authentication plugin can change the user's
     * password.
     *
     * @return bool
     */
    function can_change_password() {
        return false;
    }

    /**
     * Authentication choice (CAS or other)
     * Redirection to the CAS form or to login/index.php
     * for other authentication
     */
    function loginpage_hook() {
        global $frm;
        global $CFG;
        global $SESSION, $OUTPUT, $PAGE;

        $site = get_site();
        $CASform = get_string('CASform', 'auth_cas');
        $username = optional_param('username', '', PARAM_RAW);
        $courseid = optional_param('courseid', 0, PARAM_INT);

        if (!empty($username)) {
            if (isset($SESSION->wantsurl) && (strstr($SESSION->wantsurl, 'ticket') ||
                                              strstr($SESSION->wantsurl, 'NOCAS'))) {
                unset($SESSION->wantsurl);
            }
            return;
        }

        // Return if CAS enabled and settings not specified yet
        if (empty($this->config->hostname)) {
            return;
        }

        // If the multi-authentication setting is used, check for the param before connecting to CAS.
        if ($this->config->multiauth) {

            // If there is an authentication error, stay on the default authentication page.
            if (!empty($SESSION->loginerrormsg)) {
                return;
            }

            $authCAS = optional_param('authCAS', '', PARAM_RAW);
            if ($authCAS == 'NOCAS') {
                return;
            }
            // Show authentication form for multi-authentication.
            // Test pgtIou parameter for proxy mode (https connection in background from CAS server to the php server).
            if ($authCAS != 'CAS' && !isset($_GET['pgtIou'])) {
                $PAGE->set_url('/login/index.php');
                $PAGE->navbar->add($CASform);
                $PAGE->set_title("$site->fullname: $CASform");
                $PAGE->set_heading($site->fullname);
                echo $OUTPUT->header();
                include($CFG->dirroot.'/auth/cas/cas_form.html');
                echo $OUTPUT->footer();
                exit();
            }
        }

        // Connection to CAS server
        $this->connectCAS();

        if (phpCAS::checkAuthentication()) {
            $frm = new stdClass();
            $frm->username = phpCAS::getUser();
            $frm->password = 'passwdCas';

            // Redirect to a course if multi-auth is activated, authCAS is set to CAS and the courseid is specified.
            if ($this->config->multiauth && !empty($courseid)) {
                redirect(new moodle_url('/course/view.php', array('id'=>$courseid)));
            }

            return;
        }

        if (isset($_GET['loginguest']) && ($_GET['loginguest'] == true)) {
            $frm = new stdClass();
            $frm->username = 'guest';
            $frm->password = 'guest';
            return;
        }

        // Force CAS authentication (if needed).
        if (!phpCAS::isAuthenticated()) {
            phpCAS::setLang($this->config->language);
            phpCAS::forceAuthentication();
        }
    }

    /**
     * Connect to the CAS (clientcas connection or proxycas connection)
     *
     */
    function connectCAS() {
        global $CFG;
        static $connected = false;

        if (!$connected) {
            // Make sure phpCAS doesn't try to start a new PHP session when connecting to the CAS server.
            if ($this->config->proxycas) {
                phpCAS::proxy($this->config->casversion, $this->config->hostname, (int) $this->config->port, $this->config->baseuri, false);
            } else {
                phpCAS::client($this->config->casversion, $this->config->hostname, (int) $this->config->port, $this->config->baseuri, false);
            }
            $connected = true;
        }

        // If Moodle is configured to use a proxy, phpCAS needs some curl options set.
        if (!empty($CFG->proxyhost) && !is_proxybypass(phpCAS::getServerLoginURL())) {
            phpCAS::setExtraCurlOption(CURLOPT_PROXY, $CFG->proxyhost);
            if (!empty($CFG->proxyport)) {
                phpCAS::setExtraCurlOption(CURLOPT_PROXYPORT, $CFG->proxyport);
            }
            if (!empty($CFG->proxytype)) {
                // Only set CURLOPT_PROXYTYPE if it's something other than the curl-default http
                if ($CFG->proxytype == 'SOCKS5') {
                    phpCAS::setExtraCurlOption(CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
                }
            }
            if (!empty($CFG->proxyuser) and !empty($CFG->proxypassword)) {
                phpCAS::setExtraCurlOption(CURLOPT_PROXYUSERPWD, $CFG->proxyuser.':'.$CFG->proxypassword);
                if (defined('CURLOPT_PROXYAUTH')) {
                    // any proxy authentication if PHP 5.1
                    phpCAS::setExtraCurlOption(CURLOPT_PROXYAUTH, CURLAUTH_BASIC | CURLAUTH_NTLM);
                }
            }
        }

        if ($this->config->certificate_check && $this->config->certificate_path){
            phpCAS::setCasServerCACert($this->config->certificate_path);
        } else {
            // Don't try to validate the server SSL credentials
            phpCAS::setNoCasServerValidation();
        }
    }

    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     *
     * @param array $page An object containing all the data for this page.
     */
    function config_form($config, $err, $user_fields) {
        global $CFG, $OUTPUT;
        
        include($CFG->dirroot.'/auth/cas_db/config.html');
    }

    /**
     * A chance to validate form data, and last chance to
     * do stuff before it is inserted in config_plugin
     * @param object object with submitted configuration settings (without system magic quotes)
     * @param array $err array of error messages
     */
    function validate_form($form, &$err) {
        $certificate_path = trim($form->certificate_path);
        if ($form->certificate_check && empty($certificate_path)) {
            $err['certificate_path'] = get_string('auth_cas_certificate_path_empty', 'auth_cas');
        }
    }

    /**
     * Returns the URL for changing the user's pw, or empty if the default can
     * be used.
     *
     * @return moodle_url
     */
    function change_password_url() {
        return null;
    }

    /**
     * Processes and stores configuration data for this authentication plugin.
     */
    function process_config($config) {

        // CAS settings
        if (!isset($config->hostname)) {
            $config->hostname = '';
        }
        if (!isset($config->port)) {
            $config->port = '';
        }
        if (!isset($config->casversion)) {
            $config->casversion = '';
        }
        if (!isset($config->baseuri)) {
            $config->baseuri = '';
        }
        if (!isset($config->language)) {
            $config->language = '';
        }
        if (!isset($config->proxycas)) {
            $config->proxycas = '';
        }
        if (!isset($config->logoutcas)) {
            $config->logoutcas = '';
        }
        if (!isset($config->multiauth)) {
            $config->multiauth = '';
        }
        if (!isset($config->certificate_check)) {
            $config->certificate_check = '';
        }
        if (!isset($config->certificate_path)) {
            $config->certificate_path = '';
        }
        if (!isset($config->logout_return_url)) {
            $config->logout_return_url = '';
        }

        // external database settings
        if (!isset($config->host)) {
            $config->host = 'localhost';
        }
        if (!isset($config->type)) {
            $config->type = 'mysql';
        }
        if (!isset($config->sybasequoting)) {
            $config->sybasequoting = 0;
        }
        if (!isset($config->name)) {
            $config->name = '';
        }
        if (!isset($config->user)) {
            $config->user = '';
        }
        if (!isset($config->pass)) {
            $config->pass = '';
        }
        if (!isset($config->table)) {
            $config->table = '';
        }
        if (!isset($config->fielduser)) {
            $config->fielduser = '';
        }
        if (!isset($config->fieldpass)) {
            $config->fieldpass = '';
        }
        if (!isset($config->passtype)) {
            $config->passtype = 'plaintext';
        }
        if (!isset($config->extencoding)) {
            $config->extencoding = 'utf-8';
        }
        if (!isset($config->setupsql)) {
            $config->setupsql = '';
        }
        if (!isset($config->debugauthdb)) {
            $config->debugauthdb = 0;
        }
        if (!isset($config->removeuser)) {
            $config->removeuser = AUTH_REMOVEUSER_KEEP;
        }
        if (!isset($config->changepasswordurl)) {
            $config->changepasswordurl = '';
        }

        // save CAS settings
        set_config('hostname', trim($config->hostname), $this->pluginconfig);
        set_config('port', trim($config->port), $this->pluginconfig);
        set_config('casversion', $config->casversion, $this->pluginconfig);
        set_config('baseuri', trim($config->baseuri), $this->pluginconfig);
        set_config('language', $config->language, $this->pluginconfig);
        set_config('proxycas', $config->proxycas, $this->pluginconfig);
        set_config('logoutcas', $config->logoutcas, $this->pluginconfig);
        set_config('multiauth', $config->multiauth, $this->pluginconfig);
        set_config('certificate_check', $config->certificate_check, $this->pluginconfig);
        set_config('certificate_path', $config->certificate_path, $this->pluginconfig);
        set_config('logout_return_url', $config->logout_return_url, $this->pluginconfig);

        // save external database settings
        set_config('host',          $config->host,          $this->pluginconfig);
        set_config('type',          $config->type,          $this->pluginconfig);
        set_config('sybasequoting', $config->sybasequoting, $this->pluginconfig);
        set_config('name',          $config->name,          $this->pluginconfig);
        set_config('user',          $config->user,          $this->pluginconfig);
        set_config('pass',          $config->pass,          $this->pluginconfig);
        set_config('table',         $config->table,         $this->pluginconfig);
        set_config('fielduser',     $config->fielduser,     $this->pluginconfig);
        set_config('fieldpass',     $config->fieldpass,     $this->pluginconfig);
        set_config('passtype',      $config->passtype,      $this->pluginconfig);
        set_config('extencoding',   trim($config->extencoding), $this->pluginconfig);
        set_config('setupsql',      trim($config->setupsql),$this->pluginconfig);
        set_config('debugauthdb',   $config->debugauthdb,   $this->pluginconfig);
        set_config('removeuser',    $config->removeuser,    $this->pluginconfig);
        set_config('changepasswordurl', trim($config->changepasswordurl), $this->pluginconfig);

        return true;
    }

    /**
     * Reads user information from external database and returns it as array()
     *
     * If no external database is configured, user information has to be
     * provided via other methods (CSV file, manually, etc.). Return
     * an empty array so existing user info is not lost. Otherwise,
     * calls parent class method to get user info.
     *
     * @param string $username username
     * @return mixed array with no magic quotes or false on error
     */
    function get_userinfo($username) {
        if (empty($this->config->host)) {
            return array();
        }
        return parent::get_userinfo($username);
    }

    /**
     * Synchronizes user from external db to moodle user table.
     *
     * If no external database is configured, simply return. Otherwise,
     * call parent class method to do the work.
     *
     * @param progress_trace $trace
     * @param bool $do_updates  Optional: set to true to force an update of existing accounts
     * @return int 0 means success, 1 means failure
     */
    function sync_users(progress_trace $trace, $do_updates=false) {
        if (empty($this->config->host)) {
            error_log('[AUTH CAS DB] '.get_string('auth_cas_dbnodb', 'auth_cas_db'));
            return;
        }
        parent::sync_users($trace, $do_updates);
    }
    
    /**
     * Called when the user record is updated. It will modify the user 
     * information in external database.
     *
     * This does not actually update the external database, but it returns
     * true so that Moodle is happy.
     *
     * @param mixed $olduser     Userobject before modifications    (without system magic quotes)
     * @param mixed $newuser     Userobject new modified userobject (without system magic quotes)
     * @return boolean result
     *
     */
    function user_update($olduser, $newuser) {
      global $DB, $CFG;
      
      return true;
    }

    /**
    * Hook for logout page
    */
    function logoutpage_hook() {
        global $USER, $redirect;

        // Only do this if the user is actually logged in via CAS
        if ($USER->auth === $this->authtype) {
            // Check if there is an alternative logout return url defined
            if (isset($this->config->logout_return_url) && !empty($this->config->logout_return_url)) {
                // Set redirect to alternative return url
                $redirect = $this->config->logout_return_url;
            }
        }
    }

    /**
     * Post logout hook.
     *
     * Note: this method replace the prelogout_hook method to avoid redirect to CAS logout
     * before the event userlogout being triggered.
     *
     * @param stdClass $user clone of USER object object before the user session was terminated
     */
    public function postlogout_hook($user) {
        global $CFG;
        // Only redirect to CAS logout if the user is logged as a CAS user.
        if (!empty($this->config->logoutcas) && $user->auth == $this->authtype) {
            $backurl = !empty($this->config->logout_return_url) ? $this->config->logout_return_url : $CFG->wwwroot;
            $this->connectCAS();
            phpCAS::logoutWithRedirectService($backurl);
        }
    }
    
}
