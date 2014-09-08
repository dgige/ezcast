<?php

/*
* EZCAST Commons 
* Copyright (C) 2014 Université de Picardie Jules Verne
*
* Written by Julien Marignale <julien.marignale@u-picardie.fr>
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 3 of the License, or (at your option) any later version.
*
* This software is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

include dirname(__FILE__).'/lib_various.php';
include dirname(__FILE__).'/lib_auth_ldap.php';
include_once dirname(__FILE__).'/phpCAS/CAS.php';

/**
 * check if user credentials are ok and return an assoc array containing ['full_name'] and ['email'] ['login'] (['real_login']) of the user. failure returns false. Error message can be received via checkauth_last_error()
 * @global string $ldap_servers_auth_json_file path to the json file containing list of ldap servers for authentication
 * @return assoc_array|false
 */
function cas_checkauth($login, $password) {
    global $cas_server_auth_info_file;
    if (file_exists($cas_server_auth_info_file)) {
        if (!phpCAS::isAuthenticated()) {
            return false;
        }
        
        $cas_login = phpCAS::getUser();
        
        $info = cas_getinfo($cas_login);

        $userinfo = array();
        if (isset($info['full_name']))
            $userinfo['full_name'] = $info['full_name'];
        if (isset($info['email']))
            $userinfo['email'] = $info['email'];
        if ($userinfo) {
            $userinfo['login'] = $cas_login; //return login as normal login
            $userinfo['real_login'] = $cas_login; //return login as real login
            return $userinfo;
        } else {
            return false;
        }
    }
    else return false;
}

function cas_getinfo($login) {
    return ldap_getinfo($login);
}

function cas_login($service_url) {
    global $cas_server_auth_info_file;
    if (file_exists($cas_server_auth_info_file)) {
        # Fixe l'adresse du service
        phpCAS::setFixedServiceURL($service_url.'/index.php?action=cas_login');
        phpCAS::forceAuthentication();
    }
}

//end function
?>
