<?php

class eZSimpleLDAPUser extends eZUser
{
    static function loginUser( $login, $password, $authenticationMatch = false )
    {
        $db = eZDB::instance();

        $loginEscaped = $db->escapeString( $login );
        $loginText = "login='$loginEscaped'";

        $contentObjectStatus = eZContentObject::STATUS_PUBLISHED;

        $query = "SELECT contentobject_id, password_hash, password_hash_type, email, login
                      FROM ezuser, ezcontentobject
                      WHERE ( $loginText ) AND
                            ezcontentobject.status='$contentObjectStatus' AND
                            ezcontentobject.id=contentobject_id";

        $users = $db->arrayQuery( $query );

        if ( count( $users ) >= 1 )
        {
            foreach ( $users as $userRow )
            {
                $userID = $userRow['contentobject_id'];

                if ( self::LDAPLogin( $login, $password ) )
                {
                    $canLogin = eZUser::isEnabledAfterFailedLogin( $userID );
                    // We should store userID for warning message.
                    $GLOBALS['eZFailedLoginAttemptUserID'] = $userID;

                    /** @var eZUserSetting $userSetting */
                    $userSetting = eZUserSetting::fetch( $userID );
                    $isEnabled = $userSetting->attribute( "is_enabled" );

                    if ( $isEnabled && $canLogin )
                    {
                        $user = new eZUser( $userRow );
                        eZUser::updateLastVisit( $userID );
                        eZUser::setCurrentlyLoggedInUser( $user, $userID );
                        eZUser::setFailedLoginAttempts( $userID, 0 );
                        return $user;
                    }
                }
            }
        }
        return false;
    }

    protected static function LDAPLogin( $login, $password )
    {
        $LDAPIni = eZINI::instance( 'ldap.ini' );
        $LDAPVersion            = $LDAPIni->variable( 'LDAPSettings', 'LDAPVersion' );
        $LDAPServer             = $LDAPIni->variable( 'LDAPSettings', 'LDAPServer' );
        $LDAPPort               = $LDAPIni->variable( 'LDAPSettings', 'LDAPPort' );
        $LDAPFollowReferrals    = (int) $LDAPIni->variable( 'LDAPSettings', 'LDAPFollowReferrals' );
	$LDAPUserDomainName     = $LDAPIni->variable( 'LDAPSettings', 'LDAPUserDomainName' );

	if ( $LDAPUserDomainName ) $login .= '@' . $LDAPUserDomainName;

        if ( function_exists( 'ldap_connect' ) )
        {
            $ds = ldap_connect( $LDAPServer, $LDAPPort );
            if ( $ds )
            {
                ldap_set_option( $ds, LDAP_OPT_PROTOCOL_VERSION, $LDAPVersion );
                ldap_set_option( $ds, LDAP_OPT_REFERRALS, $LDAPFollowReferrals );
                $r = ldap_bind( $ds, $login, $password );
                if ( $r )
                {
                    @ldap_close( $ds );
                    return true;
                }
		else
		{
			eZLog::write( "File to login user $login", 'ldap.log' );
		}
            }
            else
            {
                eZLog::write( "Can not to connect to $LDAPServer  (user $login)", 'ldap.log' );
            }
            ldap_close( $ds );
            return false;
        }
        eZLog::write( "Function 'ldap_connect' not found (user $login)", 'ldap.log' );
        return false;
    }
}
