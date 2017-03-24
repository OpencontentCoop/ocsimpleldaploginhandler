<?php
require 'autoload.php';

$cli = eZCLI::instance();
$script = eZScript::instance( array( 'description' => ( "" ),
                                     'use-session' => false,
                                     'use-modules' => true,
                                     'use-extensions' => true ) );

$script->startup();

$options = $script->getOptions('[login:][password:]');
$script->initialize();
$script->setUseDebugAccumulators( true );

function LDAPLogin( $login, $password )
{
    $cli = eZCLI::instance();

    $LDAPIni = eZINI::instance( 'ldap.ini' );
    $LDAPVersion = $LDAPIni->variable( 'LDAPSettings', 'LDAPVersion' );
    $LDAPServer = $LDAPIni->variable( 'LDAPSettings', 'LDAPServer' );
    $LDAPPort = $LDAPIni->variable( 'LDAPSettings', 'LDAPPort' );
    $LDAPFollowReferrals = (int)$LDAPIni->variable( 'LDAPSettings', 'LDAPFollowReferrals' );

    $LDAPUserDomainName = false;
    if ( $LDAPIni->hasVariable( 'LDAPSettings', 'LDAPUserDomainName' ) )
        $LDAPUserDomainName = $LDAPIni->variable( 'LDAPSettings', 'LDAPUserDomainName' );

    if ( $LDAPUserDomainName )
    {
        $login .= '@' . $LDAPUserDomainName;
    }

    if ( function_exists( 'ldap_connect' ) )
    {
        $ds = ldap_connect( $LDAPServer, $LDAPPort );
        if ( $ds )
        {
            ldap_set_option( $ds, LDAP_OPT_PROTOCOL_VERSION, $LDAPVersion );
            ldap_set_option( $ds, LDAP_OPT_REFERRALS, $LDAPFollowReferrals );
            $r = ldap_bind( $ds, $login, $password );
            @ldap_close( $ds );

            if ( $r )
            {
                return true;
            }
            else
            {
                $cli->error( "Failed login user $login" );
                return false;
            }
        }
        else
        {
            $cli->error( "Can not to connect to $LDAPServer  (user $login)" );
            return false;
        }
    }

    $cli->error( "Function 'ldap_connect' not found (user $login)" );
    return false;
}

try {
    $canLogin = LDAPLogin($options['login'], $options['password']);
    $cli->warning( var_export($canLogin, 1) );
} catch(Exception $e){
    $cli->error($e->getMessage());
}


$script->shutdown();

