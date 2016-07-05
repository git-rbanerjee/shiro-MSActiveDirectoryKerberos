# MSActiveDirectoryKerberos for Shiro

A Shiro realm for authentication using Microsoft Active Directory via kerberos protocol.
Users can be authenticated via their domain username and password using DC. 

//////////////////////////////////////////
To use put the generated JAR in classpath

Using it in your shiro.ini file:
[main]
msActiveKRBRealm=org.apache.shiro.realm.krb.MSActiveKRBRealm
msActiveKRBRealm.krbfile=conf/krb5.conf
msActiveKRBRealm.loginfile=conf/login.conf
msActiveKRBRealm.module=spnego-client


krb5.conf need to be modified , according to your domain and KDC .

To know you domain , check Windows computer's properties , domain name . Windows machine should be in the domain.
TO Know KDC ping <domina> ; then find ip ; then ping -a <that ip> ;

Details for the same is given here :

http://spnego.sourceforge.net/pre_flight.html


//////////////////////////////////////////////////////
Build instruction

mvn package 

Then use the geerated jar in the classpath .
