#!/usr/bin/perl

use IO::Socket;
use IO::Select;
use strict;
use Digest::MD5  qw(md5 md5_hex md5_base64);
use Time::HiRes;
use Switch;
use Getopt::Long qw(:config posix_default bundling);

#1. Осуществить проверку на принимаемые сообщения.
#2. Подумать над логикой обработки входящих сообщений.
#3. Решить почему на SipServere не обрабатываются эти соообщения.
#4. Похоже, что Bye не правильно формируется
#========================Variables==================
#my $user="testu";
my ($server,$user,$pass);
GetOptions('S|server=s' => \$server, 'U|user=s' => \$user,'P|pass=s'  => \$pass) || usage( "bad option" );
if(!defined($server) or !defined($user) or !defined($pass)) { print "\n==>Parameters are not defined.\n\n"; usage( ); exit 1;}
my $dsturi="sip:$user\@$server";
my $localhost="localhost";
my $debug_lavel=1;
my $localport=5062;
my $fromuri="sip:$user\@$server";
my $tag=genTag(6);
my $idtag=genTag(6);
my $realm="CallManager";
my $UserAgent="UdpSender";
my $call_num="user_name\@";
my $uri="sip:".$call_num.$server;
my $qop="auth";
my $cnonce=genTag(8);
my $method="REGISTER";
my $nc="00000001";
my $branch=genTag(18);
my $resp=0;
my $timeout = 5;                         # Подождать 10 секунд
my $rin = '';                             # Инициализировать маску
my ($req2,$sip_request,$nonce,$received,$rport,$ttag,$i,$j);#,$rout,$nfound);
my $recv_pack_name="";
my $recv_pack_num=0;
my $pname="";
#my @mpname=("qinv","qack","qinv2","sleep","qbye","qack");
#my @mpname=("qreg","qreg2");
my @mpname=("qopt");
#====================================================
my $start = [ Time::HiRes::gettimeofday( ) ];

my $sock = IO::Socket::INET->new(
    Proto    => 'udp',
    PeerPort => 5080,
    PeerAddr => $server,
    Timeout => 5,
    LocalAddr => $localhost,
    localport => $localport) or die "Could not create socket: $!\n";
vec($rin, fileno($sock), 1) = 1;       # Пометить SOCKET в $rin
                                       # Повторить вызовы vec() для каждого проверяемого сокета
#my $client_socket = $sock->accept(); #<---------------for remove

#####################
for($i=0;$i<$#mpname+1;$i++)
{
  $pname=$mpname[$i];
  switch ($pname) 
    {
      case "qopt"    { $method="OPTIONS"; }
      case "qreg"    { $method="REGISTER"; }
      case "qinv"    { $method="INVITE"; }
      case "qreg2"   { $method="REGISTER"; }
      case "qinv2"   { $method="INVITE"; }
      case "qack"    { $method="ACK"; }
      case "qbye"    { $method="BYE"; }
      else           { $method=""; }
    }


  if($pname ne "hold" and $pname ne "sleep")
  {
    $req2=sip_message($pname,$localhost,$localport,$branch,$fromuri,$tag,$idtag,$user,$server,$uri,$received,$rport,$realm,$nonce,$resp,$cnonce,$nc,$ttag,$i);
    if($debug_lavel>0){print ">>>>>>>>>>>>>>\n".$req2;}
    $sock->send($req2) or die "Send error: $!\n"; $req2='';
  }

  if($pname eq "qinv" or $pname eq "qreg" or $pname eq "qinv2" or $pname eq "qreg2" or $pname eq "hold" or $pname eq "qbye")
  {
    recv_with_timeout(\$sock,$rin,$timeout,\$sip_request); 
    if(!$sip_request){ print "ERROR -1\n No received MESSAGE from server:$server!\n";exit 1;}
    if($sip_request =~ m/.*SIP\/2\.0\ ([0-9]+) ([a-zA-Z ]+).*/){$recv_pack_name=$2; $recv_pack_num=$1;}
    if($debug_lavel>0){print "<<<<<<<<<<<<<<<\nResponse received. Packet name is \"$recv_pack_num\" \"$recv_pack_name\": \n$sip_request";}
    $j=0;
    while(($recv_pack_num==183 or $recv_pack_num==100) and $j<5) #Ожидание прихода 200 OK на INVITE с авторизацией
      {
        recv_with_timeout(\$sock,$rin,$timeout,\$sip_request); #In call mast recv - SIP/2.0 401 Unauthorized
        if(!$sip_request){ print "ERROR -1\n No received MESSAGE from server:$server!\n";exit 1;}
        if($sip_request =~ m/.*SIP\/2\.0\ ([0-9]+) ([a-zA-Z]+).*/){$recv_pack_name=$2; $recv_pack_num=$1;}
        if($debug_lavel>0){print "<<<<<<<<<<<<<<<\nResponse received. Packet name is \"$recv_pack_num\" \"$recv_pack_name\": \n$sip_request";}
        $j++;
      }
  }

  if($pname eq "qinv" or $pname eq "qreg"){
      #WWW-Authenticate: Digest realm="CallManager", nonce="wkV5UTpAwB", opaque="opaqueData", algorithm=MD5, qop="auth"
      if($sip_request =~ m/.*nonce="([a-zA-Z0-9-]+)".*/){$nonce=$1;}
      #Via: SIP/2.0/UDP 192.168.100.40:5060;branch=z9hG4bK521038409;received=31.13.34.98;rport=50042.
      if($sip_request =~ m/.*received=([0-9\.]+);rport=(\d+).*/){$received=$1;$rport=$2;}
      if(!defined($received)) {$received=$localhost;}
      #To: <sip:009@tele.svetets.ru>;tag=uHEQDiTW90ipjF6rmOdzAOosxjEK7BsC.
      if($sip_request =~ m/.*To\: \<sip\:.*\@[a-zA-Z0-9\.]+>;tag=([a-zA-Z0-9]+).*/){$ttag=$1;}
      $resp=DigestAuth($user,$pass,$realm,$method,$uri,$nonce,$nc,$cnonce,$qop);
  }

  if($pname eq "sleep") {sleep 1;}
}
#####################

my $elapsed = Time::HiRes::tv_interval( $start );
if($debug_lavel>0) {print "Elapsed time(sec): ";}
print $elapsed."\n";

exit 0;

sub usage {
        print STDERR "ERROR: @_\n" if @_;
        print STDERR <<EOS;
usage: $0 [ options ] FROM TO
Compile SIP message to make the call to the destination server.
Call is made to the sip uri sip:009@<server_name>

Options:
  -S|--server <server name>          declare server name
  -U|--user <user name>              declare user name
  -P|--pass <password>               declare password 

Examples:
        ./udp_send_packet.pl -S sipnet.ru -U username -P 123456
EOS
        exit( @_ ? 1:0 );
}

sub DigestAuth
{
  #Аутентификация
#Формируется с помошью применения функции хеширования к 
#значениям nonce, nc, cnonce, qop, uri, username, realm, типу запроса и паролю password. 
# request-digest  = <"> < KD ( H(A1),     unq(nonce-value)
#                                           ":" nc-value
#                                           ":" unq(cnonce-value)
#                                           ":" unq(qop-value)
#                                           ":" H(A2)
#                                   ) <">
  my ($luser,$lpass,$lrealm,$lmethod,$luri,$lnonce,$lnc,$lcnonce,$lqop)=@_;

  my $la1h=md5_hex(join(':',$luser,$lrealm,$lpass));
  my $la2h=md5_hex(join(':',$lmethod,$luri));
  my $lresp=md5_hex(join(':',$la1h,$lnonce,$lnc,$lcnonce,$lqop,$la2h));
  #my $lresp=md5_hex(join(':',$la1h,$lnonce,$la2h)); #Возможно применение этой формы без cnonce, qop и nc.
  return $lresp;
}

sub genTag
{
  my ($num)=@_;
  my $tag;
  my @chars = ('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p',
  'q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8',
  '9','0','1','2','3','4','5','6','7','8','9');

  for (my $i = 0; $i < $num; $i++)
  {
    $tag .= $chars[rand(scalar @chars)];
  }
  return $tag;
}
sub recv_with_timeout
{
  my($hsock,$vrin,$vtimeout,$hsip_request)=@_;

  #$$hsock->recv($$hsip_request, 1024) or die "Can't recv: $!\n";


  my ($lnfound,$lrout);
  $lnfound = select($lrout = $vrin, undef, undef, $vtimeout);
  if (vec($lrout, fileno($$hsock),1)) 
    {
    $$hsock->recv($$hsip_request, 5000) or die "Can't recv: $!\n";
    }
  else {$$hsip_request=0;}
}

sub sip_message
{
  my ($id,$localhost,$localport,$branch,$fromuri,$tag,$idtag,$user,$server,$uri,$received,$rport,$realm,$nonce,$resp,$cnonce,$nc,$ttag,$i)=@_;
  my ($qopt,$qreg,$qreg2,$qinv,$qinv2,$qack,$qbye,$cont_length,$content);

  $qopt.= "OPTIONS $dsturi SIP/2.0\r\n";
  $qopt.= "Via: SIP/2.0/UDP $localhost:$localport;branch=$branch\r\n";
  $qopt.= "Max-Forwards: 70\r\n";
  $qopt.= "To: $fromuri\r\n";
  $qopt.= "From: $fromuri;tag=$tag\r\n";
  $qopt.= "Call-ID: $idtag\@$localhost\r\n";
  $qopt.= "CSeq: $i OPTIONS\r\n";
  $qopt.= "Contact: <$user\@$localhost:$localport>\r\n";
  $qopt.= "Accept: application/sdp\r\n";
  $qopt.= "Content-Length: 0\r\n\r\n";
  
  $qreg.= "REGISTER sip:$server SIP/2.0\r\n";
  $qreg.= "Via: SIP/2.0/UDP $localhost:$localport;rport;branch=$branch\r\n";
  $qreg.= "From: \"$user\" <$fromuri\>;tag=$tag\r\n";
  $qreg.= "To: \"$user\" <$fromuri\>\r\n";
  $qreg.= "Call-ID: $idtag\@$localhost\r\n";
  $qreg.= "CSeq: $i REGISTER\r\n";
  $qreg.= "Contact: <sip:$user\@$localhost:$localport>;expires=3600\r\n";
  $qreg.= "Allow: INVITE,ACK,BYE,CANCEL,OPTIONS,PRACK,REFER,NOTIFY,SUBSCRIBE,INFO,MESSAGE";
  $qreg.= "Max-Forwards: 70\r\n";
  $qreg.= "User-Agent: \r\n";
  $qreg.= "Accept: application/sdp\r\n";
  $qreg.= "Content-Length: 0\r\n\r\n";

# REGISTER sip:192.168.100.134 SIP/2.0
# Via: SIP/2.0/UDP 192.168.100.40:5062;rport;branch=z9hG4bKrxhbpgba
# Max-Forwards: 70
# To: "user" <sip:user@192.168.100.134>
# From: "user" <sip:user@192.168.100.134>;tag=jqhmr
# Call-ID: ctinogbaylwicqo@kzan
# CSeq: 935 REGISTER
# Contact: <sip:user@192.168.100.40:5062>;expires=3600
# Allow: INVITE,ACK,BYE,CANCEL,OPTIONS,PRACK,REFER,NOTIFY,SUBSCRIBE,INFO,MESSAGE
# User-Agent: Twinkle/1.4.2
# Content-Length: 0
# ----------------------------------  

  $content.= "v=0\r\n";
  $content.= "o=$user 123456 654321 IN IP4 $localhost\r\n";
  $content.= "s=A conversation\r\n";
  $content.= "c=IN IP4 $localhost\r\n";
  $content.= "t=0 0\r\n";
  $content.= "m=audio 7078 RTP/AVP 0 101\r\n";
  $content.= "a=rtpmap:0 PCMU/8000/1\r\n";
  $content.= "a=rtpmap:101 telephone-event/8000/1\r\n";
  $content.= "a=fmtp:101 0-11\r\n";
  $cont_length=length($content);

  $qinv.= "INVITE $uri SIP/2.0\r\n";
  $qinv.= "Via: SIP/2.0/UDP $localhost:$localport;rport;branch=$branch\r\n";
  $qinv.= "From: <$fromuri\>;tag=$tag\r\n";
  $qinv.= "To: <$uri\>\r\n";
  $qinv.= "Call-ID: $idtag\@$localhost\r\n";
  $qinv.= "CSeq: $i INVITE\r\n";
  $qinv.= "Contact: <sip:$user\@$localhost:$localport>\r\n";
  $qinv.= "Content-Type: application/sdp\r\n";
  $qinv.= "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO\r\n";
  $qinv.= "Max-Forwards: 70\r\n";
  $qinv.= "User-Agent: $UserAgent\r\n";
#  $qinv.= "Subject: Phone call\r\n";
  $qinv.= "Content-Length: $cont_length\r\n\r\n";
  $qinv.=$content;
  
  $qreg2.= "REGISTER sip:$server SIP/2.0\r\n";
  $qreg2.= "Via: SIP/2.0/UDP $localhost:$localport;rport;branch=$branch\r\n";
  $qreg2.= "From: \"$user\" <$fromuri\>;tag=$tag\r\n";
  $qreg2.= "To: \"$user\" <$fromuri\>\r\n";
  $qreg2.= "Call-ID: $idtag\@$localhost\r\n";
  $qreg2.= "CSeq: $i REGISTER\r\n";
  $qreg2.= "Contact: <sip:$user\@$received:$rport>;expires=3600\r\n";
  $qreg2.= "Authorization: Digest username=\"$user\", realm=\"$realm\", nonce=\"$nonce\", uri=\"$uri\", response=\"$resp\", algorithm=MD5, cnonce=\"$cnonce\", opaque=\"opaqueData\", qop=\"auth\", nc=$nc\r\n";
  $qreg2.= "Max-Forwards: 70\r\n";
  $qreg2.= "User-Agent: $UserAgent\r\n";
  $qreg2.= "Accept: application/sdp\r\n";
  $qreg2.= "Content-Length: 0\r\n\r\n";

# 26-10-12 12:23:09,552 DEBUG [] Sent SIP message to 192.168.100.40:5062. SIP:
# SIP/2.0 401 Unauthorized
# Via: SIP/2.0/UDP 192.168.100.40:5062;branch=z9hG4bKrxhbpgba;received=192.168.100.40;rport=5062
# From: "user" <sip:user@192.168.100.134>;tag=jqhmr
# To: "user" <sip:user@192.168.100.134>;tag=NSEMXmbGnkVKjyPkBbVxpFvWxRNNqSrb
# Call-ID: ctinogbaylwicqo@kzan
# CSeq: 935 REGISTER
# WWW-Authenticate: Digest realm="CallManager", nonce="Xom0mdFYUZ", opaque="opaqueData", algorithm=MD5, qop="auth"
# Allow: INVITE,ACK,CANCEL,BYE,NOTIFY,MESSAGE,PUBLISH,SUBSCRIBE,OPTIONS,INFO
# Max-Forwards: 70
# User-Agent: Svetets CallManager 3.15.0-174-gc70458a
# Content-Length: 0
#----------------------------
# REGISTER sip:192.168.100.134 SIP/2.0
# Via: SIP/2.0/UDP 192.168.100.40:5062;rport;branch=z9hG4bKrvyqfdgt
# Max-Forwards: 70
# To: "user" <sip:user@192.168.100.134>
# From: "user" <sip:user@192.168.100.134>;tag=jqhmr
# Call-ID: ctinogbaylwicqo@kzan
# CSeq: 936 REGISTER
# Contact: <sip:user@192.168.100.40:5062>;expires=3600
# Authorization: Digest username="user",realm="CallManager",nonce="Xom0mdFYUZ",uri="sip:192.168.100.134",response="3146a3cc00908420b89810d8cc0b40ec",algorithm=MD5,cnonce="cacc780327",opaque="opaqueData",qop=auth,nc=00000001
# Allow: INVITE,ACK,BYE,CANCEL,OPTIONS,PRACK,REFER,NOTIFY,SUBSCRIBE,INFO,MESSAGE
# User-Agent: Twinkle/1.4.2
# Content-Length: 0
  
  $qinv2.= "INVITE $uri SIP/2.0\r\n";
  $qinv2.= "Via: SIP/2.0/UDP $localhost:$localport;rport;branch=$branch\r\n";
  $qinv2.= "From: <$fromuri\>;tag=$tag\r\n";
  $qinv2.= "To: <$uri\>\r\n";
  $qinv2.= "Call-ID: $idtag\@$localhost\r\n";
  $qinv2.= "CSeq: $i INVITE\r\n";
  $qinv2.= "Contact: <sip:$user\@$received:$rport>\r\n";
  $qinv2.= "Authorization: Digest username=\"$user\", realm=\"$realm\", nonce=\"$nonce\", uri=\"$uri\", response=\"$resp\", algorithm=MD5, cnonce=\"$cnonce\", opaque=\"opaqueData\", qop=auth, nc=$nc\r\n";
  $qinv2.= "Content-Type: application/sdp\r\n";
  $qinv2.= "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO\r\n";
  $qinv2.= "Max-Forwards: 70\r\n";
  $qinv2.= "User-Agent: $UserAgent\r\n";
#  $qinv2.= "Subject: Phone call\r\n";
  $qinv2.= "Content-Length: $cont_length\r\n\r\n";
  $qinv2.=$content;
  
  $qack.= "ACK $uri SIP/2.0\r\n";
  $qack.= "Via: SIP/2.0/UDP $localhost:$localport;rport;branch=$branch\r\n";
  $qack.= "From: <$fromuri\>;tag=$tag\r\n";
  $qack.= "To: <$uri\>;tag=$ttag\r\n";
  $qack.= "Call-ID: $idtag\@$localhost\r\n";
  $qack.= "CSeq: $i ACK\r\n";
  $qack.= "Content-Length: 0\r\n\r\n";

  $qbye.= "BYE $uri SIP/2.0\r\n";
  $qbye.= "Via: SIP/2.0/UDP $localhost:$localport;rport;branch=$branch\r\n";
  $qbye.= "From: <$fromuri\>;tag=$tag\r\n";
  $qbye.= "To: <$uri\>;tag=$ttag\r\n";
  $qbye.= "Call-ID: $idtag\@$localhost\r\n";
  $qbye.= "CSeq: $i BYE\r\n";
  $qbye.= "Contact: <sip:$user\@$localhost:$localport>\r\n";
  $qbye.= "Max-Forwards: 70\r\n";
  $qbye.= "User-Agent: $UserAgent\r\n";
  $qbye.= "Content-Length: 0\r\n\r\n";

switch ($id) 
    {
      case "qopt"    { return $qopt; }
      case "qreg"    { return $qreg; }
      case "qinv"    { return $qinv; }
      case "qreg2"   { return $qreg2; }
      case "qinv2"   { return $qinv2; }
      case "qack"    { return $qack; }
      case "qbye"    { return $qbye; }
      else           { return 0; }
    }


}



