#!/usr/bin/env python

from twisted.internet import reactor
from twisted.internet import task
from twisted.protocols import sip
from twisted.internet.protocol import ServerFactory, Protocol
import random
import string
import re
import sys

"""
Test Reactor for SIP registrations
Documentation for SIP methods in page http://twistedmatrix.com/documents/current/api/twisted.protocols.sip.html
Obsolete - RFC 2543 (SIP: Session Initiation Protocol)http://www.ietf.org/rfc/rfc2543.txt
RFC 2543 (SIP: Session Initiation Protocol)http://tools.ietf.org/html/rfc3261
"This specification defines six methods: REGISTER for
           registering contact information, INVITE, ACK, and CANCEL for
           setting up sessions, BYE for terminating sessions, and
           OPTIONS for querying servers about their capabilities."

Some info about request and response:
SIP Requests:

There are six basic request / method types:

INVITE = Establishes a session
ACK = Confirms an INVITE request
BYE = Ends a session
CANCEL = Cancels establishing of a session
+REGISTER = Communicates user location (host name, IP)
OPTIONS = Communicates information about the capabilities of the calling and receiving SIP phones

SIP responses:

SIP Requests are answered with SIP responses, of which there are 6 classes:

1xx = informational responses, such as 180, which means ringing
2xx = success responses
3xx = redirection responses
4xx = request failures
5xx = server errors
6xx = global failures
"""


mParam = {'myIP' : '127.0.0.1',\
          'myport' : 5080,\
          'SIPservIP' : 'sipnet.ru',\
          'SIPservPort' : '5060',\
          'SIPuser' : 'user_name',\
          'SIPpass' : 'password',\
          'CSeq' : 1,\
          'Method' : 'REGISTER',\
          'RTries' : 0,\
          'callid' : '123456qwerty',\
          'ftag' : '11',\
          'Exp' : 300,\
          'Quit' : 180,\
          'Count' : 1,\
          'ReReg' : 0}

mMsg = {'MultiPMessage' : None,\
        'SIPtoControl' : None}
# ------------------------------------------------------------------

# create our own class from an original sipProxy class


#class myRequest(sip.Request):
#  def __init__(self, method, uri, version='SIP/2.0'):

#def runEverySecond():
#    mParam['Count']+=1
#    print mParam['Count']
#    if mParam['Count'] > mParam['Quit'] : 
#      reactor.SipProxy.CreateUnregister()
#      #reactor.stop()

def randstring(n):
    a = string.ascii_letters + string.digits
    return ''.join([random.choice(a) for i in range(n)])    


class myReq(sip.Request):
  def __init__(self, method, uri,Param):
    sip.Request.__init__(self,method, uri)
    self.method = method
    self.servIP=Param['SIPservIP']
    self.servPort=Param['SIPservPort']
    self.user=Param['SIPuser']
    self.myIP=Param['myIP']
    self.myPort=Param['myport']
    self.Via=Param['sVia'].toString()
    self.Pass=Param['SIPpass']
    self.CSeq=str(Param['CSeq'])
    self.callid=Param['callid']
    self.exp=Param['Exp']
    self.ftag=Param['ftag']

    self.addHeader("Via",self.Via)
    self.addHeader("To",sip.URL(self.servIP,self.user))
    self.addHeader("From", sip.URL(self.servIP,self.user,tag=self.ftag))
    self.addHeader("Call-ID", self.callid + "@" + self.myIP)
    self.addHeader("CSeq", self.CSeq + " " + self.method)
    self.addHeader("Contact","<" + sip.URL(self.myIP,self.user,port=self.myPort).toString() + ">")
    if mParam['RTries'] > 0:
      self.addHeader("Authorization",Param['Auth'])
      del Param['Auth']
    self.addHeader("Max-Forwards", "70")
    self.addHeader("User-Agent","Twistedtdtd")
    self.addHeader("Accept", "application/sdp")
    if self.method == 'REGISTER' : self.addHeader("Allow","INVITE,ACK,CANCEL,BYE,NOTIFY,MESSAGE,PUBLISH,SUBSCRIBE,OPTIONS,INFO")
    if self.method == 'REGISTER' : self.addHeader("Expires",self.exp)
    self.addHeader("Content-Length", "0")
    self.creationFinished()


class SipProxy(sip.Proxy):
 
  def __init__(self):
    self.echo = None
    self.tcount = 1
    sip.Proxy.__init__(self,host='localhost',port=5080)
    self.tries=0
    print 'Yepp, i`m listen in ' + self.host + ' and ' + str(self.port)
    #self.echo = task.LoopingCall(self.runEverySecond)
    #self.echo.start(1)
    self.echo = task.LoopingCall(self.runEverySecond)
    self.echo.start(1)
    mParam['callid']=randstring(20)
    mParam['ftag']=randstring(10)

 
  def handle_request(self,message,addr):
    print message.toString()
    #mParam['branch']=randstring(18)
    #mParam['sVia']=sip.Via(mParam['myIP'],mParam['SIPservPort'],branch=mParam['branch'])
    #mrc=myReq(mParam['Method'],sip.URL(mParam['SIPservIP']),mParam)
    #self.sendMessage(sip.URL(mParam['SIPservIP'],mParam['SIPuser']),mrc)
    #print mrc.toString()



  def handle_response(self, message, addr):
    print 'Count of Unregister request = ' + str(mParam['RTries'])
    
    print message.toString()
    mParam['branch']=randstring(18)
    mParam['sVia']=sip.Via(mParam['myIP'],mParam['SIPservPort'],branch=mParam['branch'])
    if message.code == 200 and message.phrase == 'OK' and message.headers['cseq'][0].split()[1] == 'REGISTER': 
        #mParam['Count']=self.tcount+10
        mParam['RTries'] = 0

    if message.code == 401 and message.phrase == 'Unauthorized' and mParam['RTries'] == 1:
      print 'REGISTER Error. More then 2 iterations. Ups, something is wrong'
      reactor.stop()

    if message.code == 401 and message.phrase == 'Unauthorized' and mParam['RTries'] < 1:
      mParam['Auth']=self.GenAuthorized(message)
      mParam['RTries']+=1
      mParam['CSeq']+=1
      mrc=myReq(mParam['Method'],sip.URL(mParam['SIPservIP']),mParam)
      print mrc.toString()
      self.sendMessage(sip.URL(mParam['SIPservIP'],mParam['SIPuser']),mrc)

    #print 'resp - 1\n'
    #print message.toString()
    #print message.headers
    #print message.code 
    #print message.length
    #print message.phrase


  def GenAuthorized(self,msg):
    """
    Generate Authorise string
    """
    if msg==None: return None
    wwwstr=msg.headers['www-authenticate'][0].split()
    #print wwwstr
    mRealm='CallManager'
    mNonce='wbwGSEDPuI'
    mOpaque='opaqueData'
    mAlgorithm='MD5'
    mQop='auth'

    for mkey in wwwstr:
      tempstr=mkey.split('=')
      if tempstr[0]=='realm':mRealm=tempstr[1].replace('"','').replace(',','')
      elif tempstr[0]=='nonce':mNonce=tempstr[1].replace('"','').replace(',','')
      elif tempstr[0]=='opaque':mOpaque=tempstr[1].replace('"','').replace(',','')
      elif tempstr[0]=='algorithm':mAlgorithm=tempstr[1].replace('"','').replace(',','')
      elif tempstr[0]=='qop':mQop=tempstr[1].replace('"','').replace(',','')

    mCNonce=randstring(8)
    mHA1=sip.DigestCalcHA1(mAlgorithm,mParam['SIPuser'],mRealm,mParam['SIPpass'],mNonce,mCNonce)
    mResp=sip.DigestCalcResponse(mHA1,mNonce,'00000001',mCNonce,mQop,mParam['Method'],sip.URL(mParam['SIPservIP']).toString(),mOpaque)
    mAuthStr='Digest username="' + mParam['SIPuser'] +\
             '", realm="' + mRealm +\
             '", nonce="' + mNonce +\
             '", uri="' + sip.URL(mParam['SIPservIP']).toString() +\
             '", response="' + mResp +\
             '", algorithm=' + mAlgorithm +\
             ', cnonce="' + mCNonce +\
             '", opaque="' + mOpaque +\
             '", qop="' + mQop + '", nc=00000001'
    return mAuthStr

  def CreateUnregister(self):
    """
    Call this method for generate initiale unregister paket
    """
    mParam['branch']=randstring(18)
    mParam['CSeq']+=1
    mParam['Exp']=0
    mParam['sVia']=sip.Via(mParam['myIP'],mParam['SIPservPort'],branch=mParam['branch'])
    mrc=myReq(mParam['Method'],sip.URL(mParam['SIPservIP']),mParam)
    self.sendMessage(sip.URL(mParam['SIPservIP'],mParam['SIPuser']),mrc)
    print mrc.toString()

  def runEverySecond(self):
    """
    Inside loop for check time inside session
    """
    self.CheckMessage()

    self.tcount+=1
    print self.tcount
    if self.tcount > mParam['Quit']:
      reactor.stop()

  def SetmParam(self,mkey,mvalue):
    mParam[mkey] = mvalue
    return mParam[mkey]

  def GetmParam(self,mkey):
    return mParam[mkey]

  def CheckMessage(self):
    """
    Method for check global veriable.
    Use for send message between two protocols.
    """
    command_msg = ''
    param0_msg = ''
    param1_msg = ''
    ansv = ''
    if mMsg['MultiPMessage'] != None :
      mMsg['MultiPMessage'] = re.sub("^\s+|\n|\r|\s+$", '', mMsg['MultiPMessage'])

      if ':' not in mMsg['MultiPMessage']:
        command_msg = mMsg['MultiPMessage']
      elif '=' in mMsg['MultiPMessage']: 
        command_msg, param0_msg = mMsg['MultiPMessage'].split(':',1)
        param0_msg, param1_msg = param0_msg.split('=',1)
      else:
        command_msg, param0_msg = mMsg['MultiPMessage'].split(':',1)
      print '==Catch command ' + command_msg + ' ' + param0_msg + ' ' + param1_msg

      if command_msg == 'unreg' :
        ansv = 'Message is UNREG'
        self.CreateUnregister()
      elif command_msg == 'reg' :
        ansv = 'Message is REG'
        mParam['branch']=randstring(18)
        mParam['sVia']=sip.Via(mParam['myIP'],mParam['SIPservPort'],branch=mParam['branch'])
        mrc=myReq(mParam['Method'],sip.URL(mParam['SIPservIP']),mParam)
        self.sendMessage(sip.URL(mParam['SIPservIP'],mParam['SIPuser']),mrc)
        print mrc.toString()
      elif command_msg == 'quit' : 
        mParam['Quit'] = self.tcount + 2
        ansv = 'Server is shutdown for 2 seconds...'
      elif command_msg == 'get' : 
        ansv = 'Param ' + param0_msg + ' is: ' + self.GetmParam(param0_msg)
      elif command_msg == 'set' : 
        ansv = 'Param ' + param0_msg + ' set to: ' + self.SetmParam(param0_msg,param1_msg)
      else: ansv = 'Unknown command.'
      #mParam['MultiPMessage'] = ansv + '\n'
      mMsg['SIPtoControl'] = ansv + '\n'
      mMsg['MultiPMessage'] = None

class sipfactory(ServerFactory):
  protocol = SipProxy
  
#========================Controll reactor===================
class ControlProtocol(Protocol):

  def __init__(self):
    self.pt = 1
    self.echo = task.LoopingCall(self.pCheckCommand)
    self.echo.start(1)

  def connectionMade(self):
    self.transport.write('Control side:\n')
  
  def dataReceived(self, data):
    mMsg['MultiPMessage'] = data

  def pCheckCommand(self):
    self.pt +=1
    print "==cp:" + str(self.pt)
    if mMsg['SIPtoControl'] != None :
      #print mParam['MultiPMessage']
      self.SendSubject(mMsg['SIPtoControl'])
      #mParam['MultiPMessage'] = None
      mMsg['SIPtoControl'] = None

  def SendSubject(self,text):
    self.transport.write(text)

  def connectionLost(self, reason):
    print "==Lost connection with control Client=="
    self.echo.stop()

class ControlFactory(ServerFactory):

  protocol = ControlProtocol

  def __init__(self):
    self.ft = 1

  #def CheckCommand(self):
  #  self.ft += 1
  #  print 'ft:' + str(self.ft)
  #  if mParam['MultiPMessage'] != None :
  #    print 'We print command str and remove it' + mParam['MultiPMessage']
  #    self.protocol.SendSubject(protocol,mParam['MultiPMessage'])
  #    mParam['MultiPMessage'] = None

#========================End Declare logic==================


def main():
  #l = task.LoopingCall(runEverySecond)
  #l.start(1.0) # call every second
  sfactory = sipfactory()
  port = reactor.listenUDP(mParam['myport'], SipProxy())
  factory = ControlFactory()
  reactor.listenTCP(mParam['myport']+1, factory)
  reactor.run()

# Standard boilerplate to call the main() function to begin
# the program.
if __name__ == '__main__':
    main()
