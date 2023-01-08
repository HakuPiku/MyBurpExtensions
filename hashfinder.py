import hashlib
import hmac
import base64
import time
import binascii
from burp import IBurpExtender, IContextMenuFactory, IMessageEditorTabFactory, IMessageEditorTab, ITab, IHttpListener, IExtensionStateListener,IBurpExtenderCallbacks

from java.awt import BorderLayout, GridLayout
from java.awt.event import ActionListener
from java.util import List, ArrayList
from javax.swing import (
    JFrame,
    JMenuItem,
    GroupLayout,
    JPanel,
    JCheckBox,
    JTextField,
    JLabel,
    JButton,
    JScrollPane,
    JTextArea,
    ScrollPaneConstants,
    JFileChooser,
    BorderFactory,
    JEditorPane,
    ImageIcon,
)

### Big problem with this! What if the request which has the value that is later hashed is before the hashed value. 
### Check specifically for request parameters and response bodies which have base64 encoded values or hex values. 



class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IHttpListener, IExtensionStateListener,IBurpExtenderCallbacks):
    
    def getTabCaption(self):
        return "Hashfinder"
    
    def getUiComponent(self):
        return self._mainPanel
    
    
        
    
    def registerExtenderCallbacks(self, callbacks):

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.setExtensionName("HashFinder")
        
        self.foundValues = []
        
        self._mainPanel = JPanel(BorderLayout())
        self.output = JTextArea(30, 100)
        self.output.setLineWrap(True)
        self.output.setEditable(False)
        self.scroll_output = JScrollPane(self.output)
        self.scroll_output.setVerticalScrollBarPolicy(
            ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS
        )
        self._mainPanel.add(self.output, BorderLayout.SOUTH)
        
        callbacks.addSuiteTab(self)

    def processHttpMessage(self, fromTool, messageIsRequest, messageInfo):
        if messageIsRequest and fromTool == 4:
            requestUrl = self._helpers.analyzeRequest(messageInfo).getUrl()
            if self._callbacks.isInScope(requestUrl):
                allParams = []
                requestResponseList = []
                for p in self._helpers.analyzeRequest(messageInfo.getRequest()).getParameters():
                    allParams.append({p.getName() :  self._helpers.urlDecode(p.getValue())})
  
                requestResponseList.append(self._helpers.bytesToString(messageInfo.getRequest()))
                
                
                requestsToAnalyze = self._callbacks.getProxyHistory()[-25:]
                for request in requestsToAnalyze:
                        requestUrl = self._helpers.analyzeRequest(request).getUrl()
                        if self._callbacks.isInScope(requestUrl):
                            if request.getRequest() != None:
                                requestResponseList.append(self._helpers.bytesToString(request.getRequest()))
          
                            if request.getResponse() != None:
                                offset = self._helpers.analyzeRequest(request.getResponse()).getBodyOffset()
                                requestResponseList.append(self._helpers.bytesToString(request.getResponse()[offset:]))
                    
                    
                print(len(requestResponseList))

                
                for param in allParams:
                    hashedValues = getValues(param.values()[0])
                    for hashedValue in hashedValues:
                        for requestResponse in requestResponseList:
                            if hashedValue in requestResponse:
                                #print("FOUND")
                                if {param.values()[0]:requestResponse} not in self.foundValues:
                                    self.output.text += param.values()[0] + " : \n " + requestResponse
                                    self.foundValues.append({param.values()[0]:requestResponse})
                print("Finished")
            
            ### Look for opposite?
            # hashLikeParams = [] 
            # for param in allParams:
            #     p = param.values()[0]
            #     hashLike = False
            #     if len(p)>=16 and len(p) <= 64:
            #         try:
            #             bytes.fromhex(p)
            #             hashLike= True
            #         except:
            #             None
            #         try:
            #             base64.b64decode(p)
            #             hashLike = True
            #         except:
            #             None
            #     if hashLike:
            #         hashLikeParams.append(param)
                



def getValues(value):
    requestTime = time.time()
# The value to be hashed, HMAC'd, and encrypted

    result_list = []
    # The key to use for HMAC and AES
    key = bytes(16)  # 16 zero bytes

    # Hash the value with several different algorithms
    md5_hash = hashlib.md5(value.encode()).hexdigest()
    sha1_hash = hashlib.sha1(value.encode()).hexdigest()
    sha256_hash = hashlib.sha256(value.encode()).hexdigest()

    # HMAC the value with the key
    hmac_value = hmac.new(key, value.encode(), digestmod= hashlib.md5).hexdigest()
    result_list.append(hmac.new(key, value.encode(), digestmod= hashlib.sha1).hexdigest())
    result_list.append(base64.b64encode(hmac.new(key, value.encode(), digestmod= hashlib.sha1).digest()))
    result_list.append(hmac.new(key, value.encode(), digestmod= hashlib.sha256).hexdigest())
    result_list.append(base64.b64encode(hmac.new(key, value.encode(), digestmod= hashlib.sha256).digest()))
    # AES encrypt the value in different modes


    # Base64 encode each of the resulting values
    md5_hash_b64 = base64.b64encode(binascii.unhexlify(md5_hash)).decode()
    sha1_hash_b64 = base64.b64encode(binascii.unhexlify(sha1_hash)).decode()
    sha256_hash_b64 = base64.b64encode(binascii.unhexlify(sha256_hash)).decode()
    hmac_value_b64 = base64.b64encode(binascii.unhexlify(hmac_value)).decode()

 
    
    result_list.append(md5_hash)
    result_list.append(md5_hash_b64)
    result_list.append(sha1_hash)
    result_list.append(sha1_hash_b64)
    result_list.append(sha256_hash)
    result_list.append(sha256_hash_b64)
    result_list.append(hmac_value)
    result_list.append(hmac_value_b64)

     # Append all the generated values 

    for i in range(-5,5,1):
        result_list.append(hmac.new(str(requestTime + i).encode(), value.encode(), hashlib.md5).hexdigest()) 
        result_list.append(base64.b64encode(hmac.new(str(requestTime + i).encode(), value.encode(), hashlib.md5).digest()))
        result_list.append(hmac.new(str(requestTime + i).encode(), value.encode(), hashlib.sha1).hexdigest()) 
        result_list.append(base64.b64encode(hmac.new(str(requestTime + i).encode(), value.encode(), hashlib.sha1).digest()))
        result_list.append(hmac.new(str(requestTime + i).encode(), value.encode(), hashlib.sha256).hexdigest()) 
        result_list.append(base64.b64encode(hmac.new(str(requestTime + i).encode(), value.encode(), hashlib.sha256).digest()))
        
    return result_list