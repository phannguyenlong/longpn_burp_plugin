# package for burp
from burp import IBurpExtender
from burp import IContextMenuFactory, IContextMenuInvocation
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from javax.swing import JMenuItem
from java.io import PrintWriter
import java.util.ArrayList as ArrayList
# other url
from urlparse import urlparse
import urllib, urllib2, json

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        # for print out
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName('Common utils')

        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        self.invocation = invocation # invocationn will contain the current repeater tab
        context = invocation.getInvocationContext()

        # create options dropdown
        if context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST \
                or context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:

            # Convert to URL Encoded option
            menuItem1 = JMenuItem('Convert body to url-encoded', actionPerformed=self.convertBodyToURLEncode)

            # Copy cookie options
            menuItem2 = JMenuItem('Copy "Cookie" header', actionPerformed=self.copyCookieHeader)

            # Copy Authorization header options
            menuItem3 = JMenuItem('Copy "Authorization" header', actionPerformed=self.copyAuthorizationHeader)

            # return menu items
            return [menuItem1, menuItem2, menuItem3]

    def copyCookieHeader(self, event):
        menuItem = event.getSource()
        cookie_header = self.getHeader(self.invocation, 'cookie')
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(cookie_header), None)

    def copyAuthorizationHeader(self, event):
        menuItem = event.getSource()
        authorize_header = self.getHeader(self.invocation, 'authorization')
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(authorize_header), None)

    def convertBodyToURLEncode(self, event):
        # get request body and convert
        request_obj = self.invocation.getSelectedMessages()[0]
        request = request_obj.getRequest()
        request_body = self.processRequestBody(request)
        data_dec = json.loads(request_body)
        urlEncodededBody = self.JSON_to_URL_encode(data_dec)
        
        # update request
        updateRequest = self.updateRequest(request, urlEncodededBody)
        request_obj.setRequest(updateRequest)

    # ==================== Utils code -=====================================
    def updateRequest(self, request, updateBody):
        requestInfo = self.helpers.analyzeRequest(request)
        bodyOffset = requestInfo.getBodyOffset()
        content_type = requestInfo.getContentType()

        # update header
        headers = self.helpers.analyzeRequest(request).getHeaders()
        headers_new  = ArrayList() # create new header for fixing bugs not python array and java not compatible
        hasContentType = False
        for i in range(0, len(headers)):
            print(headers[i])
            if ( "Content-Type" in headers[i] or "content-type" in headers[i]):
                self.stdout.println("Has content type")
                headers[i] = "Content-Type: application/x-www-form-urlencoded"
                hasContentType = True
            headers_new.add(headers[i]) 
        if (hasContentType == False): 
            self.stdout.println("Append content type")
            headers_new.add("Content-Type: application/x-www-form-urlencoded")
        print("===============================")       
        for i in range(0, len(headers)):
            print(headers[i])
        print("===============================")
        return self.helpers.buildHttpMessage(headers_new, updateBody)
        

    def getBody(self, rawMessage, parsedMessage):
        return self.helpers.bytesToString(rawMessage[parsedMessage.getBodyOffset():])
    
    # Get header base on header name
    def getHeader(self, invocation, headerName):
        request = invocation.getSelectedMessages()[0].getRequest()
        headers = self.helpers.analyzeRequest(request).getHeaders() 
        for header in headers:
            if (headerName == "cookie"):
                if header.startswith('Cookie:'):
                    return header
            elif (headerName == "authorization"):
                if header.startswith('Authorization:'):
                    return header

    # get request body
    def processRequestBody(self, request):
        parse_request = self.helpers.analyzeRequest(request)
        body = self.getBody(request, parse_request)
        return body

    def convertToUrlEncoded(self, data):
        for key in data:
            if (type(data[key]) == list):
                new_key = key + "[]"
                data[new_key] = data.pop(key)
        return urllib.urlencode(data, True)
    
    def JSON_to_URL_encode(self, value, key=None):
        def quot(v):
            return None if v is None else urllib.quote_plus(str(v))
        if isinstance(value, dict):
            iterator = value.items()
        elif isinstance(value, list):
            iterator = enumerate(value)
        elif key is None:
            raise TypeError('Only lists and dictionaries supported')
        else:
            return '{}={}'.format(quot(key), quot(value))

        res_l = []
        for k, v in iterator:
            this_key = k if key is None else '{}[{}]'.format(key, k)
            v = v.encode('utf-8')
            res_l.append(self.JSON_to_URL_encode(v, this_key))
        return '&'.join(res_l)