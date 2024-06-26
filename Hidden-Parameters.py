from burp import IBurpExtender, IHttpListener, IScannerCheck, IScanIssue, ITab
from javax.swing import JPanel, JButton, JFileChooser, JScrollPane, JTextArea
import java.awt.BorderLayout as BorderLayout
import re
class BurpExtender(IBurpExtender, IHttpListener, IScannerCheck, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Hidden Parameters Detector by Yasin Saffari")
        self._callbacks.registerHttpListener(self)
        self._callbacks.registerScannerCheck(self)
        self._panel = JPanel(BorderLayout())
        self._textArea = JTextArea(10, 50)
        self._panel.add(JScrollPane(self._textArea), BorderLayout.CENTER)
        self._load_button = JButton("Load Wordlist", actionPerformed=self.load_wordlist)
        self._panel.add(self._load_button, BorderLayout.SOUTH)
        self._callbacks.addSuiteTab(self)
        self.wordlist = ["test", "debug", "hidden"]
        print("Hidden Parameters Detector loaded")
    def getTabCaption(self):
        return "Hidden Params Detector"
    def getUiComponent(self):
        return self._panel
    def load_wordlist(self, event):
        chooser = JFileChooser()
        ret = chooser.showOpenDialog(self._panel)
        if ret == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            with open(file.getAbsolutePath()) as f:
                self.wordlist = [line.strip() for line in f]
            self._textArea.append("Loaded wordlist from {}\n".format(file.getAbsolutePath()))
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            request_info = self._helpers.analyzeRequest(messageInfo)
            params = request_info.getParameters()
            for param in params:
                if param.getType() == 0:  # Only check for URL parameters
                    if param.getName() in self.wordlist:
                        self._textArea.append("Hidden parameter detected: {}\n".format(param.getName()))
                        self._callbacks.addScanIssue(self.create_issue(messageInfo, param.getName()))
    def doPassiveScan(self, baseRequestResponse):
        return self.scan_for_hidden_params(baseRequestResponse)
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return self.scan_for_hidden_params(baseRequestResponse)
    def scan_for_hidden_params(self, baseRequestResponse):
        request_info = self._helpers.analyzeRequest(baseRequestResponse)
        params = request_info.getParameters()
        issues = []
        for param in params:
            if param.getType() == 0:  # Only check for URL parameters
                if param.getName() in self.wordlist:
                    issues.append(self.create_issue(baseRequestResponse, param.getName()))
        return issues
    def create_issue(self, baseRequestResponse, param_name):
        return CustomScanIssue(baseRequestResponse.getHttpService(),
                               self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                               [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                               "Hidden Parameter Detected",
                               "A hidden parameter was detected: {}".format(param_name),
                               "Medium",
                               "Certain")
class CustomScanIssue(IScanIssue):
    def __init__(self, http_service, url, http_messages, name, detail, severity, confidence):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence
    def getHttpService(self):
        return self._http_service
    def getUrl(self):
        return self._url
    def getHttpMessages(self):
        return self._http_messages
    def getIssueName(self):
        return self._name
    def getIssueDetail(self):
        return self._detail
    def getSeverity(self):
        return self._severity
    def getConfidence(self):
        return self._confidence
    def getIssueBackground(self):
        return None
    def getRemediationBackground(self):
        return None
    def getRemediationDetail(self):
        return None
    def getReferences(self):
        return None
