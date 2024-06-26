from burp import IBurpExtender, IHttpListener, IScannerCheck, IScanIssue, ITab
from javax.swing import JPanel, JButton, JFileChooser, JScrollPane, JTextArea
import java.awt.BorderLayout as BorderLayout
import re
class BurpExtender(IBurpExtender, IHttpListener, IScannerCheck, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Data Leak Prevention Tool by Yasin Saffari")
        self._callbacks.registerHttpListener(self)
        self._callbacks.registerScannerCheck(self)
        self._panel = JPanel(BorderLayout())
        self._textArea = JTextArea(10, 50)
        self._panel.add(JScrollPane(self._textArea), BorderLayout.CENTER)
        self._load_button = JButton("Load Patterns", actionPerformed=self.load_patterns)
        self._panel.add(self._load_button, BorderLayout.SOUTH)
        self._callbacks.addSuiteTab(self)
        self.patterns = [
            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN
            re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b"),  # Visa
            re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),  # GUID
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")  # Email
        ]
        print("Data Leak Prevention Tool loaded")
    def getTabCaption(self):
        return "Data Leak Prevention"
    def getUiComponent(self):
        return self._panel
    def load_patterns(self, event):
        chooser = JFileChooser()
        ret = chooser.showOpenDialog(self._panel)
        if ret == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            with open(file.getAbsolutePath()) as f:
                for line in f:
                    self.patterns.append(re.compile(line.strip()))
            self._textArea.append("Loaded patterns from {}\n".format(file.getAbsolutePath()))
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            response_body = self.get_response_body(messageInfo)
            for pattern in self.patterns:
                if pattern.search(response_body):
                    self._textArea.append("Data leak detected in response: {}\n".format(pattern.pattern))
                    self._callbacks.addScanIssue(self.create_issue(messageInfo, response_info.getUrl(), pattern.pattern))
    def doPassiveScan(self, baseRequestResponse):
        return self.scan_for_data_leaks(baseRequestResponse)
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return self.scan_for_data_leaks(baseRequestResponse)
    def scan_for_data_leaks(self, baseRequestResponse):
        response_info = self._helpers.analyzeResponse(baseRequestResponse.getResponse())
        response_body = self.get_response_body(baseRequestResponse)
        issues = []
        for pattern in self.patterns:
            if pattern.search(response_body):
                issues.append(self.create_issue(baseRequestResponse, response_info.getUrl(), pattern.pattern))
        return issues
    def get_response_body(self, baseRequestResponse):
        response = baseRequestResponse.getResponse()
        if response:
            return self._helpers.bytesToString(response[baseRequestResponse.getResponse().getBodyOffset():])
        return ""
    def create_issue(self, baseRequestResponse, url, pattern):
        return CustomScanIssue(baseRequestResponse.getHttpService(),
                               url,
                               [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                               "Data Leak Detected",
                               "A data leak was detected matching pattern: {}".format(pattern),
                               "High",
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
