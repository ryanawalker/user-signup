#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import cgi
import re

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
    return PASS_RE.match(password)

def valid_email(email):
    return EMAIL_RE.match(email)


header = '''
<!DOCTYPE html>
<html>
    <head>
        <title>User Signup</title>
        <style>
            .error {
                color: red;
            }
        </style>
    </head>
    <body>
'''

footer = '''
    </body>
</html>
'''

class MainHandler(webapp2.RequestHandler):
    def get(self):
        user_error = self.request.get("userError")
        password_error = self.request.get("passwordError")
        verify_error = self.request.get("verifyError")
        email_error = self.request.get("emailError")
        error_message = ["", "", "", ""]
        if user_error:
            error_message[0] = user_error
        if password_error:
            error_message[1] = password_error
        if verify_error:
            error_message[2] = verify_error
        if email_error:
            error_message[3] = email_error

        username_textfill = cgi.escape(self.request.get("badName"))
        email_textfill = cgi.escape(self.request.get("address"))

        form_body = '''
        <h1>Signup</h1>
        <form method="post">
            <table>
                <tr>
                    <td class="label">
                        Username
                    </td>
                    <td>
                        <input type="text" name="username" value="''' + username_textfill + '''">
                        <span class="error">{0}</span>
                    </td>
                </tr>
                <tr>
                    <td class="label">
                        Password
                    </td>
                    <td>
                        <input type="password" name="password" value="">
                        <span class="error">{1}</span>
                    </td>
                </tr>
                <tr>
                    <td class="label">
                        Verify Password
                    </td>
                    <td>
                        <input type="password" name="verify" value="">
                        <span class="error">{2}</span>
                    </td>
                </tr>
                <tr>
                    <td class="label">
                        Email (Optional)
                    </td>
                    <td>
                        <input type="text" name="email" value="'''.format(error_message[0], error_message[1], error_message[2])  + email_textfill + '''">
                        <span class="error">%s</span>
                    </td>
                </tr>
            </table>
            <input type="submit">
        </form>
        ''' % error_message[3]

        content = header + form_body + footer

        self.response.write(content)

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        error = ""

        # Check for valid username
        if not username or not valid_username(username):
            error += "&userError=Please enter a valid username."
        
        # Check for valid password
        if not password or not valid_password(password):
            error += "&passwordError=Please enter a valid password."
        if not verify or password != verify:
            error += "&verifyError=Your passwords did not match."

        # Check if email and if email is valid
        if email != "":
            if not valid_email(email):
                error += "&emailError=Please use a valid email."
        
        if not username:
            username = ""

        if not email:
            email = ""

        # Redirect if all looks good
        if error == "": 
            username_message = "?username=" + username
            self.redirect("/welcome" + username_message)
        else:
            username_message = "?badName=" + username
            email_message = "&address=" + email
            self.redirect("/" + username_message + email_message + error)

class WelcomeHandler(webapp2.RequestHandler):        
    def get(self):
        username = self.request.get("username")
        username = cgi.escape(username, quote=True)
        self.response.write("<h1>Welcome, " + username + ".</h1>")

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/welcome', WelcomeHandler)
], debug=True)
