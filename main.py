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
    </head>
    <body>
'''

footer = '''
    </body>
</html>
'''

class MainHandler(webapp2.RequestHandler):
    def get(self):
        form_body = '''
        <h1>Signup</h1>
        <form method="post">
            <table>
                <tr>
                    <td class="label">
                        Username
                    </td>
                    <td>
                        <input type="text" name="username" value="">
                    </td>
                </tr>
                <tr>
                    <td class="label">
                        Password
                    </td>
                    <td>
                        <input type="password" name="password" value="">
                    </td>
                </tr>
                <tr>
                    <td class="label">
                        Verify Password
                    </td>
                    <td>
                        <input type="password" name="verify" value="">
                    </td>
                </tr>
                <tr>
                    <td class="label">
                        Email (Optional)
                    </td>
                    <td>
                        <input type="text" name="email" value="">
                    </td>
                </tr>
            </table>
            <input type="submit">
        </form>
        '''
        error = self.request.get("error")
        error_message = "<p class='error'>" + error + "</p>" if error else ""
        content = header + form_body + error_message + footer

        self.response.write(content)

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        # Check for valid username
        if not username or not valid_username(username):
            error = "Please enter a valid username."
            self.redirect("/?error=" + error)
        
        # Check for valid password
        elif (not password or not verify) or not valid_password(password) or password != verify:
            error = "Please enter a valid password."
            self.redirect("/?error=" + error)

        # Check if email and if email is valid
        elif email != "":
            if not valid_email(email):
                error = "Please use a valid email."
                self.redirect("/?error=" + error)
            else:
                self.redirect("/welcome?username=" + username)    

        # Redirect if all looks good
        else: 
            self.redirect("/welcome?username=" + username)

class WelcomeHandler(webapp2.RequestHandler):        
    def get(self):
        username = self.request.get("username")
        username = cgi.escape(username, quote=True)
        self.response.write("<h1>Welcome " + username + "</h1>")

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/welcome', WelcomeHandler)
], debug=True)
