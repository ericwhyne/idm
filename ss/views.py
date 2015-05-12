from datetime import datetime
from django.core.urlresolvers import reverse
from django.http import HttpResponse,HttpResponseRedirect
from django.shortcuts import render
from django import forms
from django.core.validators import RegexValidator

import ldap
import utils
import ConfigParser
import os
import logging
import urllib
import urlparse

# Set up configuration
project_path = os.path.realpath(os.path.dirname(__file__))
#project_path='/django/idm/ss/'
config_file = os.path.join(project_path, 'config.ini')

config_parser = ConfigParser.ConfigParser()
config_parser.read(config_file)

ldap_host = config_parser.get('default', 'ldap_host')
ldap_admin = config_parser.get('default', 'ldap_admin')
ldap_cred = config_parser.get('default', 'ldap_cred')
ldap_dn = config_parser.get('default', 'dn')

email_server = config_parser.get('default', 'email_server')
email_port = config_parser.get('default', 'email_port')
email_local_hostname = config_parser.get('default', 'email_local_hostname')
email_username = config_parser.get('default', 'email_username')
email_password = config_parser.get('default', 'email_password')
email_fromaddr = config_parser.get('default', 'email_fromaddr')

# Set up logging
# log_file = os.path.join(project_path, 'password-recover.log')

log = logging.getLogger(__name__)

def index(request):
    return render(request, 'ss/recover.html', {})


def send_recovery_email(request):
"""
This function generates an email with a URL link that allows the user to perform a password recovery and reset.
"""
    class PasswordRecoveryForm(forms.Form):
        username = forms.CharField(label='Enter your username:', validators=[RegexValidator('^[a-zA-Z0-9]*$', message='Invalid username', code='invalid_username')])

    try:
        if request.method == 'GET':
            form = PasswordRecoveryForm()    
	    return render(request, 'ss/recover.html', {'form': form})

        elif request.method == 'POST':
            form = PasswordRecoveryForm(request.POST)    

	    if form.is_valid():
                username = form.cleaned_data.get('username')
                email, token = utils.set_token(ldap_host, ldap_admin, ldap_cred, ldap_dn, username)
                subject = 'Password Recovery'
                full_path = request.get_full_path()
                parsed_url = urlparse.urlparse(full_path)

                pathparts = str.split(str(parsed_url.path),'/')                

                pathparts = pathparts[0:len(pathparts)-1]
                baseurl = '/'.join(pathparts) 
             
                #basepath = '/'.join(pathparts) 
                #baseurl = '%s://%s/%s' % (urlparts.scheme, urlparts.netloc, basepath)
                # RLJ TODO, hardcoded the https since behind a proxy with only 
                # https, need to learn how to interrogate the request to learn
                # if behind proxy.
                message = '''
A request to recover your password has been received.
If you did not request this, please contact the administrators of the system.
If you did, you can complete the recovery process by clicking on the following link...
https://%s%s/%s/ 
    	        ''' % (request.get_host(), baseurl, token)
                utils.send_email(email_server, email_port, email_local_hostname, email_username, email_password, email, email_fromaddr, subject, message)
                content = 'Sent to email address associated with user, %s.' % username
		return render(request, 'ss/email_success.html', {'content': content})

    except Exception as e:
       log.error(e)
       url = request.get_full_path()
       return render(request, 'ss/error.html', {'content': e, 'url': url})

    return render(request, 'ss/recover.html', {'form': form})
 
def reset_password(request, token):
"""
Using the unique token supplied, this function allows the user to set his/her password without knowing their previous password.  Between the token and valid username, the user will be able to set his/her password.
"""
    class ResetPasswordForm(forms.Form):
        username = forms.CharField(label='Enter your username:', validators=[RegexValidator('^[a-zA-Z0-9]*$', message='Invalid username', code='invalid_username')])
        passwd  = forms.CharField(label='New Password:', widget=forms.PasswordInput)
        confirm = forms.CharField(label='Confirm Password:', widget=forms.PasswordInput)
 
        def clean(self):
            # cleaned_data = super(ResetPasswordForm, self).clean()
            username = self.cleaned_data.get("username")
            passwd = self.cleaned_data.get("passwd")
            confirm = self.cleaned_data.get("confirm")

            if username:
                # Only do something if all fields are valid so far.
                if passwd != confirm:
                    raise forms.ValidationError("Passwords do not match!")

            return self.cleaned_data

    if request.method == 'GET':
        form = ResetPasswordForm()
    elif request.method == 'POST':
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            token = urllib.unquote(token)
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('passwd') 
            confirm = form.cleaned_data.get('confirm')
            try:
                utils.reset_passwd_by_token(ldap_host, ldap_admin, ldap_cred, ldap_dn, username, token, password)
            except Exception as e:
                err = 'Failed to reset password for %s.  The caught exception was %s' % (username, e)
                log.error(err)
                info=''
                desc=''
                msg=''

                if isinstance(e, ldap.CONSTRAINT_VIOLATION):
		    info = e.message['info']
		    desc = e.message['desc']
                    msg =  '''Unable to reset your password, %s (%s).''' % (info, desc)

                try:
                    utils.record_recovery_status(username, 'ERROR')
		except Exception as e:
	            log.error(e)

                return render(request, 'ss/error.html', {'content': msg})
                
            try:
                utils.record_recovery_status(username, 'RESET')
            except Exception as e:
	        log.error(e)

	    return render(request, 'ss/recovered_success.html')

    return render(request, 'ss/recover.html', {'form': form})
        
def change_password(request):
"""
This function changes the user's password using user inputs of username, current password, and new password with confirmation.
"""
    class ChangePasswordForm(forms.Form):
        username = forms.CharField(label='Enter your username:', validators=[RegexValidator('^[a-zA-Z0-9]*$', message='Invalid username', code='invalid_username')])
        old_passwd  = forms.CharField(label='Current Password:', widget=forms.PasswordInput)
        passwd  = forms.CharField(label='New Password:', widget=forms.PasswordInput)
        confirm = forms.CharField(label='Confirm Password:', widget=forms.PasswordInput)
 
        def clean(self):
            # cleaned_data = super(ChangePasswordForm, self).clean()
            username = self.cleaned_data.get("username")
            current_passwd = self.cleaned_data.get("old_passwd")
            passwd = self.cleaned_data.get("passwd")
            confirm = self.cleaned_data.get("confirm")

            if username:
                # Only do something if all fields are valid so far.
                if passwd != confirm:
                    raise forms.ValidationError("Passwords do not match!")

            return self.cleaned_data

    if request.method == 'GET':
        form = ChangePasswordForm()
    elif request.method == 'POST':
        form = ChangePasswordForm(request.POST)
        if form.is_valid():

            try:
                username = form.cleaned_data.get('username')
                old = form.cleaned_data.get('old_passwd')
                new = form.cleaned_data.get('passwd')
                #userdn = utils.get_userdn(ldap_host, ldap_dn, username)
                log.debug('User, %s, found. Ready to change password from %s to %s.' % (username, old, new))
                utils.change_password(ldap_host, ldap_dn, username, old, new)
                return render(request, 'ss/password_change_success.html')

            except Exception as e:
                log.error(e)
                err = 'Failed to reset password for %s.  The caught exception was %s' % (username, e)
                log.error(err)
                info=''
                desc=''
                msg=''

                if isinstance(e, ldap.CONSTRAINT_VIOLATION):
		    info = e.message['info']
		    desc = e.message['desc']
                    msg =  '''Unable to reset your password, %s (%s).''' % (info, desc)

                return render(request, 'ss/error.html', {'content': msg})

    return render(request, 'ss/change_password.html', {'form': form})

