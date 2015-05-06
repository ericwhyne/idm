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

def post_upload(request):
    if request.method == 'GET':
        return render(request, 'ss/upload.html', {})
    elif request.method == 'POST':
        #post = m.Post.objects.create(content=request.POST['content'], created_at=datetime.utcnow())
        # No need to call post.save() at this point -- it's already saved.
        #return HttpResponseRedirect(reverse('index', kwargs={'post_id': post.id}))
        #return HttpResponseRedirect(reverse('index'))
    	content = request.POST['content']
        return render(request, 'ss/success.html', {'content': content})
        #return HttpResponse({'content':request.POST['content']})


def by_email(request):
    class PasswordRecoveryForm(forms.Form):
        username = forms.CharField(label='Enter your username:')

    if request.method == 'GET':
            form = PasswordRecoveryForm()    
	    return render(request, 'ss/recover.html', {'form': form})

    elif request.method == 'POST':
            form = PasswordRecoveryForm(request.POST)    
    
	    try:
		l = ldap.open("127.0.0.1")
	    
		# you should  set this to ldap.VERSION2 if you're using a v2 directory
		l.protocol_version = ldap.VERSION3    
		# Pass in a valid username and password to get 
		# privileged directory access.
		# If you leave them as empty strings or pass an invalid value
		# you will still bind to the server but with limited privileges.
	    
		username = "cn=Directory Manager"
		password  = "1qaz@WSX"
	    
		# Any errors will throw an ldap.LDAPError exception 
		# or related exception so you can ignore the result
		l.simple_bind(username, password)

		## The next lines will also need to be changed to support your search requirements and directory
		baseDN = "cn=users, cn=accounts, dc=example, dc=com"
		searchScope = ldap.SCOPE_SUBTREE
		## retrieve all attributes - again adjust to your needs - see documentation for more options
		retrieveAttributes = None 
		searchFilter = "uid=bubbaj"

		ldap_result_id = l.search(baseDN, searchScope, searchFilter, retrieveAttributes)
		result_set = []
		while 1:
		    result_type, result_data = l.result(ldap_result_id, 0)
		    if (result_data == []):
			break
		    else:
			## here you don't have to append to a list
			## you could do whatever you want with the individual entry
			## The appending to list is just for illustration. 
			if result_type == ldap.RES_SEARCH_ENTRY:
			    result_set.append(result_data)
		    print result_set 
	    except ldap.LDAPError, e:
		print e
		# handle error however you like

	    content = 'test'

	    if form.is_valid():
		return render(request, 'ss/success.html', {'content': content})


def send_recovery_email(request):
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

