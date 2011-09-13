from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.http import HttpResponseRedirect

from pyroven import RavenConfig
from pyroven.pyroven_django import Raven

def configure():
    """Raven is a singleton class; this checks if it has already been configured
    and if not configures the server, public keys, etc."""
    r = Raven()
    if r.config is None:
        r.config = RavenConfig("/etc/vns/raven.ini")

def raven_login(request):
    """Redirects the user to the raven login page"""
    configure()
    r = Raven()
    return r.get_login_redirect()

def raven_return(request):
    """Logs in a user with an HTTP GET from the raven server"""
    configure()
    
    # Get the response string that the server has sent us
    try:
        response = request.GET['WLS-Response']
    except KeyError:
        messages.error(request, "You can't login without going through Raven!")
        return HttpResponseRedirect('/')

    # Try to log in with the server's response
    user = authenticate(response_str=response)
    if user is not None:
        if not user.get_profile().retired:
            login(request, user)
        else:
            messages.error(request, "Either your raven authentication failed, "
                           "or you don't have an account on VNS.")

    # Redirect somewhere sensible
    return HttpResponseRedirect('/postlogin/')
