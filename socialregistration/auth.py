from django.contrib.auth.models import User
from django.contrib.sites.models import Site

from socialregistration.models import SocialProfile, OpenIDProfile

class Auth(object):
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

class SocialAuth(Auth):
    def authenticate(self, uid=None, soc_type=None):
        try:
            return SocialProfile.objects.get(
                uid=uid,
                site=Site.objects.get_current(),
                soc_type=soc_type
            ).user
        except SocialProfile.DoesNotExist:
            return None


class OpenIDAuth(Auth):
    def authenticate(self, identity=None):
        try:
            return OpenIDProfile.objects.get(
                identity=identity,
                site=Site.objects.get_current()
            ).user
        except OpenIDProfile.DoesNotExist:
            return None
