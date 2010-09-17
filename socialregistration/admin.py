from django.contrib import admin
from socialregistration.models import SocialProfile,\
    OpenIDProfile, OpenIDStore, OpenIDNonce

admin.site.register([SocialProfile, OpenIDProfile, OpenIDStore, OpenIDNonce])


