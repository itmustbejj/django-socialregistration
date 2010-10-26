from django.db import models

from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.sites.models import Site 

ST_FACEBOOK = 'fb'
ST_TWITTER = 'tw'
ST_LINKEDIN = 'li'

SOC_CHOICES = (
        (ST_FACEBOOK, 'FaceBook'),
        (ST_TWITTER, 'Twitter'),
        (ST_LINKEDIN,'LinkedIn')
        )


class SocialProfile(models.Model):
    user = models.ForeignKey(User)
    site = models.ForeignKey(Site, default=Site.objects.get_current)
    uid = models.CharField(max_length=255, blank=False, null=False)
    username = models.CharField(max_length=255,blank=True,null=True)
    avatar = models.CharField(max_length=255, blank=True,null=True)
    soc_type = models.CharField(max_length=2,choices=SOC_CHOICES)
    
    def __unicode__(self):
        return u'%s: %s' % (self.user, self.uid)
    
    def authenticate(self):
        return authenticate(uid=self.uid, soc_type=self.soc_type)
    



class OpenIDProfile(models.Model):
    user = models.ForeignKey(User)
    site = models.ForeignKey(Site, default=Site.objects.get_current)
    identity = models.TextField()
    
    def __unicode__(self):
        return u'OpenID Profile for %s, via provider %s' % (self.user, self.identity)

    def authenticate(self):
        return authenticate(identity=self.identity)

class OpenIDStore(models.Model):
    site = models.ForeignKey(Site, default=Site.objects.get_current)
    server_url = models.CharField(max_length=255)
    handle = models.CharField(max_length=255)
    secret = models.TextField()
    issued = models.IntegerField()
    lifetime = models.IntegerField()
    assoc_type = models.TextField()

    def __unicode__(self):
        return u'OpenID Store %s for %s' % (self.server_url, self.site)

class OpenIDNonce(models.Model):
    server_url = models.CharField(max_length=255)
    timestamp = models.IntegerField()
    salt = models.CharField(max_length=255)
    date_created = models.DateTimeField(auto_now_add=True)

    def __unicode__(self):
        return u'OpenID Nonce for %s' % self.server_url
