from django.contrib import admin
from .models import Blacklist, Whitelist, Suspect, Analysis

admin.site.register(Blacklist)
admin.site.register(Whitelist)
admin.site.register(Suspect)
admin.site.register(Analysis)