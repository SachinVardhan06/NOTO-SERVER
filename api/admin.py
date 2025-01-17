from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, Subscription

class CustomUserAdmin(UserAdmin):
    list_display = ('email', 'first_name', 'last_name', 'is_staff')
    search_fields = ('email', 'first_name', 'last_name')
    ordering = ('email',)
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2'),
        }),
    )

admin.site.register(User, CustomUserAdmin)

@admin.register(Subscription)
class SubscriptionAdmin(admin.ModelAdmin):
    list_display = ('user', 'membership_type', 'start_date', 'end_date', 'is_expired')
    list_filter = ('membership_type', 'start_date', 'end_date')
    search_fields = ('user__email', 'user__first_name', 'user__last_name')
    date_hierarchy = 'start_date'
    readonly_fields = ('start_date',)
    
    def is_expired(self, obj):
        return obj.is_expired()
    is_expired.boolean = True
    is_expired.short_description = 'Expired'