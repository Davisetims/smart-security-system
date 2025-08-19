from django.contrib import admin
from django.contrib.auth.admin  import UserAdmin
from django import forms
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from .models import Neighborhood, SecurityDevice,\
     Incident, Evidence, AIAnalysis, Alert, User, ChatMessage

admin.site.register(ChatMessage)

User = get_user_model()  

class CustomUserCreationForm(forms.ModelForm):
    password1 = forms.CharField(
        label="Password",
        widget=forms.PasswordInput,
        min_length=6,
    )
    password2 = forms.CharField(
        label="Confirm Password",
        widget=forms.PasswordInput,
    )

    class Meta:
        model = User
        fields = ("username", "email", "first_name", "last_name", 
                       "department", "role"    
                       )

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")

        if password1 and password2 and password1 != password2:
            raise ValidationError("Passwords do not match.")
        
        return password2

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])  
        if commit:
            user.save()
        return user

# Custom UserAdmin
class CustomUserAdmin(UserAdmin):
    add_form = CustomUserCreationForm
    fieldsets = UserAdmin.fieldsets
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("username", "email", "first_name", "last_name",  "role",
                       'department',
                       "password1", "password2"),
        }),
    )

admin.site.register(User, CustomUserAdmin) 



@admin.register(Neighborhood)
class NeighborhoodAdmin(admin.ModelAdmin):
    list_display = ('name', 'location', 'created_at')
    search_fields = ('name', 'location')
    list_filter = ('created_at',)

@admin.register(SecurityDevice)
class SecurityDeviceAdmin(admin.ModelAdmin):
    list_display = ('device_id', 'get_device_type_display', 'neighborhood', 'location', 'is_active', 'last_ping')
    list_filter = ('device_type', 'is_active', 'neighborhood')
    search_fields = ('device_id', 'location')
    list_editable = ('is_active',)

@admin.register(Incident)
class IncidentReportAdmin(admin.ModelAdmin):
    list_display = ('id', 'incident_type', 'device_type', 'timestamp', 'severity', 'is_verified')
    list_filter = ('incident_type', 'timestamp', 'is_verified')
    search_fields = ('description',)
    date_hierarchy = 'timestamp'
    ordering = ('-timestamp',)

@admin.register(Evidence)
class EvidenceAdmin(admin.ModelAdmin):
    list_display = ('id', 'get_evidence_type_display', 'incident', 'created_at')
    list_filter = ('evidence_type', 'created_at')
    search_fields = ('incident__description',)
    raw_id_fields = ('incident',)

@admin.register(AIAnalysis)
class AIAnalysisAdmin(admin.ModelAdmin):
    list_display = ('id', 'get_analysis_type_display', 'evidence', 'confidence', 'created_at')
    list_filter = ('analysis_type', 'created_at')
    search_fields = ('evidence__incident__description',)
    raw_id_fields = ('evidence',)

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('id', 'get_alert_level_display', 'incident', 'is_resolved', 'created_at')
    list_filter = ('alert_level', 'is_resolved', 'created_at')
    search_fields = ('message',)
    list_editable = ('is_resolved',)
    raw_id_fields = ('incident',)