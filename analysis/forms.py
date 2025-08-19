from django import forms
from .models import User, Incident
from django.contrib.auth.forms import UserCreationForm

class RegistrationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['department','role', "username","first_name", "last_name", "email",  "password1", "password2"]

    def save(self, commit=True):
        user = super().save(commit=False) 
        if commit:
            user.save()
        return user  

class EditProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name', 'department', 'role']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'department': forms.TextInput(attrs={'class': 'form-control'}),
            'role': forms.TextInput(attrs={'class': 'form-control'}),
        }


class EvidenceUploadForm(forms.ModelForm):
    class Meta:
        model = Incident
        fields = ['evidence_file', 'evidence_type']


class ManualAnalysisForm(forms.Form):
    manual_text = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 4, 'placeholder': 'Enter your manual analysis here...'}),
        required=True
    )