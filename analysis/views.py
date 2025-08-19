from rest_framework import viewsets, permissions
from django.utils import timezone
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.template.loader import render_to_string
from django.http import HttpResponse
from django.template.loader import render_to_string
from xhtml2pdf import pisa
from io import BytesIO
import tempfile
import time
from .forms import RegistrationForm, EditProfileForm
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView
from .models import Neighborhood, SecurityDevice, \
    Incident, Evidence, AIAnalysis, Alert,User, ChatMessage
from .serializers import (
    NeighborhoodSerializer,UserSerializer,
    SecurityDeviceSerializer,
    IncidentSerializer,ChatMessageSerializer,
    EvidenceSerializer,
    AIAnalysisSerializer,
    AlertSerializer, CustomTokenObtainPairSerializer
)
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
import json
from django.http import JsonResponse
import requests
import os
from django.shortcuts import render, redirect , get_object_or_404
from .forms import EvidenceUploadForm, ManualAnalysisForm

class CustomObtainTokenPairView(TokenObtainPairView):
    permission_classes = (AllowAny,)
    serializer_class = CustomTokenObtainPairSerializer

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [
        permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if not user.is_superuser:
            user = User.objects.filter(id=user.id)
        else:
            user = User.objects.all()
        return user


class NeighborhoodViewSet(viewsets.ModelViewSet):
    queryset = Neighborhood.objects.all()
    serializer_class = NeighborhoodSerializer
    authentication_classes = []  # No authentication required
    permission_classes = []  # No permissions required

class SecurityDeviceViewSet(viewsets.ModelViewSet):
    queryset = SecurityDevice.objects.all()
    serializer_class = SecurityDeviceSerializer
    authentication_classes = []
    permission_classes = []

class IncidentReportViewSet(viewsets.ModelViewSet):
    queryset = Incident.objects.all().order_by('-timestamp')
    serializer_class = IncidentSerializer
    authentication_classes = []
    permission_classes = []

    def get_queryset(self):
        queryset = super().get_queryset()
        # Example filter - you can add more as needed
        incident_type = self.request.query_params.get('type')
        if incident_type:
            queryset = queryset.filter(incident_type=incident_type.upper())
        return queryset

class EvidenceViewSet(viewsets.ModelViewSet):
    queryset = Evidence.objects.all().order_by('-created_at')
    serializer_class = EvidenceSerializer
    authentication_classes = []
    permission_classes = []

    def get_queryset(self):
        queryset = super().get_queryset()
        incident_id = self.request.query_params.get('incident_id')
        if incident_id:
            queryset = queryset.filter(incident_id=incident_id)
        return queryset

class AIAnalysisViewSet(viewsets.ModelViewSet):
    queryset = AIAnalysis.objects.all().order_by('-created_at')
    serializer_class = AIAnalysisSerializer
    authentication_classes = []
    permission_classes = []

    def get_queryset(self):
        queryset = super().get_queryset()
        evidence_id = self.request.query_params.get('evidence_id')
        if evidence_id:
            queryset = queryset.filter(evidence_id=evidence_id)
        return queryset

class AlertViewSet(viewsets.ModelViewSet):
    queryset = Alert.objects.all().order_by('-created_at')
    serializer_class = AlertSerializer
    authentication_classes = []
    permission_classes = []

    def get_queryset(self):
        queryset = super().get_queryset()
        # Example filters
        resolved = self.request.query_params.get('resolved')
        if resolved:
            queryset = queryset.filter(is_resolved=resolved.lower() == 'true')
        
        incident_id = self.request.query_params.get('incident_id')
        if incident_id:
            queryset = queryset.filter(incident_id=incident_id)
            
        return queryset
    


# class StartDetectionView(APIView):
#     def post(self, request):
#         cache.set('detection_status', 'start', timeout=60 * 60)  # 1 hour
#         return Response({"message": "Detection started remotely."}, status=status.HTTP_200_OK)

# class StopDetectionView(APIView):
#     def post(self, request):
#         cache.set('detection_status', 'stop', timeout=60 * 60)
#         return Response({"message": "Detection stopped remotely."}, status=status.HTTP_200_OK)

# class DetectionStatusView(APIView):
#     def get(self, request):
#         status_value = cache.get('detection_status', 'stop')  # default to 'stop'
#         return Response({"status": status_value}, status=status.HTTP_200_OK)

@csrf_exempt
def safehaven_analysis_view(request):
    if request.method != "POST":
        return JsonResponse({'error': 'Only POST method is allowed'}, status=405)

    try:
        data = json.loads(request.body)
        prompt = data.get('prompt', None)
        user = request.user if request.user.is_authenticated else None

        if not user:
            return JsonResponse({'error': 'Authentication required'}, status=401)

        # If no prompt is provided, auto-analyze incidents
        if not prompt:
            recent_incidents = Incident.objects.filter(ai_analysis__isnull=True).order_by('-timestamp')[:10]

            if not recent_incidents.exists():
                return JsonResponse({'message': 'No new incidents found for analysis'}, status=200)

            incident_text = "\n".join([
                f"Time: {incident.created_at}, Type: {incident.incident_type}, "
                f"Description: {incident.description or 'N/A'}, "
                f"Evidence: {request.build_absolute_uri(incident.evidence_file.url) if incident.evidence_file else 'None'}"
                for incident in recent_incidents
            ])
            prompt = (
                "Analyze the following recent security incidents. "
                "Summarize the key issues, categorize them by type, and recommend actions if needed:\n\n"
                + incident_text
            )
        else:
            recent_incidents = None  # For manual analysis

        # Setup Mistral API call
        api_key = os.getenv("API_KEY")
        model = "mistral-small-latest"

        system_message = (
            "You are an AI analyst for SafeHaven Security System. Analyze incidents, identify patterns, and recommend actions. "
            "Be brief and precise, highlighting any critical threats or repeated behaviors."
        )

        history_messages = [{"role": "system", "content": system_message}]
        history_messages.append({"role": "user", "content": prompt})

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": model,
            "messages": history_messages
        }

        response = requests.post("https://api.mistral.ai/v1/chat/completions", headers=headers, json=payload)

        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 5))
            time.sleep(retry_after)
            response = requests.post("https://api.mistral.ai/v1/chat/completions", headers=headers, json=payload)

        response.raise_for_status()
        reply = response.json()["choices"][0]["message"]["content"]

        # Save to chat history
        ChatMessage.objects.create(
            user=user,
            conversation=[{"user": prompt}, {"mistral": reply}],
            updated_at=timezone.now()
        )

        # Update analyzed incidents with AI feedback
        if recent_incidents:
            for incident in recent_incidents:
                incident.ai_analysis = reply
                incident.save(update_fields=['ai_analysis'])

        return JsonResponse({
            "response": reply,
            "status": "success"
        }, status=200)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    
class ChatHistoryViewSet(viewsets.ModelViewSet):
    permission_classes =[permissions.IsAuthenticated]
    serializer_class = ChatMessageSerializer
    queryset = ChatMessage.objects.all()



@login_required
def safehaven_analysis_page(request):
    """
    Render the SafeHaven analysis page with chat history
    """
    # Get recent chat history for the current user
    chat_history = ChatMessage.objects.filter(
        user=request.user
    ).order_by('-updated_at')[:10]
    
    context = {
        'chat_history': chat_history,
        'user': request.user,
    }
    
    return render(request, 'dashboard.html', context)

def home(request):
    return render(request, 'home.html')

def neighborhood_dashboard(request):
    return render(request, 'neighborhood_dashboard.html')


def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)

            # Redirect based on role
            if user.role == "admin":
                return redirect("dashboard")
            elif user.role == "responder":
                return redirect("responder_dashboard")
            elif user.role == "neighborhood":
                return redirect("neighborhood_dashboard")
            else:
                messages.error(request, "Unauthorized role. Contact admin.")
                return redirect("login")

        else:
            messages.error(request, "Invalid username or password")

    return render(request, "login.html")



def register_user(request):
    if request.method == "POST":
        form = RegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("user_list")
    else:
        form = RegistrationForm()
    
    return render(request, "add_user.html", {"form": form})

def logout_view(request):
    logout(request)  
    return redirect('/') 



@login_required
def edit_user(request, user_id):
    user_obj = get_object_or_404(User, id=user_id)
    if request.method == 'POST':
        form = EditProfileForm(request.POST, instance=user_obj)
        if form.is_valid():
            form.save()
            return redirect('user_list')
    else:
        form = EditProfileForm(instance=user_obj)
    return render(request, 'edit_user.html', {'form': form, 'user_obj': user_obj})



@login_required
def delete_user_view(request, user_id):
    user_to_delete = get_object_or_404(User, id=user_id)

    if user_to_delete == request.user:
        messages.error(request, "You cannot delete your own account.")
        return redirect('login')
    else:
        user_to_delete.delete()
        messages.success(request, "User deleted successfully.")
    
    return redirect('user_list') 

def is_admin(user):
    return user.is_superuser or user.role.lower() == 'admin'

@login_required
def user_list_view(request):
    user = request.user  # Fix: reference the logged-in user

    if is_admin(user):
        users = User.objects.all()
    else:
        users = User.objects.filter(id=user.id)

    return render(request, 'user_list.html', {'users': users})



def generate_incident_report(request):
    incidents = Incident.objects.all().order_by('-timestamp')

    html = render_to_string('incident_report.html', {
        'incidents': incidents,
        'image_path': request.build_absolute_uri('/evidence/d36dccf8-4255-4b4f-9570-b1bd740f1236.png'),
    })

    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename="incident_report.pdf"'

    result = BytesIO()
    pdf = pisa.pisaDocument(BytesIO(html.encode("UTF-8")), result)

    if not pdf.err:
        response.write(result.getvalue())
        return response
    else:
        return HttpResponse('Error generating PDF', status=500)
    
def responder_dashboard(request):
    """Simple dashboard for responder to view all incidents and go to actions page."""
    incidents = Incident.objects.all().order_by('-created_at')
    return render(request, 'responder_dashboard.html', {'incidents': incidents})


@login_required
def responder_actions(request, incident_id):
    """Responder can approve, delete AI analysis, upload new evidence, or replace analysis."""
    incident = get_object_or_404(Incident, id=incident_id)

    if request.method == "POST":
        # Approve AI analysis
        if 'approve' in request.POST:
            incident.is_verified = True
            incident.alert_message = "Verified by responder."
            incident.save()
            messages.success(request, "Incident verified successfully.")

        # Delete AI analysis
        elif 'delete_analysis' in request.POST:
            incident.ai_analysis = None
            incident.alert_message = "AI analysis deleted by responder."
            incident.save()
            messages.warning(request, "AI analysis deleted.")

        # Upload or replace evidence
        elif 'upload_evidence' in request.POST:
            form = EvidenceUploadForm(request.POST, request.FILES, instance=incident)
            if form.is_valid():
                form.save()
                messages.success(request, "Evidence uploaded/replaced successfully.")
            else:
                messages.error(request, "Error uploading evidence.")

        # Replace AI analysis with manual text
        elif 'manual_analysis' in request.POST:
            form = ManualAnalysisForm(request.POST, instance=incident)
            if form.is_valid():
                incident.ai_analysis = {"manual_text": form.cleaned_data['manual_text']}
                incident.alert_message = "Manual analysis provided by responder."
                incident.save()
                messages.success(request, "Manual analysis saved successfully.")
            else:
                messages.error(request, "Error saving manual analysis.")

        return redirect('incident_action', incident_id=incident.id)

    # Forms for evidence upload and manual analysis
    evidence_form = EvidenceUploadForm(instance=incident)
    manual_form = ManualAnalysisForm()

    return render(request, 'responder_actions.html', {
        'incident': incident,
        'evidence_form': evidence_form,
        'manual_form': manual_form
    })

@login_required
def neighborhood_incident_detail(request, incident_id):
    """Show detailed incident info for neighborhood users."""
    incident = get_object_or_404(Incident, id=incident_id)

    # Only allow user if they belong to the same neighborhood
    user_neighborhood = getattr(request.user, "neighborhood", None)
    if incident.neighborhood != user_neighborhood:
        messages.error(request, "You are not authorized to view this incident.")
        return redirect("neighborhood_dashboard")

    evidences = incident.evidences.all()

    return render(request, "neighborhood_incident_detail.html", {
        "incident": incident,
        "evidences": evidences
    })
