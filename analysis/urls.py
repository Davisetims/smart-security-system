from rest_framework.routers import DefaultRouter
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    NeighborhoodViewSet,edit_user,generate_incident_report,
    SecurityDeviceViewSet,logout_view,responder_dashboard,
    IncidentReportViewSet, user_list_view,neighborhood_incident_detail,
    EvidenceViewSet,login_view,delete_user_view,neighborhood_dashboard,
    AIAnalysisViewSet,safehaven_analysis_page,
    AlertViewSet,safehaven_analysis_view,responder_actions,
    UserViewSet,CustomObtainTokenPairView,home, register_user
)

router = DefaultRouter()
router.register(r'neighborhoods', NeighborhoodViewSet)
router.register(r'devices', SecurityDeviceViewSet)
router.register(r'incidents', IncidentReportViewSet)
router.register(r'evidences', EvidenceViewSet)
router.register(r'analyses', AIAnalysisViewSet)
router.register(r'alerts', AlertViewSet)
router.register(r'users', UserViewSet,)




urlpatterns = [
    path("token/request/", CustomObtainTokenPairView.as_view(), name="token_request"),
    # path('detection-status/', DetectionStatusView.as_view(), name='detection-status'),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"), 
    path("api/analysis/", safehaven_analysis_view, name="safehaven_analysis"),
    path('superuser/dashboard/', safehaven_analysis_page, name='dashboard'),
    path('', home, name='home'),
    path('login/', login_view, name='login'),
    path("add/user/", register_user, name="add_user"),
    path('logout/', logout_view, name='logout'),
    path('users/edit/<int:user_id>/', edit_user, name='edit_user'),
    path('users/', user_list_view, name='user_list'),
    path('users/delete/<int:user_id>/', delete_user_view, name='delete_user'),
    path('report/pdf/', generate_incident_report, name='generate_incident_report'),
    path("responder/dashboard/", responder_dashboard, name="responder_dashboard"),
    path("incident/<int:incident_id>/action/", responder_actions, name="incident_action"),
    path("neighborhood/dashboard/", neighborhood_dashboard, name="neighborhood_dashboard"),
    path("incident/<int:incident_id>/", neighborhood_incident_detail, name="neighborhood_incident_detail"),
    # path('start-detection/', StartDetectionView.as_view(), name='start-detection'),
    # path('stop-detection/', StopDetectionView.as_view(), name='stop-detection'),
]

urlpatterns += router.urls