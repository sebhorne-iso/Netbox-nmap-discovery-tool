from django.urls import include, path
from utilities.urls import get_model_urls

from . import views  # noqa: F401  (registers model views)
from .views import RediscoverView

app_name = "netbox_nmap_discovery"

urlpatterns = [
    path("credentials/", include(get_model_urls(app_name, "credentialprofile", detail=False))),
    path("credentials/<int:pk>/", include(get_model_urls(app_name, "credentialprofile"))),
    path("scan-targets/", include(get_model_urls(app_name, "scantarget", detail=False))),
    path("scan-targets/<int:pk>/", include(get_model_urls(app_name, "scantarget"))),
    path("role-rules/", include(get_model_urls(app_name, "rolerule", detail=False))),
    path("role-rules/<int:pk>/", include(get_model_urls(app_name, "rolerule"))),
    path("device-type-aliases/", include(get_model_urls(app_name, "devicetypealias", detail=False))),
    path("device-type-aliases/<int:pk>/", include(get_model_urls(app_name, "devicetypealias"))),
    path("review/", include(get_model_urls(app_name, "proposedchange", detail=False))),
    path("review/<int:pk>/", include(get_model_urls(app_name, "proposedchange"))),
    path("hosts/", include(get_model_urls(app_name, "discoveredhost", detail=False))),
    path("hosts/<int:pk>/", include(get_model_urls(app_name, "discoveredhost"))),
    path("rediscover/", RediscoverView.as_view(), name="rediscover"),
]
