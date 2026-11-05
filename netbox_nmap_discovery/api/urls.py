from netbox.api.routers import NetBoxRouter

from . import views

router = NetBoxRouter()
router.APIRootView = views.DiscoveryRootView
router.register("credentials", views.CredentialProfileViewSet)
router.register("scan-targets", views.ScanTargetViewSet)
router.register("role-rules", views.RoleRuleViewSet)
router.register("device-type-aliases", views.DeviceTypeAliasViewSet)
router.register("proposed-changes", views.ProposedChangeViewSet)
router.register("discovered-hosts", views.DiscoveredHostViewSet)

urlpatterns = router.urls
