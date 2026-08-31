"""Plugin package — every vendor plugin, registered in the PluginRegistry.

All bundled plugins are trusted (first-party); third-party plugins can be
registered dynamically and are gated by ``trusted`` (spec §18).
"""

from __future__ import annotations

from universal_vendor.plugins.cloud import (
    AwsPlugin,
    AzurePlugin,
    GcpPlugin,
)
from universal_vendor.plugins.container import (
    AwsEcrPlugin,
    AzureAcrPlugin,
    DockerEnginePlugin,
    DockerHubPlugin,
    GhcrPlugin,
    GoogleArtifactRegistryPlugin,
    HarborPlugin,
)
from universal_vendor.plugins.database import (
    CassandraPlugin,
    MariaDbPlugin,
    MongoDbPlugin,
    MySqlPlugin,
    PostgreSqlPlugin,
    RedisPlugin,
    SqlServerPlugin,
)
from universal_vendor.plugins.devops import (
    AzureDevOpsPlugin,
    BitbucketPlugin,
    GithubPlugin,
    GitlabPlugin,
)
from universal_vendor.plugins.firewall import (
    CheckPointPlugin,
    FortinetPlugin,
    PaloAltoPlugin,
    SophosPlugin,
)
from universal_vendor.plugins.hsm import (
    AwsCloudHsmPlugin,
    EntrustNshieldPlugin,
    ThalesLunaPlugin,
    UtimacoPlugin,
)
from universal_vendor.plugins.identity import (
    EntraIdPlugin,
    KeycloakPlugin,
    OktaPlugin,
    PingIdentityPlugin,
)
from universal_vendor.plugins.kubernetes import (
    AksPlugin,
    EksPlugin,
    GkePlugin,
    KubernetesCorePlugin,
    OpenShiftPlugin,
    RancherPlugin,
)
from universal_vendor.plugins.loadbalancer import (
    F5Plugin,
    HaProxyPlugin,
    NginxPlugin,
)
from universal_vendor.plugins.middleware import (
    ApacheHttpdPlugin,
    JbossPlugin,
    TomcatPlugin,
    WebLogicPlugin,
    WebSpherePlugin,
)
from universal_vendor.plugins.network import (
    AristaPlugin,
    CiscoPlugin,
    JuniperPlugin,
    MikroTikPlugin,
)
from universal_vendor.plugins.os import (
    DebianPlugin,
    RedHatPlugin,
    SusePlugin,
    UbuntuPlugin,
    VmwareEsxiPlugin,
    WindowsPlugin,
)
from universal_vendor.plugins.pki import (
    AdcsPlugin,
    EntrustPkiPlugin,
    HashiCorpVaultPkiPlugin,
    OpenSslPkiPlugin,
)
from universal_vendor.plugins.security import (
    CrowdStrikePlugin,
    Microsoft365Plugin,
    NotSupportedSaaSPlugin,
    QradarPlugin,
    SalesforcePlugin,
    SentinelOnePlugin,
    SplunkPlugin,
)
from universal_vendor.registry import PluginRegistry

ALL_PLUGINS: list[type] = [
    # network
    CiscoPlugin, JuniperPlugin, AristaPlugin, MikroTikPlugin,
    # firewall / security
    PaloAltoPlugin, FortinetPlugin, CheckPointPlugin, SophosPlugin,
    # load balancer / ADC
    F5Plugin, NginxPlugin, HaProxyPlugin,
    # cloud
    AwsPlugin, AzurePlugin, GcpPlugin,
    # PKI
    HashiCorpVaultPkiPlugin, AdcsPlugin, OpenSslPkiPlugin, EntrustPkiPlugin,
    # HSM
    ThalesLunaPlugin, EntrustNshieldPlugin, UtimacoPlugin, AwsCloudHsmPlugin,
    # identity
    KeycloakPlugin, EntraIdPlugin, OktaPlugin, PingIdentityPlugin,
    # databases
    PostgreSqlPlugin, MySqlPlugin, MariaDbPlugin, SqlServerPlugin,
    MongoDbPlugin, RedisPlugin, CassandraPlugin,
    # middleware
    ApacheHttpdPlugin, TomcatPlugin, WebSpherePlugin, WebLogicPlugin,
    JbossPlugin,
    # OS
    RedHatPlugin, UbuntuPlugin, DebianPlugin, SusePlugin, WindowsPlugin,
    VmwareEsxiPlugin,
    # EDR / SIEM
    CrowdStrikePlugin, SentinelOnePlugin, SplunkPlugin, QradarPlugin,
    # DevOps
    GithubPlugin, GitlabPlugin, BitbucketPlugin, AzureDevOpsPlugin,
    # containers / registries
    DockerEnginePlugin, DockerHubPlugin, GhcrPlugin, AwsEcrPlugin,
    AzureAcrPlugin, GoogleArtifactRegistryPlugin, HarborPlugin,
    # Kubernetes core + adapters
    KubernetesCorePlugin, EksPlugin, AksPlugin, GkePlugin, OpenShiftPlugin,
    RancherPlugin,
    # SaaS
    SalesforcePlugin, Microsoft365Plugin, NotSupportedSaaSPlugin,
]


def build_registry() -> PluginRegistry:
    """Create the plugin registry with all bundled plugins registered."""
    registry = PluginRegistry()
    for plugin_cls in ALL_PLUGINS:
        registry.register(plugin_cls)
    return registry


__all__ = ["ALL_PLUGINS", "build_registry"]
